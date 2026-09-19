"""Rigorous final evaluation.

Protocol (no test-set peeking):
  1. Features fit on TRAIN (Aug-Jan) only.
  2. Hyperparameters + operating threshold selected on injected VALIDATION (Feb + synthetic
     attacks), averaged over several injection seeds. The real March attack is never used
     for any decision.
  3. The chosen configs are frozen and evaluated ONCE on the real March TEST, with 95%
     bootstrap confidence intervals on PR-AUC and the operating-point confusion matrix.

Champions compared: tuned GMM, Deep AE ensemble (GPU), RuleNovelty (no-ML), ECOD, and a
rank-average ensemble of the complementary ones.
"""
from __future__ import annotations

import json
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import rankdata
from sklearn.metrics import average_precision_score

from . import data, labels, features, inject, models, metrics

warnings.filterwarnings("ignore")
RESULTS = Path(__file__).resolve().parent.parent / "results"
INJECT_SEEDS = [0, 1, 2, 3, 4]
TARGET_ALERTS_FRAC = 0.005  # operating point: ~top 0.5% of traffic gets alerted


def mean_val_prauc(score_fn, tr, va, enc):
    """Average injected-val PR-AUC over several injection seeds (label-free selection)."""
    aucs = []
    for s in INJECT_SEEDS:
        vinj = inject.inject(va, tr, seed=s)
        Xv = enc.transform(vinj)
        aucs.append(average_precision_score(vinj.label.values, score_fn(Xv)))
    return float(np.mean(aucs)), float(np.std(aucs))


def select_gmm(Xtr, tr, va, enc):
    best = None
    for k in (4, 8, 12, 16, 24):
        for cov in ("diag", "full"):
            det = models.GMMDetector(k=k).fit(Xtr.values)
            det.gmm.covariance_type = cov  # note: refit below for full
            from sklearn.mixture import GaussianMixture
            g = GaussianMixture(n_components=k, covariance_type=cov, random_state=0, reg_covar=1e-4)
            g.fit(det._apply(Xtr.values))
            det.gmm = g
            auc, sd = mean_val_prauc(lambda X: det.score(X.values), tr, va, enc)
            if best is None or auc > best[0]:
                best = (auc, sd, dict(k=k, cov=cov))
    return best


def select_ae(Xtr, tr, va, enc, Xtr_val):
    from .deep_model import DeepAEDetector
    grid = [
        dict(hidden=(64, 32), latent=8, dropout=0.1),
        dict(hidden=(128, 64, 32), latent=16, dropout=0.1),
        dict(hidden=(64, 32), latent=4, dropout=0.2),
        dict(hidden=(128, 64), latent=8, dropout=0.15),
    ]
    best = None
    for cfg in grid:
        det = DeepAEDetector(n_models=3, max_epochs=200, patience=20, **cfg).fit(Xtr.values, Xtr_val)
        auc, sd = mean_val_prauc(lambda X: det.score(X.values), tr, va, enc)
        print(f"    AE {cfg} -> val PR-AUC {auc:.3f}±{sd:.3f}")
        if best is None or auc > best[0]:
            best = (auc, sd, cfg)
    return best


def threshold_from_val(score_fn, tr, va, enc, frac):
    vinj = inject.inject(va, tr, seed=99)  # a held-out injection seed for thresholding
    s = score_fn(enc.transform(vinj))
    return float(np.quantile(s, 1 - frac))


def bootstrap_prauc(scores, y, B=1000, seed=0):
    rng = np.random.default_rng(seed)
    n = len(y); aucs = []
    for _ in range(B):
        idx = rng.integers(0, n, n)
        if y[idx].sum() == 0:
            continue
        aucs.append(average_precision_score(y[idx], scores[idx]))
    lo, hi = np.percentile(aucs, [2.5, 97.5])
    return float(np.mean(aucs)), float(lo), float(hi)


def main():
    import torch
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"device: {dev} ({torch.cuda.get_device_name(0) if dev=='cuda' else 'CPU'})")
    t0 = time.time()

    df = labels.attach(data.load())
    tr, va, te = data.split(df)
    enc = features.CtxEncoder().fit(tr)
    Xtr, Xte = enc.transform(tr), enc.transform(te)
    y = te.label.values
    n_days = (te.ts.max() - te.ts.min()).days + 1

    # ---- 1. model selection on injected val ----
    print("\n[1] selecting GMM on injected-val ...")
    gmm_auc, gmm_sd, gmm_cfg = select_gmm(Xtr, tr, va, enc)
    print(f"    best GMM {gmm_cfg}: val PR-AUC {gmm_auc:.3f}±{gmm_sd:.3f}")

    print("\n[2] selecting Deep AE on injected-val (GPU) ...")
    from .deep_model import DeepAEDetector
    from sklearn.model_selection import train_test_split
    Xtr_fit, Xtr_val = train_test_split(Xtr.values, test_size=0.1, random_state=0)
    ae_auc, ae_sd, ae_cfg = select_ae(Xtr, tr, va, enc,
                                      pd.DataFrame(Xtr_val, columns=Xtr.columns))
    print(f"    best AE {ae_cfg}: val PR-AUC {ae_auc:.3f}±{ae_sd:.3f}")

    # ---- 2. train frozen champions on full train ----
    print("\n[3] training frozen champions on full train ...")
    from sklearn.mixture import GaussianMixture
    from sklearn.preprocessing import StandardScaler
    gmm = models.GMMDetector(k=gmm_cfg["k"]).fit(Xtr.values)
    sc = StandardScaler().fit(Xtr.values)
    g = GaussianMixture(n_components=gmm_cfg["k"], covariance_type=gmm_cfg["cov"],
                        random_state=0, reg_covar=1e-4).fit(sc.transform(Xtr.values))
    gmm.gmm, gmm.scaler = g, sc

    ae = DeepAEDetector(n_models=7, max_epochs=400, patience=30, verbose=True, **ae_cfg)
    ae.fit(Xtr.values, Xtr_val)

    rule = models.RuleNoveltyDetector().fit(Xtr)
    ecod = models.build_pyod()["ECOD"]().fit(Xtr.values)

    champions = {
        f"GMM(k={gmm_cfg['k']},{gmm_cfg['cov']})": lambda X: gmm.score(X.values),
        f"DeepAE(x7,{ae_cfg['hidden']},z{ae_cfg['latent']})": lambda X: ae.score(X.values),
        "RuleNovelty": lambda X: rule.score(X),
        "ECOD": lambda X: ecod.score(X.values),
    }
    # ensemble of the complementary ones
    def ens(X):
        parts = [rankdata(gmm.score(X.values)), rankdata(ecod.score(X.values)),
                 rankdata(ae.score(X.values)), rankdata(rule.score(X))]
        return np.mean([p / len(X) for p in parts], axis=0)
    champions["Ensemble(GMM+ECOD+AE+Rule)"] = ens

    # ---- 3. evaluate on real March test ----
    print("\n[4] evaluating frozen champions on REAL March test ...")
    rows = []
    for name, fn in champions.items():
        s = np.asarray(fn(Xte), float)
        res = metrics.evaluate(s, y, n_days)
        mean, lo, hi = bootstrap_prauc(s, y)
        thr = threshold_from_val(fn, tr, va, enc, TARGET_ALERTS_FRAC)
        cm = metrics.confusion_at_threshold(s, y, thr)
        res.update(model=name, pr_auc_boot=mean, pr_auc_ci_lo=lo, pr_auc_ci_hi=hi,
                   op_threshold=thr, op_tp=cm["tp"], op_fp=cm["fp"], op_fn=cm["fn"],
                   op_precision=cm["tp"] / max(cm["tp"] + cm["fp"], 1),
                   op_recall=cm["tp"] / max(cm["tp"] + cm["fn"], 1),
                   op_alerts_per_day=(cm["tp"] + cm["fp"]) / n_days)
        rows.append(res)
        print(f"  {name:32s} PR-AUC={res['pr_auc']:.3f} [{lo:.3f},{hi:.3f}] "
              f"R@50={res['recall@50']:.2f} | op: P={res['op_precision']:.2f} "
              f"R={res['op_recall']:.2f} {res['op_alerts_per_day']:.2f} alerts/day")

    out = pd.DataFrame(rows).sort_values("pr_auc", ascending=False)
    RESULTS.mkdir(exist_ok=True)
    keep = ["model", "pr_auc", "pr_auc_ci_lo", "pr_auc_ci_hi", "roc_auc", "recall@50", "prec@50",
            "op_precision", "op_recall", "op_fp", "op_alerts_per_day"]
    out[keep].to_csv(RESULTS / "final_eval.csv", index=False)
    # persist selection provenance
    (RESULTS / "final_selection.json").write_text(json.dumps(
        {"gmm": gmm_cfg, "gmm_val_prauc": gmm_auc, "ae": ae_cfg, "ae_val_prauc": ae_auc,
         "inject_seeds": INJECT_SEEDS, "target_alerts_frac": TARGET_ALERTS_FRAC,
         "device": dev, "n_test": len(te), "n_attacks": int(y.sum())}, indent=2, default=str))
    print(f"\ndone in {time.time()-t0:.0f}s -> results/final_eval.csv")
    print(out[keep].to_string(index=False, float_format=lambda x: f"{x:.3f}"))


if __name__ == "__main__":
    main()
