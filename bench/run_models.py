"""Fit every detector on both feature views, score the March test month, save results."""
from __future__ import annotations

import json
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

from . import data, labels, features, metrics, models

warnings.filterwarnings("ignore")
RESULTS = Path(__file__).resolve().parent.parent / "results"


# which detectors are stochastic (seed-dependent) -> averaged over several seeds
STOCHASTIC = {"KMeans", "GMM", "IsolationForest", "OneClassSVM", "AutoEncoder", "DeepSVDD"}


def detector_factories(seed):
    fac = {
        "KMeans": lambda: models.KMeansDetector(k=8, seed=seed),
        "GMM": lambda: models.GMMDetector(k=8, seed=seed),
        "IsolationForest": lambda: models.IForestDetector(seed=seed),
        "OneClassSVM": lambda: models.OCSVMDetector(seed=seed),
        "LOF": lambda: models.LOFDetector(),
    }
    fac.update(models.build_pyod())
    return fac


def _rankavg(score_map, names):
    """Rank-average ensemble: average of per-detector percentile ranks (0..1)."""
    from scipy.stats import rankdata
    ranks = [rankdata(score_map[n]) / len(score_map[n]) for n in names if n in score_map]
    return np.mean(ranks, axis=0)


def main(seeds=(0, 1, 2)):
    t0 = time.time()
    df = labels.attach(data.load())
    train, val, test = data.split(df)
    n_days_test = (test.ts.max() - test.ts.min()).days + 1
    y = test.label.values
    print(f"train={len(train)} val={len(val)} test={len(test)} attacks_in_test={int(y.sum())} test_days={n_days_test}")

    # ---- feature views (fit on train only) ----
    Xtr_raw, cat_maps = features.raw_view(train)
    Xte_raw, _ = features.raw_view(test, cat_maps)
    enc = features.CtxEncoder().fit(train)
    Xtr_ctx = enc.transform(train)
    Xte_ctx = enc.transform(test)
    views = {"RAW": (Xtr_raw.values, Xte_raw.values, Xte_raw),
             "CTX": (Xtr_ctx.values, Xte_ctx.values, Xte_ctx)}

    det_names = list(detector_factories(0).keys())
    rows = []
    score_cols = {}  # final (seed-averaged) score vector per "det|view"
    for view_name, (Xtr, Xte, Xte_df) in views.items():
        for det_name in det_names:
            use_seeds = seeds if det_name in STOCHASTIC else (0,)
            per_seed_scores, per_seed_res, t = [], [], time.time()
            try:
                for s in use_seeds:
                    det = detector_factories(s)[det_name]().fit(Xtr)
                    sc = np.nan_to_num(np.asarray(det.score(Xte), float))
                    per_seed_scores.append(sc)
                    per_seed_res.append(metrics.evaluate(sc, y, n_days_test))
                mean_score = np.mean(per_seed_scores, axis=0)
                res = metrics.evaluate(mean_score, y, n_days_test)  # metrics on the averaged score
                res["pr_auc_std"] = float(np.std([r["pr_auc"] for r in per_seed_res]))
                res.update(model=det_name, view=view_name, n_seeds=len(use_seeds),
                           seconds=round(time.time() - t, 2))
                rows.append(res)
                score_cols[f"{det_name}|{view_name}"] = mean_score
                print(f"  {view_name:3s} {det_name:15s} PR-AUC={res['pr_auc']:.3f}"
                      f"±{res['pr_auc_std']:.3f} R@50={res['recall@50']:.2f} "
                      f"bestF1={res['best_f1']:.2f} ({res['seconds']}s)")
            except Exception as e:
                print(f"  {view_name:3s} {det_name:15s} FAILED: {type(e).__name__}: {e}")

    # rule-based engineered baseline (CTX only - it reads named columns)
    rule = models.RuleNoveltyDetector().fit(Xtr_ctx)
    rscore = rule.score(Xte_ctx)
    res = metrics.evaluate(rscore, y, n_days_test)
    res.update(model="RuleNovelty", view="CTX", n_seeds=1, pr_auc_std=0.0, seconds=0.0)
    rows.append(res)
    score_cols["RuleNovelty|CTX"] = rscore
    print(f"  CTX RuleNovelty     PR-AUC={res['pr_auc']:.3f} R@50={res['recall@50']:.2f} bestF1={res['best_f1']:.2f}")

    # rank-average ensemble of the strongest complementary CTX detectors
    ens_members = [f"{m}|CTX" for m in ("GMM", "ECOD", "AutoEncoder", "OneClassSVM")]
    if all(m in score_cols for m in ens_members):
        escore = _rankavg(score_cols, ens_members)
        res = metrics.evaluate(escore, y, n_days_test)
        res.update(model="Ensemble(GMM+ECOD+AE+OCSVM)", view="CTX", n_seeds=1, pr_auc_std=0.0, seconds=0.0)
        rows.append(res)
        score_cols["Ensemble|CTX"] = escore
        print(f"  CTX Ensemble        PR-AUC={res['pr_auc']:.3f} R@50={res['recall@50']:.2f} bestF1={res['best_f1']:.2f}")

    RESULTS.mkdir(exist_ok=True)
    resdf = pd.DataFrame(rows).sort_values("pr_auc", ascending=False)
    resdf.to_csv(RESULTS / "model_scores.csv", index=False)

    # persist per-row scores on the test set for later stacking / LLM comparison
    scores_out = test[["src_line", "ts", "user", "ip", "method", "path", "status", "bytes",
                       "label", "attack_type", "tier"]].copy()
    for name, sc in score_cols.items():
        scores_out[name] = sc
    scores_out.to_parquet(RESULTS / "test_scores.parquet")

    print(f"\nDone in {time.time()-t0:.1f}s. Wrote results/model_scores.csv and results/test_scores.parquet")
    print("\n== leaderboard (by PR-AUC) ==")
    show = ["model", "view", "pr_auc", "roc_auc", "recall@50", "prec@50", "best_f1", "alerts_per_day_at_best_f1", "seconds"]
    print(resdf[show].to_string(index=False))
    return resdf


if __name__ == "__main__":
    main()
