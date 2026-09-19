"""Score incoming log lines with the trained model store.

    # score a file of raw Apache log lines, print the most anomalous
    .venv/bin/python -m bench.predict --input newlogs.txt --model ae --top 20

    # or score the built-in March test window and show what it flags
    .venv/bin/python -m bench.predict --demo --model gmm --top 15

The feature encoder's rarity/permission statistics come from the training period, so a new
line is scored against learned 'normal'. Output: each line with an anomaly score in [0,1]
(percentile within the batch) and the rule-based reason tags that fired.
"""
from __future__ import annotations

import argparse
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from . import data, labels, features, models

STORE = Path(__file__).resolve().parent.parent / "results" / "model_store"


def _load_gmm():
    with open(STORE / "gmm.pkl", "rb") as f:
        d = pickle.load(f)
    det = models.GMMDetector()
    det.scaler, det.gmm = d["scaler"], d["gmm"]
    return det


def _load_ae():
    import torch
    from .deep_model import DeepAEDetector, AutoEncoder
    with open(STORE / "ae_meta.pkl", "rb") as f:
        meta = pickle.load(f)
    det = DeepAEDetector(**{k: meta["cfg"][k] for k in ("hidden", "latent", "dropout")})
    det.scaler, det.feat_err = meta["scaler"], meta["feat_err"]
    d_in = len(meta["cols"])
    states = torch.load(STORE / "ae_models.pt", map_location="cpu")
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    det.models = []
    for sd in states:
        m = AutoEncoder(d_in, tuple(meta["cfg"]["hidden"]), meta["cfg"]["latent"], meta["cfg"]["dropout"])
        m.load_state_dict(sd); m.to(dev).eval()
        det.models.append(m)
    return det


def load_encoder():
    with open(STORE / "encoder.pkl", "rb") as f:
        return pickle.load(f)


def score_frame(df: pd.DataFrame, model="ae"):
    enc = load_encoder()
    X = enc.transform(df)
    det = _load_ae() if model == "ae" else _load_gmm()
    # absolute score where the detector offers one, so callers can calibrate it
    # against the training distribution instead of ranking within the batch
    scorer = getattr(det, "score_abs", det.score)
    raw = np.asarray(scorer(X.values), float)
    from scipy.stats import rankdata
    pct = rankdata(raw) / len(raw)  # 0..1 percentile within this batch
    reasons = _reasons(X)
    out = df.copy()
    out["score"] = pct
    out["score_raw"] = raw
    out["reasons"] = reasons
    return out.sort_values("score", ascending=False)


def _reasons(X: pd.DataFrame):
    tags = []
    for _, r in X.iterrows():
        t = []
        if r["ip_new_for_user"]: t.append("new-IP-for-user")
        if r["unseen_key"]: t.append("never-seen-endpoint")
        if r["unseen_status_for_key"]: t.append("unusual-status-for-endpoint")
        if r["fails_60s"] >= 3: t.append(f"{int(r['fails_60s'])}-failed-logins-in-60s")
        if r["user_resource_denied_rate"] > 0.5 and r["is_error"] == 0: t.append("success-on-usually-denied-resource")
        if r["status_for_key_rarity"] > 2: t.append("rare-status")
        tags.append(",".join(t) or "-")
    return tags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="file of raw Apache log lines to score")
    ap.add_argument("--demo", action="store_true", help="score the built-in March test window")
    ap.add_argument("--model", choices=["ae", "gmm"], default="ae")
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()

    if args.demo:
        df = labels.attach(data.load())
        df = df[df.ts >= data.VAL_END]  # March
    elif args.input:
        with open(args.input) as f:
            df = data.parse_lines(f.readlines())
        df["src_line"] = range(1, len(df) + 1)
    else:
        ap.error("pass --input FILE or --demo")

    scored = score_frame(df, model=args.model)
    top = scored.head(args.top)
    print(f"model={args.model}  scored {len(df)} lines  showing top {len(top)}\n")
    cols_have_label = "label" in scored.columns
    for _, r in top.iterrows():
        mark = ""
        if cols_have_label:
            mark = "  [TRUE ATTACK]" if r["label"] == 1 else ""
        print(f"  {r['score']:.4f}  {data.to_line(r)}   <{r['reasons']}>{mark}")
    if cols_have_label:
        n = args.top
        caught = int(scored.head(n).label.sum()); total = int(scored.label.sum())
        print(f"\n  attacks in top {n}: {caught}/{total}")


if __name__ == "__main__":
    main()
