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
import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from . import data, labels, features, models
from .model_registry import TRAINED_MODELS

STORE = Path(os.environ.get("MODEL_STORE", Path(__file__).resolve().parent.parent / "results" / "model_store"))


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


def load_model(model):
    """Load the detector with the exact encoder used to train it."""
    if model not in TRAINED_MODELS:
        raise ValueError(f"Unknown trained model: {model}")
    if model in ("gmm", "ae"):
        artifact = "gmm.pkl" if model == "gmm" else "ae_meta.pkl"
        with open(STORE / artifact, "rb") as f:
            bundle = pickle.load(f)
        encoder = bundle.get("encoder")
        if encoder is None:
            encoder = load_encoder()  # compatibility with the original model store
        detector = _load_gmm() if model == "gmm" else _load_ae()
    else:
        with open(STORE / f"{model}.pkl", "rb") as f:
            bundle = pickle.load(f)
        encoder, detector = bundle["encoder"], bundle["detector"]
    return encoder, detector


def score_frame(df: pd.DataFrame, model="ae", progress=None):
    def report(stage, message, **counts):
        if progress:
            progress({"type": "progress", "stage": stage, "message": message, **counts})

    report("features", "Loading the trained feature encoder")
    enc, det = load_model(model)
    report("features", "Computing contextual request features")
    X = enc.transform(df)
    # absolute score where the detector offers one, so callers can calibrate it
    # against the training distribution instead of ranking within the batch
    scorer = getattr(det, "score_abs", det.score)
    report("model", "Scoring requests with the saved detector")
    raw = np.asarray(scorer(X if model == "rule_novelty" else X.values), float)
    from scipy.stats import rankdata
    pct = rankdata(raw) / len(raw)  # 0..1 percentile within this batch
    report("reasons", "Collecting explanation tags", completed=0, total=len(X))
    reasons = _reasons(X, progress=progress)
    out = df.copy()
    out["score"] = pct
    out["score_raw"] = raw
    out["reasons"] = reasons
    return out.sort_values("score", ascending=False)


def _reasons(X: pd.DataFrame, progress=None):
    tags = []
    for position, (_, r) in enumerate(X.iterrows(), 1):
        t = []
        if r["ip_new_for_user"]: t.append("new-IP-for-user")
        if r["unseen_key"]: t.append("never-seen-endpoint")
        if r["unseen_status_for_key"]: t.append("unusual-status-for-endpoint")
        if r["fails_60s"] >= 3: t.append(f"{int(r['fails_60s'])}-failed-logins-in-60s")
        if r["user_resource_denied_rate"] > 0.5 and r["is_error"] == 0: t.append("success-on-usually-denied-resource")
        if r["status_for_key_rarity"] > 2: t.append("rare-status")
        tags.append(",".join(t) or "-")
        if progress and (position % 1000 == 0 or position == len(X)):
            progress({"type": "progress", "stage": "reasons", "message": "Collecting explanation tags",
                      "completed": position, "total": len(X)})
    return tags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="file of raw Apache log lines to score")
    ap.add_argument("--demo", action="store_true", help="score the built-in March test window")
    ap.add_argument("--model", choices=list(TRAINED_MODELS), default="ae")
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
