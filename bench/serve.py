"""Localhost web server for the log-anomaly console, backed by the REAL trained models.

Serves results/webapp.html and exposes /api/score, which runs the actual Python pipeline
(CTX features -> GMM / deep autoencoder / RuleNovelty) instead of the in-browser port.
Tier thresholds are derived per model from the training score distribution (label-free:
99th percentile = suspicious, 99.9th = anomaly).

    .venv/bin/python -m bench.serve            # http://localhost:8000
    .venv/bin/python -m bench.serve --port 9000
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from flask import Flask, jsonify, request, send_file

from . import data, features, labels, models, predict

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "results" / "webapp.html"

app = Flask(__name__)
STATE: dict = {}


def ae_abs_score(ae, X: np.ndarray) -> np.ndarray:
    """Absolute weighted reconstruction error (the detector's .score() ranks within a batch,
    which is meaningless for a handful of pasted lines - so use the raw error here)."""
    Xs = ae.scaler.transform(X).astype(np.float32)
    per = [(ae._recon_err(m, Xs) / ae.feat_err).mean(axis=1) for m in ae.models]
    return np.mean(per, axis=0)


def score_with(model_name: str, X_df):
    Xv = X_df.values
    if model_name == "gmm":
        return np.asarray(STATE["gmm"].score(Xv), float)
    if model_name == "ae":
        return ae_abs_score(STATE["ae"], Xv)
    return np.asarray(STATE["rule"].score(X_df), float)


def boot(sample: int = 40000):
    """Load models and calibrate per-model tier thresholds on training traffic."""
    print("loading model store ...")
    STATE["enc"] = predict.load_encoder()
    STATE["gmm"] = predict._load_gmm()
    STATE["ae"] = predict._load_ae()
    STATE["rule"] = models.RuleNoveltyDetector()

    df = labels.attach(data.load())
    train = df[df.ts < data.VAL_END]
    if len(train) > sample:
        train = train.iloc[np.random.default_rng(0).choice(len(train), sample, replace=False)]
    Xtr = STATE["enc"].transform(train.sort_values("ts").reset_index(drop=True))
    STATE["tiers"] = {}
    for m in ("rule", "gmm", "ae"):
        s = score_with(m, Xtr)
        STATE["tiers"][m] = {"yellow": float(np.quantile(s, 0.99)),
                             "red": float(np.quantile(s, 0.999))}
        print(f"  {m:4s} thresholds: yellow>={STATE['tiers'][m]['yellow']:.3f} "
              f"red>={STATE['tiers'][m]['red']:.3f}")
    print("ready.")


@app.get("/")
def index():
    if not PAGE.exists():
        return ("results/webapp.html not built yet - run:\n"
                "  .venv/bin/python -m bench.export_web && .venv/bin/python -m bench.webapp\n"), 503
    return send_file(PAGE)


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "models": sorted(STATE["tiers"]), "tiers": STATE["tiers"]})


@app.post("/api/score")
def api_score():
    payload = request.get_json(force=True, silent=True) or {}
    lines = payload.get("lines") or []
    model_name = payload.get("model", "rule")
    if model_name not in ("rule", "gmm", "ae"):
        return jsonify({"error": "unknown model"}), 400
    if not lines:
        return jsonify({"scores": [], "tiers": [], "reasons": []})

    try:
        df = data.parse_lines(lines)
    except ValueError as e:
        return jsonify({"error": f"unparseable input: {e}"}), 400
    df = df.reset_index(drop=True)

    X = STATE["enc"].transform(df)
    s = score_with(model_name, X)
    th = STATE["tiers"][model_name]
    tiers = ["red" if v >= th["red"] else ("yellow" if v >= th["yellow"] else "green") for v in s]
    reasons = predict._reasons(X)
    return jsonify({
        "model": model_name,
        "scores": [float(v) for v in s],
        "tiers": tiers,
        "reasons": [[] if r == "-" else r.split(",") for r in reasons],
        "tiers_at": th,
    })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    boot()
    print(f"\n  ->  http://localhost:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
