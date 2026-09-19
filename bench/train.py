"""Train the frozen champions on all pre-March data and persist them for serving.

Produces results/model_store/ containing the feature encoder, the fitted scaler + GMM,
the deep-AE ensemble weights, and the config chosen on injected-val. Load with
bench.predict to score new log lines.
"""
from __future__ import annotations

import json
import pickle
import time
from pathlib import Path

import numpy as np
import torch

from . import data, labels, features, models

STORE = Path(__file__).resolve().parent.parent / "results" / "model_store"
SEL = Path(__file__).resolve().parent.parent / "results" / "final_selection.json"


def main():
    STORE.mkdir(parents=True, exist_ok=True)
    sel = json.loads(SEL.read_text()) if SEL.exists() else {"gmm": {"k": 4, "cov": "diag"},
                                                            "ae": {"hidden": [128, 64], "latent": 8, "dropout": 0.15}}
    df = labels.attach(data.load())
    # train on everything before March (the test month) - the deployable model uses all history
    train = df[df.ts < data.VAL_END]
    print(f"training on {len(train)} rows (Aug 2025 - Feb 2026)")

    enc = features.CtxEncoder().fit(train)
    Xtr = enc.transform(train)

    # GMM
    from sklearn.mixture import GaussianMixture
    from sklearn.preprocessing import StandardScaler
    t = time.time()
    scaler = StandardScaler().fit(Xtr.values)
    gmm = GaussianMixture(n_components=sel["gmm"]["k"], covariance_type=sel["gmm"]["cov"],
                          random_state=0, reg_covar=1e-4).fit(scaler.transform(Xtr.values))
    print(f"GMM trained in {time.time()-t:.1f}s")

    # Deep AE ensemble
    from .deep_model import DeepAEDetector
    ae_cfg = {k: (tuple(v) if k == "hidden" else v) for k, v in sel["ae"].items()}
    t = time.time()
    ae = DeepAEDetector(n_models=7, max_epochs=400, patience=30, batch_size=16384, **ae_cfg)
    ae.fit(Xtr.values)
    print(f"DeepAE ensemble trained in {time.time()-t:.1f}s on {'cuda' if torch.cuda.is_available() else 'cpu'}")

    rule = models.RuleNoveltyDetector().fit(Xtr)

    # persist. AE torch modules are saved as state_dicts; the rest via pickle.
    with open(STORE / "encoder.pkl", "wb") as f:
        pickle.dump(enc, f)
    with open(STORE / "gmm.pkl", "wb") as f:
        pickle.dump({"scaler": scaler, "gmm": gmm}, f)
    with open(STORE / "ae_meta.pkl", "wb") as f:
        pickle.dump({"scaler": ae.scaler, "feat_err": ae.feat_err, "cfg": ae.cfg,
                     "cols": list(Xtr.columns)}, f)
    torch.save([m.state_dict() for m in ae.models], STORE / "ae_models.pt")
    (STORE / "config.json").write_text(json.dumps(sel, indent=2, default=str))
    print(f"saved model store -> {STORE}")


if __name__ == "__main__":
    main()
