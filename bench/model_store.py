"""Locate a complete deployment bundle or a locally trained/custom model store."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUNDLED = ROOT / "deployment" / "models"
ARTIFACTS = ("encoder.pkl", "gmm.pkl", "ae_meta.pkl", "ae_models.pt")


def model_store():
    requested = Path(os.environ.get("MODEL_STORE", ROOT / "results" / "model_store"))
    # An empty Railway volume should not hide the bundled models. A populated
    # custom store remains authoritative, even if incomplete: never mix weights
    # or encoders from separate training runs.
    if any((requested / name).exists() for name in ARTIFACTS):
        return requested
    if (BUNDLED / "encoder.pkl").is_file():
        return BUNDLED
    return requested
