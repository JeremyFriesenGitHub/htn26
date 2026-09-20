"""Serving metadata only: importing the dashboard must not import ML dependencies.

All detectors use the contextual feature view. RAW/CTX benchmark variants are
representation comparisons, not separate production detector choices.
"""

_BASE = ("numpy", "pandas", "sklearn", "scipy")


def _spec(name, benchmark_name, score_label, meaning, dependencies=(), artifacts=None):
    return {"name": name, "benchmark_name": benchmark_name,
            "score_label": score_label, "meaning": meaning,
            "dependencies": _BASE + tuple(dependencies), "artifacts": artifacts}


TRAINED_MODELS = {
    "gmm": _spec("Gaussian mixture", "GMM", "Negative log density",
                 "Higher scores mean lower density in the learned feature distribution.",
                 artifacts=("encoder.pkl", "gmm.pkl")),
    "ae": _spec("Deep autoencoder ensemble", "DeepAE", "Weighted reconstruction error",
                "Feature reconstruction errors normalized by training errors, averaged across the ensemble.",
                dependencies=("torch",), artifacts=("encoder.pkl", "ae_meta.pkl", "ae_models.pt")),
    "kmeans": _spec("K-Means", "KMeans", "Distance to nearest centroid",
                    "Distance from the nearest learned centroid in standardized feature space."),
    "iforest": _spec("Isolation Forest", "IsolationForest", "Negated isolation score",
                     "Negated score_samples output; larger values indicate more isolated observations."),
    "ocsvm": _spec("One-Class SVM", "OneClassSVM", "Negated decision margin",
                   "Negated distance from the learned decision boundary; larger values are more unusual."),
    "lof": _spec("Local Outlier Factor", "LOF", "Negated novelty margin",
                 "Negated novelty decision function reflecting local density relative to learned neighbors."),
    "hbos": _spec("HBOS", "HBOS", "Histogram outlier score",
                  "Outlier score from the learned per-feature histograms.", dependencies=("pyod.models.hbos",)),
    "ecod": _spec("ECOD", "ECOD", "Empirical-tail outlier score",
                  "Empirical cumulative-distribution tail score supplied by ECOD.", dependencies=("pyod.models.ecod",)),
    "copod": _spec("COPOD", "COPOD", "Copula-tail outlier score",
                   "Copula-based empirical tail score supplied by COPOD.", dependencies=("pyod.models.copod",)),
    "pca": _spec("PCA detector", "PCA", "PCA outlier score",
                 "PyOD PCA decision score from deviations along the learned components.", dependencies=("pyod.models.pca",)),
    "pyod_ae": _spec("PyOD autoencoder", "AutoEncoder", "Reconstruction outlier score",
                     "Reconstruction decision score supplied by the PyOD autoencoder.", dependencies=("torch", "pyod.models.auto_encoder")),
    "deep_svdd": _spec("Deep SVDD", "DeepSVDD", "Hypersphere distance score",
                       "Decision score from distance to the learned deep representation center.", dependencies=("torch", "pyod.models.deep_svdd")),
    "rule_novelty": _spec("Context novelty baseline", "RuleNovelty", "Weighted context novelty",
                          "Weighted contextual rarity and novelty features using the fitted training encoder."),
    "ensemble": _spec("Rank ensemble", "Ensemble", "Mean training-reference rank",
                      "Mean training-reference percentile from GMM, ECOD, PyOD autoencoder, and One-Class SVM. Agreement is not independent confirmation.",
                      dependencies=("torch", "pyod.models.ecod", "pyod.models.auto_encoder")),
}
for _model_id, _metadata in TRAINED_MODELS.items():
    if _metadata["artifacts"] is None:
        _metadata["artifacts"] = (_model_id + ".pkl",)
