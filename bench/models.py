"""The detector zoo.

Each detector implements fit(X_train) then score(X) -> higher = more anomalous.
All are unsupervised: they never see labels. We run every applicable detector on both
feature views (RAW and CTX) so the comparison isolates *representation* from *algorithm*.
"""
from __future__ import annotations

import numpy as np
from sklearn.cluster import KMeans, MiniBatchKMeans
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.mixture import GaussianMixture


class _Scaled:
    """Mixin: standardise features on train, reuse the stats at score time."""

    def _fit_scaler(self, X):
        self.scaler = StandardScaler().fit(X)
        return self.scaler.transform(X)

    def _apply(self, X):
        return self.scaler.transform(X)


class KMeansDetector(_Scaled):
    """Distance to nearest centroid. The user's first instinct - included to show its ceiling."""

    def __init__(self, k=8, seed=0):
        self.k, self.seed = k, seed

    def fit(self, X):
        Xs = self._fit_scaler(X)
        self.km = MiniBatchKMeans(n_clusters=self.k, random_state=self.seed, n_init=3, batch_size=2048)
        self.km.fit(Xs)
        return self

    def score(self, X):
        d = self.km.transform(self._apply(X))
        return d.min(axis=1)


class GMMDetector(_Scaled):
    """Negative log-likelihood under a Gaussian mixture (soft-clustering density)."""

    def __init__(self, k=8, seed=0):
        self.k, self.seed = k, seed

    def fit(self, X):
        Xs = self._fit_scaler(X)
        self.gmm = GaussianMixture(n_components=self.k, covariance_type="diag", random_state=self.seed, reg_covar=1e-4)
        self.gmm.fit(Xs)
        return self

    def score(self, X):
        return -self.gmm.score_samples(self._apply(X))


class IForestDetector(_Scaled):
    def __init__(self, seed=0, n=300):
        self.seed, self.n = seed, n

    def fit(self, X):
        Xs = self._fit_scaler(X)
        self.m = IsolationForest(n_estimators=self.n, random_state=self.seed, n_jobs=-1)
        self.m.fit(Xs)
        return self

    def score(self, X):
        return -self.m.score_samples(self._apply(X))


class OCSVMDetector(_Scaled):
    """One-class SVM (RBF). Fit on a subsample - it is O(n^2) and cannot take 137k rows."""

    def __init__(self, seed=0, max_fit=8000, nu=0.05, gamma="scale"):
        self.seed, self.max_fit, self.nu, self.gamma = seed, max_fit, nu, gamma

    def fit(self, X):
        Xs = self._fit_scaler(X)
        rng = np.random.default_rng(self.seed)
        idx = rng.choice(len(Xs), size=min(self.max_fit, len(Xs)), replace=False)
        self.m = OneClassSVM(kernel="rbf", nu=self.nu, gamma=self.gamma).fit(Xs[idx])
        return self

    def score(self, X):
        return -self.m.decision_function(self._apply(X))


class LOFDetector(_Scaled):
    """Local Outlier Factor in novelty mode (fit on normal, score new points)."""

    def __init__(self, n_neighbors=20):
        self.n_neighbors = n_neighbors

    def fit(self, X):
        Xs = self._fit_scaler(X)
        self.m = LocalOutlierFactor(n_neighbors=self.n_neighbors, novelty=True, n_jobs=-1)
        self.m.fit(Xs)
        return self

    def score(self, X):
        return -self.m.decision_function(self._apply(X))


class PyODDetector(_Scaled):
    """Wrapper for pyod detectors (HBOS, ECOD, COPOD, PCA, AutoEncoder, DeepSVDD)."""

    def __init__(self, factory, needs_scale=True):
        self.factory, self.needs_scale = factory, needs_scale

    def fit(self, X):
        Xs = self._fit_scaler(X) if self.needs_scale else np.asarray(X)
        self.m = self.factory(Xs.shape[1])
        self.m.fit(Xs)
        return self

    def score(self, X):
        Xs = self._apply(X) if self.needs_scale else np.asarray(X)
        return self.m.decision_function(Xs)


class RuleNoveltyDetector:
    """Interpretable baseline: a weighted sum of the context signals, no learning beyond
    the rarity tables already in the features. This is the 'engineered surprisal' approach
    and the thing the ML detectors have to beat to justify their complexity.

    Operates directly on the CTX feature frame (column names are contractual).
    """

    WEIGHTS = {
        "unseen_key": 4.0,
        "unseen_status_for_key": 3.0,
        "ip_new_for_user": 3.0,
        "user_ip_rarity": 1.0,
        "status_for_key_rarity": 1.0,
        "user_key_rarity": 0.5,
        "fails_60s": 1.0,
        "user_resource_denied_rate": 2.0,
        "is_auth_fail": 0.5,
    }

    def fit(self, X):
        return self  # nothing to learn: the rarity is already baked into the features

    def score(self, X):
        s = np.zeros(len(X))
        for col, w in self.WEIGHTS.items():
            s = s + w * np.asarray(X[col], float)
        return s


def build_pyod():
    from pyod.models.hbos import HBOS
    from pyod.models.ecod import ECOD
    from pyod.models.copod import COPOD
    from pyod.models.pca import PCA as PPCA
    from pyod.models.auto_encoder import AutoEncoder
    from pyod.models.deep_svdd import DeepSVDD

    return {
        "HBOS": lambda: PyODDetector(lambda d: HBOS(n_bins=20)),
        "ECOD": lambda: PyODDetector(lambda d: ECOD()),
        "COPOD": lambda: PyODDetector(lambda d: COPOD()),
        "PCA": lambda: PyODDetector(lambda d: PPCA()),
        "AutoEncoder": lambda: PyODDetector(
            lambda d: AutoEncoder(epoch_num=30, batch_size=512, hidden_neuron_list=[32, 16, 32], verbose=0)
        ),
        "DeepSVDD": lambda: PyODDetector(
            lambda d: DeepSVDD(n_features=d, epochs=30, batch_size=512, verbose=0)
        ),
    }
