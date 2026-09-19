"""Deep autoencoder anomaly detector, engineered properly.

Unsupervised: trained to reconstruct NORMAL traffic; anomaly score = reconstruction error.
Techniques:
  - MLP encoder/decoder with BatchNorm1d + GELU + Dropout (regularisation)
  - AdamW with weight decay (L2 regularisation)
  - CosineAnnealingWarmRestarts LR schedule (smooth decay, avoids LR blow-ups)
  - gradient clipping (guards against exploding grads / overflow)
  - AMP mixed precision on CUDA (uses the 2060's tensor cores; larger effective batch)
  - large batch (default 16384) — the whole 137k-row train set fits on 6 GB many times over
  - early stopping on a held-out validation reconstruction loss
  - a small ensemble of independently-seeded AEs, scores rank-averaged (variance reduction)

Scoring uses per-feature reconstruction error scaled by each feature's train error
(a Mahalanobis-flavoured weighting) so rarely-wrong features dominate the score.
"""
from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler


def _device():
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


class AutoEncoder(nn.Module):
    def __init__(self, d_in, hidden=(64, 32), latent=8, dropout=0.1):
        super().__init__()
        dims = [d_in, *hidden, latent]
        enc = []
        for a, b in zip(dims[:-1], dims[1:]):
            enc += [nn.Linear(a, b), nn.BatchNorm1d(b), nn.GELU(), nn.Dropout(dropout)]
        self.encoder = nn.Sequential(*enc[:-1])  # no dropout right after latent
        dec, rdims = [], list(reversed(dims))
        for i, (a, b) in enumerate(zip(rdims[:-1], rdims[1:])):
            dec += [nn.Linear(a, b)]
            if i < len(rdims) - 2:  # no BN/act on the final reconstruction layer
                dec += [nn.BatchNorm1d(b), nn.GELU(), nn.Dropout(dropout)]
        self.decoder = nn.Sequential(*dec)

    def forward(self, x):
        return self.decoder(self.encoder(x))


class DeepAEDetector:
    def __init__(self, hidden=(64, 32), latent=8, dropout=0.1, lr=2e-3, weight_decay=1e-4,
                 batch_size=16384, max_epochs=300, patience=25, n_models=5, seed=0, verbose=False):
        self.cfg = dict(hidden=hidden, latent=latent, dropout=dropout, lr=lr,
                        weight_decay=weight_decay, batch_size=batch_size, max_epochs=max_epochs,
                        patience=patience, n_models=n_models, seed=seed, verbose=verbose)
        self.models, self.feat_err = [], None

    def _train_one(self, Xtr, Xva, seed):
        dev = _device()
        torch.manual_seed(seed); np.random.seed(seed)
        d_in = Xtr.shape[1]
        model = AutoEncoder(d_in, self.cfg["hidden"], self.cfg["latent"], self.cfg["dropout"]).to(dev)
        opt = torch.optim.AdamW(model.parameters(), lr=self.cfg["lr"], weight_decay=self.cfg["weight_decay"])
        sched = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(opt, T_0=25, T_mult=2)
        use_amp = dev.type == "cuda"
        scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
        loss_fn = nn.MSELoss()
        Xtr_t = torch.tensor(Xtr, dtype=torch.float32, device=dev)
        Xva_t = torch.tensor(Xva, dtype=torch.float32, device=dev)
        bs = min(self.cfg["batch_size"], len(Xtr))
        n = len(Xtr)

        best_val, best_state, bad = float("inf"), None, 0
        for epoch in range(self.cfg["max_epochs"]):
            model.train()
            perm = torch.randperm(n, device=dev)
            for i in range(0, n, bs):
                idx = perm[i:i + bs]
                if len(idx) < 2:  # BatchNorm needs >=2
                    continue
                xb = Xtr_t[idx]
                opt.zero_grad(set_to_none=True)
                with torch.amp.autocast("cuda", enabled=use_amp):
                    loss = loss_fn(model(xb), xb)
                scaler.scale(loss).backward()
                scaler.unscale_(opt)
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)  # anti-overflow
                scaler.step(opt); scaler.update()
            sched.step(epoch)
            model.eval()
            with torch.no_grad(), torch.amp.autocast("cuda", enabled=use_amp):
                vloss = loss_fn(model(Xva_t), Xva_t).item()
            if vloss < best_val - 1e-5:
                best_val, best_state, bad = vloss, {k: v.detach().clone() for k, v in model.state_dict().items()}, 0
            else:
                bad += 1
                if bad >= self.cfg["patience"]:
                    break
            if self.cfg["verbose"] and epoch % 20 == 0:
                print(f"      seed{seed} epoch{epoch:3d} val={vloss:.5f} best={best_val:.5f} lr={sched.get_last_lr()[0]:.2e}")
        model.load_state_dict(best_state)
        model.eval()
        return model, best_val

    def fit(self, X, X_val=None):
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X).astype(np.float32)
        if X_val is None:  # carve a val split for early stopping
            rng = np.random.default_rng(self.cfg["seed"])
            m = rng.random(len(Xs)) < 0.9
            Xtr, Xva = Xs[m], Xs[~m]
        else:
            Xtr, Xva = Xs, self.scaler.transform(X_val).astype(np.float32)
        self.models = []
        for j in range(self.cfg["n_models"]):
            model, vloss = self._train_one(Xtr, Xva, self.cfg["seed"] + j)
            self.models.append(model)
            if self.cfg["verbose"]:
                print(f"    AE {j+1}/{self.cfg['n_models']} val_recon={vloss:.5f}")
        # per-feature typical error on training, for weighted scoring
        errs = np.mean([self._recon_err(model, Xtr) for model in self.models], axis=0)
        self.feat_err = errs.mean(axis=0) + 1e-6
        return self

    def _recon_err(self, model, Xs):
        dev = _device()
        with torch.no_grad(), torch.amp.autocast("cuda", enabled=dev.type == "cuda"):
            out = model(torch.tensor(Xs, dtype=torch.float32, device=dev)).float().cpu().numpy()
        return (Xs - out) ** 2

    def score(self, X):
        Xs = self.scaler.transform(X).astype(np.float32)
        from scipy.stats import rankdata
        per_model = []
        for model in self.models:
            sq = self._recon_err(model, Xs)
            weighted = (sq / self.feat_err).mean(axis=1)  # emphasise usually-well-reconstructed dims
            per_model.append(rankdata(weighted) / len(weighted))  # rank so models combine fairly
        return np.mean(per_model, axis=0)
