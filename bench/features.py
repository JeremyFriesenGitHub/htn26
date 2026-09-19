"""Two feature views of each log line.

RAW   : the 7 log fields, encoded naively (what a "just cluster it" approach sees).
CTX   : behavioural / contextual features built from per-entity history, computed
        causally (each row sees only earlier rows) so nothing leaks from the future.

Both views are fit on the training slice only; the fitted state is then applied to
val/test. This mirrors deployment: you learn "normal" once, then score new traffic.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- RAW view

RAW_COLS = ["ip", "user", "method", "status", "hour", "weekday", "log_bytes", "path_hash"]


def raw_view(df: pd.DataFrame, cat_maps=None):
    """Encode the 7 fields with no engineering: categoricals -> integer codes.

    This is deliberately the weak, obvious representation - distance in this space is
    dominated by log_bytes and treats IPs/users as arbitrary integers.
    """
    out = pd.DataFrame(index=df.index)
    out["hour"] = df.ts.dt.hour
    out["weekday"] = df.ts.dt.weekday
    out["status"] = df.status
    out["log_bytes"] = np.log1p(df["bytes"])
    fit = cat_maps is None
    cat_maps = {} if fit else cat_maps
    for col, src in [("ip", df.ip), ("user", df.user), ("method", df.method), ("path_hash", df.tmpl)]:
        if fit:
            cats = {v: i for i, v in enumerate(sorted(src.unique()))}
            cat_maps[col] = cats
        out[col] = src.map(cat_maps[col]).fillna(-1).astype(int)
    return out[RAW_COLS], cat_maps


# ---------------------------------------------------------------- CTX view

CTX_COLS = [
    "ip_new_for_user",       # this user never came from this IP during training
    "user_ip_rarity",        # -log P(ip | user) from training
    "key_global_rarity",     # -log P(method+template) globally
    "user_key_rarity",       # -log P(key | user)
    "status_for_key_rarity", # -log P(status | key): a 200 on a usually-403 path scores high
    "user_resource_denied_rate",  # historically, fraction of this user's hits on this resource that were 403
    "is_sensitive",          # request under a department/confidential namespace
    "is_error",              # status >= 400
    "is_auth_fail",          # 401
    "fails_60s",             # rolling count of 401s from this (ip,user) in the last 60s
    "req_5m",                # rolling request count from this (ip,user) in the last 5 min (burst)
    "unseen_key",            # method+template never seen in training
    "unseen_status_for_key", # (template,status) pair never seen in training
    "off_hours",             # outside 08:00-19:00
    "log_bytes",             # log transfer size
]

SENSITIVE_PREFIXES = ("/finance", "/hr", "/it", "/eng", "/exec", "/sales", "/marketing", "/api/admin")


class CtxEncoder:
    """Learns rarity/permission statistics on training data, applies them anywhere."""

    def fit(self, train: pd.DataFrame):
        n = len(train)
        self.user_ip = _cond_logprob(train, "user", "ip")
        self.key_global = _log_rarity(train["key"], n)
        self.user_key = _cond_logprob(train, "user", "key")
        self.status_for_key = _cond_logprob(train, "key", "status")
        self.seen_keys = set(train["key"].unique())
        self.seen_key_status = set(zip(train["key"], train["status"]))
        self.seen_user_ip = set(zip(train["user"], train["ip"]))
        # per (user,resource) historical denial rate on sensitive resources
        sens = train[train.tmpl.str.startswith(SENSITIVE_PREFIXES)]
        grp = sens.assign(denied=(sens.status == 403).astype(int)).groupby(["user", "tmpl"])["denied"]
        self.denied_rate = grp.mean().to_dict()
        self.global_denied = float((sens.status == 403).mean()) if len(sens) else 0.0
        self._max_rarity = max(self.key_global.values()) + 1.0
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        d = df.sort_values("ts")
        out = pd.DataFrame(index=d.index)
        user, ip, key, tmpl, status = d.user, d.ip, d.key, d.tmpl, d.status
        out["ip_new_for_user"] = [int((u, i) not in self.seen_user_ip) for u, i in zip(user, ip)]
        out["user_ip_rarity"] = [self.user_ip.get((u, i), self._max_rarity) for u, i in zip(user, ip)]
        out["key_global_rarity"] = [self.key_global.get(k, self._max_rarity) for k in key]
        out["user_key_rarity"] = [self.user_key.get((u, k), self._max_rarity) for u, k in zip(user, key)]
        out["status_for_key_rarity"] = [self.status_for_key.get((k, s), self._max_rarity) for k, s in zip(key, status)]
        out["user_resource_denied_rate"] = [
            self.denied_rate.get((u, t), self.global_denied) if t.startswith(SENSITIVE_PREFIXES) else 0.0
            for u, t in zip(user, tmpl)
        ]
        out["is_sensitive"] = tmpl.str.startswith(SENSITIVE_PREFIXES).astype(int).values
        out["is_error"] = (status >= 400).astype(int).values
        out["is_auth_fail"] = (status == 401).astype(int).values
        out["unseen_key"] = [int(k not in self.seen_keys) for k in key]
        out["unseen_status_for_key"] = [int((k, s) not in self.seen_key_status) for k, s in zip(key, status)]
        out["off_hours"] = ((d.ts.dt.hour < 8) | (d.ts.dt.hour >= 19)).astype(int).values
        out["log_bytes"] = np.log1p(d["bytes"]).values
        out["fails_60s"] = _rolling_count(d, mask=(status == 401), window="60s").values
        out["req_5m"] = _rolling_count(d, mask=pd.Series(True, index=d.index), window="300s").values
        return out.reindex(df.index)[CTX_COLS]


def _log_rarity(series: pd.Series, n: int) -> dict:
    vc = series.value_counts()
    return (-np.log(vc / n)).to_dict()


def _cond_logprob(df: pd.DataFrame, a: str, b: str) -> dict:
    """-log P(b | a) as a dict keyed by (a_value, b_value)."""
    joint = df.groupby([a, b]).size()
    totals = df.groupby(a).size()
    out = {}
    for (av, bv), c in joint.items():
        out[(av, bv)] = float(-np.log(c / totals[av]))
    return out


def _rolling_count(d: pd.DataFrame, mask: pd.Series, window: str) -> pd.Series:
    """For each row, how many masked events occurred in the trailing window per (ip,user).

    Counts strictly earlier-or-equal events sharing the (ip,user) actor. Causal by construction.
    """
    res = pd.Series(0, index=d.index, dtype=int)
    sub = d[mask]
    if sub.empty:
        return res
    for _, g in sub.groupby([sub.ip, sub.user]):
        t = g.ts.values.astype("datetime64[ns]")
        w = np.timedelta64(int(window[:-1]), "s")
        counts = np.searchsorted(t, t, side="right") - np.searchsorted(t, t - w, side="left")
        res.loc[g.index] = counts
    return res
