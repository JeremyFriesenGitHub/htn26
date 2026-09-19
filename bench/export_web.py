"""Export the fitted encoder + RuleNovelty scorer to JSON for the in-browser front-end.

The web app re-implements the CTX feature extraction and the weighted-surprisal score in
JS. Everything it needs is dumped here: the rarity tables (their keys double as the
"seen" sets), the per-user denial rates, the sensitive-path prefixes, the rule weights,
tier thresholds derived from the training score distribution, and a demo log sample.

    .venv/bin/python -m bench.export_web
-> results/web/model.json + results/web/demo_logs.txt  (+ a Python parity check)
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from . import data, labels, features, models

SEP = "§"  # section-sign delimiter for composite keys; never appears in log data
OUT = Path(__file__).resolve().parent.parent / "results" / "web"


def tuple_dict(d, order):
    """{(a,b,...): v} -> {"a§b§...": v}."""
    return {SEP.join(str(k[i]) for i in range(order)): float(v) for k, v in d.items()}


def build_model(enc, rule, train):
    model = {
        "sep": SEP,
        "sensitive_prefixes": list(features.SENSITIVE_PREFIXES),
        "max_rarity": float(enc._max_rarity),
        "global_denied": float(enc.global_denied),
        "rule_weights": dict(models.RuleNoveltyDetector.WEIGHTS),
        "user_ip": tuple_dict(enc.user_ip, 2),                # keys -> seen (user,ip)
        "key_global": {k: float(v) for k, v in enc.key_global.items()},  # keys -> seen keys
        "user_key": tuple_dict(enc.user_key, 2),
        "status_for_key": tuple_dict(enc.status_for_key, 2),  # keys -> seen (key,status)
        "denied_rate": tuple_dict(enc.denied_rate, 2),
        "off_hours": {"lo": 8, "hi": 19},
        "burst_windows": {"fails_60s": 60, "req_5m": 300},
    }
    s_tr = rule.score(enc.transform(train))
    model["tiers"] = {"yellow": float(np.quantile(s_tr, 0.99)),
                      "red": float(np.quantile(s_tr, 0.999))}
    model["display_cap"] = float(np.quantile(s_tr, 0.9999)) or 1.0
    return model


def rolling_fails(d, window):
    """fails_60s per (ip,user), causal (mirrors features._rolling_count)."""
    fails = np.zeros(len(d))
    mask = (d.status.values == 401)
    if not mask.any():
        return fails
    sub = d[mask]
    for _, g in sub.groupby([sub.ip, sub.user]):
        tsec = g.ts.values.astype("datetime64[s]").astype(np.int64)
        counts = np.searchsorted(tsec, tsec, side="right") - np.searchsorted(tsec, tsec - window, side="left")
        fails[g.index.values] = counts
    return fails


def js_style_scores(d, model):
    """Mirror the JS implementation, in Python, from the exported JSON. `d` is time-sorted
    with a clean RangeIndex; returns scores in that same order."""
    sep = model["sep"]; mr = model["max_rarity"]; W = model["rule_weights"]
    sens = tuple(model["sensitive_prefixes"])
    fails = rolling_fails(d, model["burst_windows"]["fails_60s"])
    out = np.zeros(len(d))
    for pos in range(len(d)):
        u = d.user.iat[pos]; ip = d.ip.iat[pos]; k = d.key.iat[pos]
        t = d.tmpl.iat[pos]; s = int(d.status.iat[pos])
        f = {
            "ip_new_for_user": 0 if (u + sep + ip) in model["user_ip"] else 1,
            "user_ip_rarity": model["user_ip"].get(u + sep + ip, mr),
            "user_key_rarity": model["user_key"].get(u + sep + k, mr),
            "status_for_key_rarity": model["status_for_key"].get(k + sep + str(s), mr),
            "unseen_key": 0 if k in model["key_global"] else 1,
            "unseen_status_for_key": 0 if (k + sep + str(s)) in model["status_for_key"] else 1,
            "is_auth_fail": 1 if s == 401 else 0,
            "user_resource_denied_rate": (model["denied_rate"].get(u + sep + t, model["global_denied"])
                                          if t.startswith(sens) else 0.0),
            "fails_60s": fails[pos],
        }
        out[pos] = sum(W[c] * f[c] for c in W)
    return out


def parity_check(model, test, enc, rule):
    d = test.sort_values("ts").reset_index(drop=True)
    real = np.asarray(rule.score(enc.transform(d)))
    sim = js_style_scores(d, model)
    def tier(s):
        s = np.asarray(s)
        return np.where(s >= model["tiers"]["red"], 2, np.where(s >= model["tiers"]["yellow"], 1, 0))
    return {"max_diff": float(np.abs(real - sim).max()),
            "tier_agree": float((tier(real) == tier(sim)).mean())}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    df = labels.attach(data.load())
    train = df[df.ts < data.VAL_END]
    test = df[df.ts >= data.VAL_END]

    enc = features.CtxEncoder().fit(train)
    rule = models.RuleNoveltyDetector()
    model = build_model(enc, rule, train)
    (OUT / "model.json").write_text(json.dumps(model, separators=(",", ":")))

    rng = np.random.default_rng(0)
    atk = test[test.label == 1]
    normal = test[test.label == 0]
    keep = normal.iloc[rng.choice(len(normal), size=min(2200, len(normal)), replace=False)]
    demo = pd.concat([atk, keep]).sort_values("ts")
    (OUT / "demo_logs.txt").write_text("\n".join(data.to_line(r) for _, r in demo.iterrows()))

    p = parity_check(model, test, enc, rule)
    print(f"model.json: {len(json.dumps(model))/1024:.0f} KB, {len(model['user_key'])} user-key entries")
    print(f"demo_logs.txt: {len(demo)} lines ({len(atk)} attacks)")
    print(f"tiers: yellow>={model['tiers']['yellow']:.2f}  red>={model['tiers']['red']:.2f}  cap={model['display_cap']:.2f}")
    print(f"PARITY vs real RuleNovelty on {len(test)} rows: max abs diff={p['max_diff']:.2e}, "
          f"tier agreement={p['tier_agree']:.4f}")


if __name__ == "__main__":
    main()
