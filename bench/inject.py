"""Synthetic attack injection for label-free model selection.

The real incident lives entirely in March (the test month); February (validation) has no
attacks. To tune hyperparameters and thresholds WITHOUT peeking at the test labels, we
synthesise attacks that mimic the same tactics into a copy of the validation window and
select models on how well they rank those. The real March test stays pristine.

Tactics mirrored from the real incident (but with different users/resources/timing so we
don't just memorise it):
  - credential brute force: a burst of 401s for a user from an IP that isn't theirs
  - account takeover: a successful login + confidential download from the wrong IP
  - privilege abuse: a user succeeding on a resource they are normally denied
  - injection probe: a request with never-seen query parameters + rare status
  - novel endpoint: a request to an endpoint absent from training
"""
from __future__ import annotations

import numpy as np
import pandas as pd


def _row(base, ts, ip, user, method, path, status, nbytes, tmpl, key, tag):
    r = base.copy()
    r.update(ip=ip, user=user, ts=ts, method=method, path=path, status=status,
             bytes=int(nbytes), tmpl=tmpl, key=key, label=1, attack_type="synthetic",
             incident="synthetic", tier="detectable", stage=tag,
             src_line=-1, raw="synthetic")
    return r


def inject(val: pd.DataFrame, train: pd.DataFrame, seed=0) -> pd.DataFrame:
    """Return val + synthetic attacks. Uses train to pick 'wrong' IPs and denied resources."""
    rng = np.random.default_rng(seed)
    base = val.iloc[0].to_dict()
    users = sorted(val.user.unique())
    user_ip = train.groupby("user").ip.agg(lambda s: s.value_counts().index[0]).to_dict()
    # sensitive resources and, per user, the ones they are (almost) always denied
    sens = train[train.tmpl.str.startswith(("/finance", "/hr", "/it", "/eng", "/exec", "/sales", "/marketing"))]
    denied = {}
    for u in users:
        us = sens[sens.user == u]
        by = us.groupby("tmpl").apply(lambda g: (g.status == 403).mean(), include_groups=False)
        denied[u] = [t for t, frac in by.items() if frac > 0.9]

    day = val.ts.dt.normalize().unique()
    rows = []

    def rand_day_time(hour_lo=8, hour_hi=19):
        d = pd.Timestamp(rng.choice(day))
        return d + pd.Timedelta(hours=int(rng.integers(hour_lo, hour_hi)),
                                minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))

    # 3 independent synthetic incidents so val has enough positives to rank
    for k in range(3):
        victim, attacker = rng.choice(users, size=2, replace=False)
        wrong_ip = user_ip[attacker]  # attacker's own IP, used under victim's name
        t0 = rand_day_time(20, 23)  # off hours
        # brute force burst
        for i in range(rng.integers(4, 8)):
            rows.append(_row(base, t0 + pd.Timedelta(seconds=3 * i), wrong_ip, victim,
                             "POST", "/api/auth/login", 401, 88,
                             "/api/auth/login", "POST /api/auth/login", "bf"))
        # takeover: success + confidential pull from wrong IP
        t1 = t0 + pd.Timedelta(minutes=int(rng.integers(30, 300)))
        rows.append(_row(base, t1, wrong_ip, victim, "POST", "/api/auth/login", 200, 128,
                         "/api/auth/login", "POST /api/auth/login", "takeover"))
        res = denied[attacker][0] if denied[attacker] else "/finance/reports/q1_draft_CONFIDENTIAL.zip"
        rows.append(_row(base, t1 + pd.Timedelta(seconds=40), wrong_ip, victim, "GET", res, 200,
                         8459200, res, f"GET {res}", "exfil"))
        # privilege abuse: attacker succeeds on a normally-denied resource from own IP
        if denied[attacker]:
            r2 = denied[attacker][min(1, len(denied[attacker]) - 1)]
            rows.append(_row(base, rand_day_time(), user_ip[attacker], attacker, "GET", r2, 200,
                             45120, r2, f"GET {r2}", "privabuse"))
        # injection probe: never-seen params + rare status
        rows.append(_row(base, rand_day_time(), user_ip[attacker], attacker, "POST",
                         "/intranet/forum/new?topic=x&exec=1&inject=1", 500, 1024,
                         "/intranet/forum/new", "POST /intranet/forum/new", "inject"))
        # novel endpoint absent from training
        rows.append(_row(base, rand_day_time(), user_ip[attacker], attacker, "GET",
                         "/api/internal/debug/dump", 200, 9000,
                         "/api/internal/debug/dump", "GET /api/internal/debug/dump", "novel_ep"))

    syn = pd.DataFrame(rows)
    out = pd.concat([val, syn], ignore_index=True).sort_values("ts").reset_index(drop=True)
    return out
