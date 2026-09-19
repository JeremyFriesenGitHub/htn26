"""Forensic ground truth for the real incident found in March 2026.

These labels come from a manual investigation (IP/user mismatch, 401 bursts, never-seen
endpoints and parameters, and a user succeeding on a resource they had only ever been denied).
Every row is listed explicitly so the labels can be reviewed by a human.

tier:
  detectable - anomalous from the log line plus history alone
  context    - only suspicious once linked to the rest of the attack chain
"""
import pandas as pd

# (timestamp, ip, user, method, path, status, stage, tier)
INCIDENT = [
    ("13/Mar/2026:23:10:19", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("13/Mar/2026:23:10:25", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("13/Mar/2026:23:10:28", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("13/Mar/2026:23:10:32", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("14/Mar/2026:09:19:15", "10.0.8.45", "david_m", "GET", "/finance/reports/q1_draft_CONFIDENTIAL.zip", 403, "recon", "context"),
    ("14/Mar/2026:22:11:26", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("14/Mar/2026:22:11:30", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("14/Mar/2026:22:11:32", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("14/Mar/2026:22:11:35", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("14/Mar/2026:22:11:37", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("14/Mar/2026:22:11:39", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 401, "bruteforce", "detectable"),
    ("15/Mar/2026:09:20:20", "10.0.8.45", "david_m", "POST", "/intranet/forum/new?topic=lunch_menu&payload=csrf_test", 500, "csrf_probe", "detectable"),
    ("15/Mar/2026:09:42:35", "10.0.8.45", "david_m", "POST", "/intranet/forum/new?topic=q1_updates&action=csrf_role_update", 400, "csrf_probe", "detectable"),
    ("15/Mar/2026:10:18:52", "10.0.8.45", "david_m", "POST", "/intranet/forum/new?topic=parking_issues&script=success", 302, "csrf_probe", "detectable"),
    ("15/Mar/2026:11:07:57", "10.0.5.12", "sarah_j", "POST", "/api/admin/role_update", 200, "csrf_fired", "detectable"),
    ("15/Mar/2026:11:07:59", "10.0.5.12", "sarah_j", "GET", "/assets/avatar_1042.png", 200, "csrf_fired", "detectable"),
    ("15/Mar/2026:11:26:59", "10.0.8.45", "david_m", "GET", "/finance/reports/q1_draft_CONFIDENTIAL.zip", 200, "priv_escalation", "detectable"),
    ("15/Mar/2026:11:48:01", "10.0.8.45", "david_m", "POST", "/intranet/forum/edit/1042", 302, "cleanup", "context"),
    ("15/Mar/2026:22:29:43", "10.0.8.45", "sarah_j", "POST", "/api/auth/login", 200, "account_takeover", "detectable"),
    ("15/Mar/2026:22:29:45", "10.0.8.45", "sarah_j", "GET", "/dashboard", 200, "account_takeover", "detectable"),
    ("15/Mar/2026:22:30:40", "10.0.8.45", "sarah_j", "GET", "/finance/reports/q1_draft_CONFIDENTIAL.zip", 200, "exfiltration", "detectable"),
    ("15/Mar/2026:22:33:40", "10.0.8.45", "sarah_j", "GET", "/logout", 302, "account_takeover", "detectable"),
]


def attach(df: pd.DataFrame) -> pd.DataFrame:
    """Add label/attack_type/incident/tier columns for the real incident (in place on a copy)."""
    df = df.copy()
    for col, default in [("label", 0), ("attack_type", ""), ("incident", ""), ("tier", "")]:
        if col not in df:
            df[col] = default
    ts_str = df["ts"].dt.strftime("%d/%b/%Y:%H:%M:%S")
    found = 0
    for ts, ip, user, method, path, status, stage, tier in INCIDENT:
        m = (ts_str == ts) & (df.ip == ip) & (df.user == user) & (df.method == method) & (df.path == path) & (df.status == status)
        if m.sum() == 0:
            continue
        assert m.sum() == 1, (ts, path)
        df.loc[m, ["label", "attack_type", "incident", "tier"]] = [1, "real_incident", "real", tier]
        df.loc[m, "stage"] = stage
        found += 1
    if found and found != len(INCIDENT):
        raise AssertionError(f"matched {found}/{len(INCIDENT)} incident rows")
    return df
