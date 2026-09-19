"""Parse Apache common-log lines and define the temporal splits."""
import re
from pathlib import Path

import pandas as pd

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "htn_challenge_logs_2026.txt"

LINE_RX = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d{3}) (?P<bytes>\S+)$'
)

# Fit on Aug-Jan, select on Feb, report on Mar (the month holding the real incident).
TRAIN_END = pd.Timestamp("2026-02-01", tz="-04:00")
VAL_END = pd.Timestamp("2026-03-01", tz="-04:00")


def template(path: str) -> str:
    """Collapse ids and query values so structurally identical requests share a key.

    /intranet/forum/view/1042           -> /intranet/forum/view/{n}
    /intranet/forum/new?topic=x&a=y     -> /intranet/forum/new?a=&topic=
    """
    base, _, query = path.partition("?")
    base = re.sub(r"\d{3,}", "{n}", base)
    if not query:
        return base
    keys = sorted(kv.split("=", 1)[0] for kv in query.split("&"))
    return base + "?" + "&".join(k + "=" for k in keys)


def parse_lines(lines) -> pd.DataFrame:
    recs = []
    for i, line in enumerate(lines):
        m = LINE_RX.match(line.rstrip("\n"))
        if not m:
            raise ValueError(f"unparseable line {i}: {line!r}")
        recs.append(m.groupdict())
    df = pd.DataFrame(recs)
    df["ts"] = pd.to_datetime(df["ts"], format="%d/%b/%Y:%H:%M:%S %z")
    df["status"] = df["status"].astype(int)
    df["bytes"] = pd.to_numeric(df["bytes"].replace("-", "0")).astype(int)
    df["tmpl"] = df["path"].map(template)
    df["key"] = df["method"] + " " + df["tmpl"]
    return df


def load() -> pd.DataFrame:
    with open(LOG_PATH) as f:
        raw = f.readlines()
    df = parse_lines(raw)
    df["raw"] = [l.rstrip("\n") for l in raw]
    df["src_line"] = range(1, len(df) + 1)
    return df


def to_line(r) -> str:
    """Render a row back into the exact common-log format."""
    ts = r["ts"].strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{r["ip"]} - {r["user"]} [{ts}] "{r["method"]} {r["path"]} HTTP/1.1" {r["status"]} {r["bytes"]}'


def split(df: pd.DataFrame):
    train = df[df.ts < TRAIN_END]
    val = df[(df.ts >= TRAIN_END) & (df.ts < VAL_END)]
    test = df[df.ts >= VAL_END]
    return train, val, test
