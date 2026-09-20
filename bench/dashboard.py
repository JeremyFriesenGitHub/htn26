"""Local log-review dashboard, with a dependency-free heuristic preview.

Run ``python3 -m bench.dashboard`` and open http://localhost:8765.
Trained scoring uses the existing bench.predict pipeline when its dependencies and
model artifacts are present. Uploaded logs remain in memory for the request only.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import html
import importlib
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "results" / "model_store"
STATIC = ROOT / "dashboard"
MAX_LINE_BYTES = 16384
MODEL_NAMES = {"rules": "Heuristic preview", "gmm": "Gaussian mixture", "ae": "Deep autoencoder",
               "hybrid": "GMM + LLM triage"}
HYBRID_TOPK = 60  # only the detector's shortlist is sent for review
MODEL_FILES = {"gmm": ("encoder.pkl", "gmm.pkl"),
               "ae": ("encoder.pkl", "ae_meta.pkl", "ae_models.pt")}
SCORING_LOCK = threading.Lock()
HYBRID_LOCK = threading.Lock()
MONTHS = {name: i for i, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
LINE_RX = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z][A-Z0-9_-]*) (?P<path>[^\s"]+) '
    r'(?P<proto>HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?))" '
    r'(?P<status>[1-5][0-9]{2}) (?P<bytes>[0-9]+|-)'
    r'(?: "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*")?$'
)
TIME_RX = re.compile(
    r'^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$'
)


class APIError(Exception):
    """A safe, user-facing validation or availability error."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class LogRecord:
    id: int
    timestamp: datetime
    ip: str
    ident: str
    user: str
    method: str
    path: str
    proto: str
    status: int
    bytes: int
    raw: str

    def public(self, score, reasons, tier=None):
        row = {"id": self.id, "timestamp": self.timestamp.isoformat(),
               "ip": self.ip, "user": self.user, "method": self.method,
               "path": self.path, "status": self.status, "bytes": self.bytes,
               "score": float(score), "reasons": reasons, "raw": self.raw}
        if tier:
            row["tier"] = tier
        return row


def report_progress(progress, stage, message, completed=None, total=None):
    if progress:
        event = {"type": "progress", "stage": stage, "message": message}
        if completed is not None:
            event.update(completed=completed, total=total)
        progress(event)


def parse_logs(logs, progress=None):
    """Strict CLF/combined parsing with original, one-based physical line IDs."""
    if not isinstance(logs, str):
        raise APIError("The logs field must be text.")
    try:
        logs.encode("utf-8")
    except UnicodeEncodeError:
        raise APIError("Logs must contain valid UTF-8 text.") from None
    lines = logs.split("\n")
    if lines and not lines[-1]:
        lines.pop()
    report_progress(progress, "parse", "Parsing Apache log lines", 0, len(lines))
    records = []
    for line_number, raw in enumerate(lines, 1):
        if line_number > 1 and (line_number - 1) % 1000 == 0:
            report_progress(progress, "parse", "Parsing Apache log lines", line_number - 1, len(lines))
        raw = raw.removesuffix("\r")
        if not raw.strip(" \t"):
            continue
        if len(raw.encode("utf-8")) > MAX_LINE_BYTES:
            raise APIError("Line %d exceeds the 16 KiB per-line limit." % line_number, 413)
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
            raise APIError("Line %d contains a control character." % line_number)
        match = LINE_RX.fullmatch(raw)
        if not match:
            raise APIError("Line %d: expected Apache Common or Combined Log Format "
                           '(IP - user [time] "METHOD /path HTTP/1.1" status bytes).' % line_number)
        values = match.groupdict()
        # Some exports pad IPv4 octets or HTML-encode whitespace after the IP.
        # Clean only that field, preserving its decimal spelling for the trained
        # encoder's exact-string history and preserving the complete raw line.
        if "&" in values["ip"]:
            values["ip"] = html.unescape(values["ip"]).rstrip()
        validation_ip = values["ip"]
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", validation_ip):
            validation_ip = ".".join(part.lstrip("0") or "0" for part in validation_ip.split("."))
        try:
            ipaddress.ip_address(validation_ip)
        except ValueError:
            raise APIError("Line %d: invalid IP address." % line_number) from None
        tm = TIME_RX.fullmatch(values["ts"])
        try:
            if not tm:
                raise ValueError
            day, month, year, hour, minute, second, sign, tz_hour, tz_minute = tm.groups()
            if int(tz_hour) > 23 or int(tz_minute) > 59:
                raise ValueError
            offset = timedelta(hours=int(tz_hour), minutes=int(tz_minute))
            if sign == "-":
                offset = -offset
            timestamp = datetime(int(year), MONTHS[month], int(day), int(hour),
                                 int(minute), int(second), tzinfo=timezone(offset))
        except (KeyError, ValueError, OverflowError):
            raise APIError("Line %d: invalid timestamp; use DD/Mon/YYYY:HH:MM:SS +0000." % line_number) from None
        if not (values["path"].startswith(("/", "http://", "https://")) or values["path"] == "*"):
            raise APIError("Line %d: request path must start with / or be an HTTP URL." % line_number)
        if values["path"].startswith(("http://", "https://")):
            try:
                target = urlsplit(values["path"])
                if not target.hostname or target.username or target.password:
                    raise ValueError
                _ = target.port
            except ValueError:
                raise APIError("Line %d: invalid absolute request URL." % line_number) from None
        # Bound before int conversion, including on Python versions without its
        # integer-string limit. JavaScript cannot exactly represent larger sizes.
        byte_text = values["bytes"].lstrip("0") or "0"
        if len(byte_text) > 16 or (byte_text != "-" and int(byte_text) > 2**53 - 1):
            raise APIError("Line %d: response size is too large." % line_number)
        response_bytes = 0 if byte_text == "-" else int(byte_text)
        records.append(LogRecord(line_number, timestamp, values["ip"], values["ident"],
                                 values["user"], values["method"], values["path"],
                                 values["proto"], int(values["status"]), response_bytes, raw))
    if not records:
        raise APIError("Add at least one Apache log line before running analysis.")
    report_progress(progress, "parse", "Log lines parsed", len(lines), len(lines))
    return records


def _hybrid_status():
    """The hybrid needs the GMM artifacts, the openai client, and a key.

    It is the only model that sends data off this machine, so say so plainly.
    """
    import os
    detail = ("Ranks every line with the GMM, then sends only the top %d to an LLM for review "
              "with each user's normal-access profile. SENDS THOSE LINES TO OPENAI." % HYBRID_TOPK)
    missing = [name for name in MODEL_FILES["gmm"] if not (STORE / name).is_file()]
    if missing:
        return {"id": "hybrid", "name": MODEL_NAMES["hybrid"], "available": False,
                "detail": "Missing model artifacts: %s. Run python -m bench.train." % ", ".join(missing)}
    for dependency in ("numpy", "pandas", "sklearn", "scipy", "openai"):
        try:
            importlib.import_module(dependency)
        except Exception:
            return {"id": "hybrid", "name": MODEL_NAMES["hybrid"], "available": False,
                    "detail": "The %s package is required for LLM triage." % dependency}
    if not (os.environ.get("OPENAI_API_KEY") or "").strip():
        return {"id": "hybrid", "name": MODEL_NAMES["hybrid"], "available": False,
                "detail": "Set OPENAI_API_KEY before starting the dashboard to enable LLM triage."}
    return {"id": "hybrid", "name": MODEL_NAMES["hybrid"], "available": True,
            "detail": detail, "external": True}


def model_status():
    result = [{"id": "rules", "name": MODEL_NAMES["rules"], "available": True,
               "detail": "Local, deterministic request rules; no trained model or learned user baseline."}]
    result.append(_hybrid_status())
    for model, artifacts in MODEL_FILES.items():
        missing = [name for name in artifacts if not (STORE / name).is_file()]
        available = not missing
        detail = "Uses the saved model; scores are calibrated against the training baseline."
        if missing:
            detail = "Missing model artifacts: %s. Run python -m bench.train in your ML environment." % ", ".join(missing)
        else:
            dependencies = ["numpy", "pandas", "sklearn", "scipy"]
            if model == "ae":
                dependencies.append("torch")
            for dependency in dependencies:
                try:
                    importlib.import_module(dependency)
                except Exception:
                    available = False
                    detail = "The %s dependency is missing or could not load in this Python environment." % dependency
                    break
        result.append({"id": model, "name": MODEL_NAMES[model], "available": available, "detail": detail})
    return {"models": result, "max_bytes": None, "max_lines": None}


def score_rules(records, progress=None):
    """Weighted indicators, with strictly prior same-actor login failures.

    The preview has no training state. Every request starts at 0.04, receives
    the weights below, and is capped at 0.99. These scores are not probabilities.
    Equal-time requests do not count as prior history for each other.
    """
    failures = defaultdict(deque)
    pending = []
    previous_time = None
    rows = []
    report_progress(progress, "model", "Ordering requests by time")
    ordered = sorted(records, key=lambda row: (row.timestamp, row.id))
    report_progress(progress, "model", "Applying heuristic rules", 0, len(ordered))
    for position, record in enumerate(ordered, 1):
        if previous_time != record.timestamp:
            for actor, timestamp in pending:
                failures[actor].append(timestamp)
            pending = []
            previous_time = record.timestamp
        actor = (record.ip, record.user)
        recent = failures[actor]
        while recent and (record.timestamp - recent[0]).total_seconds() > 60:
            recent.popleft()
        score, reasons = 0.04, []
        path = unquote(unquote(record.path)).lower()
        # Split the original target first: encoded delimiters are request data,
        # not URL structure. Decoding an authority before urlsplit can even turn
        # an accepted target into an invalid IPv6 URL and abort a whole upload.
        raw_route = (urlsplit(record.path).path if record.path.startswith(("http://", "https://"))
                     else record.path.split("?", 1)[0])
        route = unquote(unquote(raw_route)).lower()
        login = bool(re.search(r"(?:^|/)(?:login|signin|sign-in|authenticate)(?:/|$)", route))
        failed_login = login and record.status in (401, 403)
        if record.status == 401:
            score += 0.18
            reasons.append("authentication-required")
        elif record.status == 403:
            score += 0.16
            reasons.append("access-denied")
        elif record.status >= 500:
            score += 0.12
            reasons.append("server-error")
        if failed_login:
            score += 0.10
            reasons.append("failed-login")
            pending.append((actor, record.timestamp))
        if len(recent) >= 3:
            score += 0.48 + min(0.12, (len(recent) - 3) * 0.04)
            reasons.append("%d-prior-failed-logins-in-60s" % len(recent))
            if login and 200 <= record.status < 300:
                score += 0.24
                reasons.append("login-success-after-failures")
        suspicious = ("../", "<script", "javascript:", "union select", "' or ",
                      '" or ', "/etc/passwd", "cmd=", "csrf_", "csrf=", "script=")
        if any(marker in path.replace("+", " ") for marker in suspicious):
            score += 0.66
            reasons.append("suspicious-request-content")
        admin = bool(re.search(r"(?:^|/)(?:admin|role_update|permissions)(?:/|$)", route))
        if admin and record.method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 0.56
            reasons.append("administrative-write")
        if 200 <= record.status < 300 and record.bytes >= 5 * 1024 * 1024:
            score += 0.40
            reasons.append("large-successful-response")
            if any(marker in route for marker in ("confidential", "/export", "/backup", ".zip", ".sql")):
                score += 0.22
                reasons.append("bulk-or-sensitive-download")
        if record.timestamp.hour < 7 or record.timestamp.hour >= 20:
            score += 0.08
            reasons.append("outside-07-to-20-hours")
        rows.append(record.public(round(min(0.99, score), 4), reasons))
        if position % 1000 == 0 or position == len(ordered):
            report_progress(progress, "model", "Applying heuristic rules", position, len(ordered))
    return sorted(rows, key=lambda row: (-row["score"], row["id"]))


CALIBRATION_LOCK = threading.Lock()
_CALIBRATION = {}


def _calibration_identity(model):
    """Invalidate baseline scores if the encoder or detector is replaced."""
    return [[name, (STORE / name).stat().st_size, (STORE / name).stat().st_mtime_ns]
            for name in MODEL_FILES[model] if (STORE / name).is_file()]


def _validated_grid(loaded):
    if not isinstance(loaded, dict):
        return None
    try:
        values = [float(v) for v in loaded["values"]]
        levels = [float(v) for v in loaded["levels"]]
        if not values or len(values) != len(levels):
            return None
        if any(not math.isfinite(v) for v in values + levels):
            return None
        if any(a > b for a, b in zip(values, values[1:])) or any(a > b for a, b in zip(levels, levels[1:])):
            return None
        if levels[0] < 0 or levels[-1] > 1:
            return None
        grid = {"values": values, "levels": levels, "kind": "quantile"}
        if loaded.get("kind") == "empirical":
            upper = [float(v) for v in loaded["upper"]]
            if (len(upper) != len(values) or any(not math.isfinite(v) for v in upper)
                    or any(a >= b for a, b in zip(values, values[1:]))
                    or any(a > b for a, b in zip(upper, upper[1:]))
                    or any(not 0 <= mid <= hi <= 1 for mid, hi in zip(levels, upper))):
                return None
            grid.update(kind="empirical", upper=upper, sample_size=int(loaded["sample_size"]))
        return grid
    except (KeyError, ValueError, TypeError, OverflowError):
        return None


def calibration(model, progress=None):
    """Training-score distribution, never an attack probability or target count."""
    identity = _calibration_identity(model)
    key = (str(STORE), model, repr(identity))
    if key in _CALIBRATION:
        return _CALIBRATION[key]
    report_progress(progress, "calibration", "Loading the training-score baseline")
    with CALIBRATION_LOCK:
        if key in _CALIBRATION:
            return _CALIBRATION[key]
        cache = STORE / ("calibration3_%s.json" % model)
        grid = None
        if cache.is_file():
            try:
                loaded = json.loads(cache.read_text())
                if isinstance(loaded, dict) and loaded.get("artifacts") == identity:
                    grid = _validated_grid(loaded)
            except (OSError, ValueError, TypeError):
                grid = None
        if grid is None:
            grid = _build_calibration(model, progress=progress)
            if grid is not None:
                try:
                    cache.write_text(json.dumps({**grid, "artifacts": identity}))
                except OSError:
                    pass
        if grid is not None:
            _CALIBRATION[key] = grid
        return grid


def _build_calibration(model, progress=None):
    """Keep the empirical score distribution, including the mass of ties."""
    try:
        import numpy as np
        from . import data as data_module, predict
        report_progress(progress, "calibration", "Reading the training window for baseline calibration")
        frame = data_module.load()
        frame = frame[frame.ts < data_module.VAL_END]
        if not len(frame):
            return None
        def baseline_progress(event):
            report_progress(progress, "calibration", "Baseline: " + event["message"],
                            event.get("completed"), event.get("total"))
        with SCORING_LOCK:
            scored = predict.score_frame(frame.sort_values("ts").reset_index(drop=True),
                                         model=model, progress=baseline_progress if progress else None)
        if "score_raw" not in scored:
            return None
        raw = np.asarray(scored["score_raw"], dtype=float)
        raw = raw[np.isfinite(raw)]
        if not raw.size:
            return None
        values, counts = np.unique(raw, return_counts=True)
        cumulative = np.cumsum(counts)
        return {"kind": "empirical", "sample_size": int(raw.size),
                "values": values.tolist(),
                "levels": ((cumulative - counts / 2) / raw.size).tolist(),
                "upper": (cumulative / raw.size).tolist()}
    except Exception:
        return None  # calibration is an enhancement; scoring still works without it


def calibrated_score(grid, raw):
    """Baseline percentile: P(score < raw) + half the probability mass at ties.

    Legacy quantile grids are interpolated rather than rounded up to the next
    quantile. Values beyond the observed maximum have percentile 1; that limit
    says nothing about the distance beyond it, which the raw score preserves.
    """
    values, levels = grid["values"], grid["levels"]
    left, right = bisect_left(values, raw), bisect_right(values, raw)
    if left != right:
        return (levels[left] + levels[right - 1]) / 2
    if left == 0:
        return 0.0
    if left == len(values):
        return 1.0
    if grid.get("kind") == "empirical":
        return grid["upper"][left - 1]
    fraction = (raw - values[left - 1]) / (values[left] - values[left - 1])
    return levels[left - 1] + fraction * (levels[left] - levels[left - 1])


def score_trained(records, model, progress=None):
    # Imports stay inside this path so the preview starts without ML packages.
    import pandas as pd
    from . import data, predict

    report_progress(progress, "features", "Preparing requests for the trained encoder")
    frame = pd.DataFrame([{"ip": r.ip, "ident": r.ident, "user": r.user,
                           "ts": r.timestamp, "method": r.method, "path": r.path,
                           "proto": r.proto, "status": r.status, "bytes": r.bytes,
                           "tmpl": data.template(r.path),
                           "key": r.method + " " + data.template(r.path),
                           "src_line": r.id, "raw": r.raw} for r in records])
    # Give the encoder one timezone, preserving the first request's clock for
    # off-hours features and correctly ordering mixed-offset submissions.
    frame["ts"] = pd.to_datetime(frame["ts"], utc=True).dt.tz_convert(records[0].timestamp.tzinfo)
    with SCORING_LOCK:
        scored = predict.score_frame(frame, model=model, **({"progress": progress} if progress else {}))
    columns = getattr(scored, "columns", ())
    grid = calibration(model, progress=progress) if "score_raw" in columns else None
    originals = {r.id: r for r in records}
    result = []
    seen = set()
    report_progress(progress, "results", "Preparing scored requests", 0, len(records))
    for position, (_, row) in enumerate(scored.iterrows(), 1):
        source_id, score = int(row["src_line"]), float(row["score"])
        if source_id not in originals or source_id in seen or not math.isfinite(score) or not 0 <= score <= 1:
            raise APIError("The saved model returned invalid results. Check or regenerate the model store.", 503)
        seen.add(source_id)
        raw = float(row["score_raw"]) if "score_raw" in columns else None
        if raw is not None and not math.isfinite(raw):
            raise APIError("The saved model returned invalid results. Check or regenerate the model store.", 503)
        baseline = calibrated_score(grid, raw) if grid is not None and raw is not None else None
        tags = str(row["reasons"])
        reasons = [tag for tag in tags.split(",") if tag and tag != "-"]
        public = originals[source_id].public(baseline if baseline is not None else score, reasons)
        public.update(raw_score=raw, batch_percentile=score, baseline_percentile=baseline,
                      above_baseline=raw > grid["values"][-1] if grid is not None and raw is not None else None)
        result.append(public)
        if position % 1000 == 0 or position == len(records):
            report_progress(progress, "results", "Preparing scored requests", position, len(records))
    if len(result) != len(records):
        raise APIError("The saved model returned incomplete results. Check or regenerate the model store.", 503)
    result.sort(key=lambda row: (-(row["raw_score"] if row["raw_score"] is not None else row["score"]), row["id"]))
    return result


_PROFILES = {}


def user_profiles():
    """What normal access looks like per user, learned from the training window."""
    if "p" in _PROFILES:
        return _PROFILES["p"]
    with CALIBRATION_LOCK:
        if "p" in _PROFILES:
            return _PROFILES["p"]
        cache = STORE / "profiles.json"
        profiles = None
        if cache.is_file():
            try:
                loaded = json.loads(cache.read_text())
                if isinstance(loaded, dict) and loaded:
                    profiles = loaded
            except (OSError, ValueError):
                profiles = None
        if profiles is None:
            try:
                from . import data as data_module, hybrid
                frame = data_module.load()
                profiles = hybrid.build_profiles(frame[frame.ts < data_module.VAL_END])
                try:
                    cache.write_text(json.dumps(profiles))
                except OSError:
                    pass
            except Exception:
                profiles = {}
        _PROFILES["p"] = profiles
        return profiles


def _call_llm(prompt):
    """Keep the provider's module-level configuration scoped to this call."""
    from . import hybrid
    from . import llm_baseline as provider_module
    with HYBRID_LOCK:
        names = ("SYSTEM", "SCHEMA", "MAX_OUT", "REASONING_EFFORT")
        saved = {name: getattr(provider_module, name) for name in names}
        try:
            provider_module.SYSTEM, provider_module.SCHEMA = hybrid.SYSTEM, hybrid.SCHEMA
            provider_module.MAX_OUT, provider_module.REASONING_EFFORT = 16000, "low"
            provider = provider_module.OpenAIProvider("gpt-5")
            parsed, _, _ = provider.classify(prompt)
            return parsed
        finally:
            for name, value in saved.items():
                setattr(provider_module, name, value)


def score_hybrid(records, progress=None):
    """Add LLM verdicts to a detector shortlist without changing detector scores."""
    rows = score_trained(records, "gmm", progress=progress)
    shortlist = rows[:min(HYBRID_TOPK, len(rows))]
    report_progress(progress, "llm", "Loading user access profiles for the shortlist")
    profiles = user_profiles()
    lines = []
    for position, row in enumerate(shortlist, 1):
        profile = profiles.get(row["user"], {})
        lines.append(
            "ALERT %d:\n    line: %s\n    user profile: usual_ips=%s, normally_accesses=%s, "
            "normally_denied=%s\n    raw detector score: %s  signals: %s" % (
                position, row["raw"], profile.get("usual_ips"),
                profile.get("normally_accesses"), profile.get("normally_denied"),
                row.get("raw_score"), ", ".join(row["reasons"]) or "none"))
    prompt = ("Triage these detector alerts. Use each alert's profile: authorised access to "
              "sensitive files IS normal when it matches the user's profile. Missing profiles "
              "are unknown; do not assume that their absence implies unauthorized access.\n\n"
              + "\n\n".join(lines) + "\n\nReturn a verdict for every alert id as JSON.")
    report_progress(progress, "llm", "OpenAI is reviewing %d shortlisted requests" % len(shortlist))
    parsed = _call_llm(prompt)
    candidates = parsed.get("verdicts", []) if isinstance(parsed, dict) else []
    if not isinstance(candidates, list):
        candidates = []
    verdicts, duplicates = {}, set()
    for verdict in candidates:
        if not isinstance(verdict, dict):
            continue
        position = verdict.get("id")
        if type(position) is not int or not 1 <= position <= len(shortlist):
            continue
        if position in verdicts:
            duplicates.add(position)
        if (type(verdict.get("is_incident")) is not bool
                or not isinstance(verdict.get("reason"), str)):
            continue
        verdicts[position] = verdict
    for position in duplicates:
        verdicts.pop(position, None)
    if not verdicts:
        raise APIError("The LLM returned no valid, unambiguous verdicts for this upload.", 503)
    for row in rows:
        row.update(triage="unreviewed", triage_reason=None)
    flagged = cleared = 0
    for position, row in enumerate(shortlist, 1):
        verdict = verdicts.get(position)
        if verdict is None:
            continue
        row["triage"] = "flagged" if verdict["is_incident"] else "cleared"
        row["triage_reason"] = verdict["reason"].strip()
        flagged += int(verdict["is_incident"])
        cleared += int(not verdict["is_incident"])
    reviewed = flagged + cleared
    report_progress(progress, "llm", "Received %d valid verdicts for %d submitted requests" % (reviewed, len(shortlist)),
                    reviewed, len(shortlist))
    return rows, {"submitted": len(shortlist), "reviewed": reviewed, "flagged": flagged,
                  "cleared": cleared, "unreviewed": len(rows) - reviewed,
                  "missing_verdicts": len(shortlist) - reviewed}


_KNOWN = {}


def known_actors():
    """Users and IPs present in the training window, for an out-of-domain check."""
    if "k" in _KNOWN:
        return _KNOWN["k"]
    with CALIBRATION_LOCK:
        if "k" in _KNOWN:
            return _KNOWN["k"]
        users, ips = set(), set()
        try:
            from . import predict
            encoder = predict.load_encoder()
            for user, ip in getattr(encoder, "seen_user_ip", ()):
                users.add(user); ips.add(ip)
        except Exception:
            pass
        _KNOWN["k"] = (users, ips)
        return _KNOWN["k"]


def domain_note(records, flagged_share):
    """Warn when the upload does not look like the traffic the model learned.

    These models learn one organisation's habits. Point them at another system's
    logs and every line is legitimately novel, so everything scores high - which
    is useless rather than wrong. Say so instead of presenting 100% as a result.
    """
    users, ips = known_actors()
    if not users:
        return None
    unknown = sum(1 for r in records if r.user not in users and r.ip not in ips)
    share = unknown / len(records)
    if share >= 0.5:
        return ("%.0f%% of these requests come from users or addresses the model has never "
                "seen, so almost everything looks novel to it. These trained models only "
                "apply to the system they were trained on - use Heuristic preview for "
                "unfamiliar logs." % (share * 100))
    if flagged_share >= 0.2:
        return ("%.0f%% of this upload exceeds the default review cutoff. A high detector score "
                "does not establish an incident; inspect the requests and their context." % (flagged_share * 100))
    return None


def predict_payload(payload, progress=None):
    start = time.perf_counter()
    if not isinstance(payload, dict):
        raise APIError("Send a JSON object with logs and model fields.")
    model = payload.get("model", "rules")
    if not isinstance(model, str) or model not in MODEL_NAMES:
        raise APIError("Choose rules, gmm, ae, or hybrid as the model.")
    records = parse_logs(payload.get("logs"), progress=progress)
    warning = None
    triage = None
    if model == "rules":
        rows = score_rules(records, progress=progress)
        kind = "heuristic"
        threshold = 0.75
        notice = ("Heuristic preview uses fixed request rules and earlier same-IP/user login failures "
                  "in this upload. It has no learned user baseline. Scores are review indicators, "
                  "not attack probabilities; legitimate activity can trigger them.")
    else:
        report_progress(progress, "model", "Checking saved model availability")
        status = next(item for item in model_status()["models"] if item["id"] == model)
        if not status["available"]:
            raise APIError(status["detail"], 503)
        try:
            if model == "hybrid":
                rows, triage = score_hybrid(records, progress=progress)
            else:
                rows = score_trained(records, model, progress=progress)
        except APIError:
            raise
        except (BrokenPipeError, ConnectionResetError):
            raise
        except Exception:
            message = ("LLM triage could not complete. Check OPENAI_API_KEY and connectivity." if model == "hybrid"
                       else "The saved model could not score this upload. Check that its artifacts match the "
                            "installed dependencies, or regenerate them with python -m bench.train.")
            raise APIError(message, 503) from None
        calibrated = bool(rows) and rows[0].get("baseline_percentile") is not None
        kind = "calibrated" if calibrated else "percentile"
        threshold = 0.999 if calibrated else 0.98
        warning = domain_note(records, sum(row["score"] >= threshold for row in rows) / len(rows))
        if calibrated:
            notice = ("Raw detector scores rank requests. Baseline percentiles compare those scores with "
                      "the saved model's training-score distribution, using midpoint ranks for ties. "
                      "Scores above the observed baseline maximum share a percentile of 1; their raw "
                      "scores still distinguish them. These are not attack probabilities.")
        else:
            notice = ("Raw detector scores rank requests. The training-score baseline is unavailable, "
                      "so percentiles describe only this uploaded batch, not attack probabilities.")
        if triage:
            notice += (" OpenAI reviewed %d of %d submitted requests and flagged %d. "
                       "%d requests remain unreviewed. Verdicts do not change detector scores. "
                       "Shortlisted log lines and user profiles were sent to OpenAI." %
                       (triage["reviewed"], triage["submitted"], triage["flagged"], triage["unreviewed"]))
    result = {"model": model, "model_name": MODEL_NAMES[model],
              "mode": "heuristic" if model == "rules" else "trained",
              "score_kind": "triaged" if triage else kind,
              "detector_score_kind": kind, "review_threshold": threshold,
              "review_threshold_note": "Default display cutoff; not a validated alarm boundary or target alert count.",
              "notice": notice, "elapsed_ms": round((time.perf_counter() - start) * 1000, 2), "rows": rows}
    if triage:
        result.update(triage=triage, external=True)
    if warning:
        result["warning"] = warning
    report_progress(progress, "results", "Analysis ready", len(rows), len(rows))
    return result


def sample_payload():
    """A deterministic synthetic week, unrelated to the benchmark dataset."""
    events = []
    start = datetime(2026, 9, 13, 8, tzinfo=timezone(timedelta(hours=-4)))
    users = ("alex_chen", "maya_patel", "noah_wilson", "sarah_j", "david_m", "emma_lee")
    routes = ("/dashboard", "/api/projects", "/intranet/forum/view/1042", "/assets/app.css",
              "/api/team", "/reports/weekly", "/api/notifications", "/profile")
    for day in range(7):
        for i in range(40):
            timestamp = start + timedelta(days=day, minutes=i * 16 + (i % 3))
            user = users[(i + day) % len(users)]
            ip = "10.0.%d.%d" % (2 + (i % 3), 10 + (i + day) % len(users))
            path = routes[(i * 3 + day) % len(routes)]
            status = 404 if i == 19 else 403 if i == 33 else 200
            method = "GET"
            if i == 8:
                method, path, status = "POST", "/api/auth/login", 401
            size = 384 + ((i * 1543 + day * 709) % 32000)
            events.append((timestamp, ip, user, method, path, status, size))
    attack = start + timedelta(days=5, hours=14, minutes=13)
    for i in range(7):
        events.append((attack + timedelta(seconds=i * 7), "198.51.100.42", "sarah_j",
                       "POST", "/api/auth/login", 401, 280))
    events.extend([
        (attack + timedelta(seconds=50), "198.51.100.42", "sarah_j", "POST", "/api/auth/login", 200, 540),
        (attack + timedelta(seconds=54), "198.51.100.42", "sarah_j", "POST", "/api/admin/role_update", 200, 680),
        (attack + timedelta(seconds=57), "198.51.100.42", "sarah_j", "GET", "/finance/export_CONFIDENTIAL.zip", 200, 18574320),
        (start + timedelta(days=3, hours=4), "203.0.113.18", "-", "GET", "/api/search?q=1%27+OR+%271%27=%271", 400, 180),
        (start + timedelta(days=3, hours=4, minutes=2), "203.0.113.18", "-", "GET", "/files?name=../../etc/passwd", 403, 240),
        (start + timedelta(days=4, hours=5), "10.0.3.12", "maya_patel", "POST", "/api/admin/permissions", 200, 870),
        (start + timedelta(days=6, hours=1), "10.0.2.10", "alex_chen", "GET", "/reports/weekly.zip", 200, 7340032),
    ])
    lines = []
    months = tuple(MONTHS)
    for timestamp, ip, user, method, path, status, size in sorted(events):
        date = "%02d/%s/%04d:%02d:%02d:%02d -0400" % (
            timestamp.day, months[timestamp.month - 1], timestamp.year,
            timestamp.hour, timestamp.minute, timestamp.second)
        lines.append('%s - %s [%s] "%s %s HTTP/1.1" %d %d' % (ip, user, date, method, path, status, size))
    return {"name": "Synthetic sample · September 13–19, 2026", "logs": "\n".join(lines) + "\n"}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "LogDashboard/1.0"
    sys_version = ""
    timeout = 20
    static_routes = {"/": ("index.html", "text/html; charset=utf-8"),
                     "/index.html": ("index.html", "text/html; charset=utf-8"),
                     "/style.css": ("style.css", "text/css; charset=utf-8"),
                     "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                     "/review.js": ("review.js", "application/javascript; charset=utf-8"),
                     "/charts.js": ("charts.js", "application/javascript; charset=utf-8"),
                     "/investigation.js": ("investigation.js", "application/javascript; charset=utf-8"),
                     "/model-lens.js": ("model-lens.js", "application/javascript; charset=utf-8")}

    def log_message(self, format, *args):
        # Uploaded content and user-controlled request targets are never logged.
        pass

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler otherwise renders HTML, potentially echoing a
        # malformed request target. Keep protocol errors in the API's JSON shape.
        self.close_connection = True
        self._send(code, {"error": self.responses.get(code, ("Request rejected",))[0]})

    def _send(self, status, body, content_type="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _request_path(self):
        if not self.path.startswith("/") or self.path.startswith("//"):
            raise APIError("Use a path on this dashboard server.", 400)
        try:
            return urlsplit(self.path).path
        except ValueError:
            raise APIError("Invalid request path.", 400) from None

    def _validate_host(self):
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            raise APIError("A single valid Host header is required.", 403)
        try:
            host = urlsplit("//" + hosts[0])
            if host.username or host.password or host.path or host.query or host.fragment:
                raise ValueError
            if not host.hostname or (host.port or 80) != self.server.server_port:
                raise ValueError
            allowed = {"localhost", "127.0.0.1", "::1", self.server.server_address[0].lower()}
            if host.hostname.lower() not in allowed:
                # Explicit --host 0.0.0.0/:: binding may serve other numeric local
                # interfaces, but never an arbitrary DNS hostname.
                if self.server.server_address[0] not in ("0.0.0.0", "::"):
                    raise ValueError
                ipaddress.ip_address(host.hostname)
        except (ValueError, AttributeError):
            raise APIError("This Host is not allowed by the local dashboard.", 403) from None
        return host

    def _validate_post_origin(self, host):
        if self.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
            raise APIError("Cross-site requests are not allowed.", 403)
        origins = self.headers.get_all("Origin", [])
        if len(origins) > 1:
            raise APIError("A single Origin header is required.", 403)
        if origins:
            try:
                origin = urlsplit(origins[0])
                if (origin.scheme != "http" or origin.hostname != host.hostname or
                        (origin.port or 80) != (host.port or 80) or origin.username or
                        origin.password or origin.path or origin.query or origin.fragment):
                    raise ValueError
            except ValueError:
                raise APIError("Only requests from this dashboard origin are allowed.", 403) from None

    def do_GET(self):
        try:
            self._validate_host()
            path = self._request_path()
            if path == "/api/status":
                self._send(200, model_status())
            elif path == "/api/sample":
                self._send(200, sample_payload())
            elif path in self.static_routes:
                filename, mime = self.static_routes[path]
                try:
                    body = (STATIC / filename).read_bytes()
                except OSError:
                    raise APIError("Dashboard files are missing from this checkout.", 503) from None
                self._send(200, body, mime)
            else:
                raise APIError("Resource not found.", 404)
        except APIError as error:
            self._send(error.status, {"error": str(error)})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._send(500, {"error": "The dashboard could not complete this request."})

    def do_HEAD(self):
        self.do_GET()

    def _begin_stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self._streaming = True

    def _stream_event(self, event):
        encoded = json.dumps(event, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.wfile.write(encoded + b"\n")
        self.wfile.flush()

    def _post_error(self, status, message):
        if self._streaming:
            self._stream_event({"type": "error", "error": message, "status": status})
        else:
            self._send(status, {"error": message})

    def do_POST(self):
        self._streaming = False
        try:
            host = self._validate_host()
            self._validate_post_origin(host)
            if self._request_path() != "/api/predict":
                raise APIError("Resource not found.", 404)
            if self.headers.get("Transfer-Encoding"):
                raise APIError("Transfer-Encoding is not supported; send Content-Length.", 400)
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
                raise APIError("A valid Content-Length header is required.", 411)
            # No application-level upload cap. Reject only lengths that cannot
            # be represented by this runtime's read() API.
            length_text = lengths[0].lstrip("0") or "0"
            if len(length_text) > len(str(sys.maxsize)) or int(length_text) > sys.maxsize:
                raise APIError("Content-Length exceeds this runtime's integer range.", 400)
            length = int(length_text)
            if self.headers.get_content_type() != "application/json":
                raise APIError("Send the request as application/json.", 415)
            wants_stream = any(part.split(";", 1)[0].strip().lower() == "application/x-ndjson"
                               for part in self.headers.get("Accept", "").split(","))
            progress = None
            if wants_stream:
                self._begin_stream()
                progress = self._stream_event
            try:
                report_progress(progress, "upload", "Receiving the log upload", 0, length)
                chunks, received = [], 0
                while received < length:
                    chunk = self.rfile.read(min(256 * 1024, length - received))
                    if not chunk:
                        raise APIError("The request body is incomplete.")
                    chunks.append(chunk)
                    received += len(chunk)
                    report_progress(progress, "upload", "Receiving the log upload", received, length)
                raw = b"".join(chunks)
                report_progress(progress, "parse", "Decoding the request body")
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                raise APIError("The request body must be valid UTF-8 JSON.") from None
            result = predict_payload(payload, progress=progress)
            if self._streaming:
                self._stream_event({"type": "result", "result": result})
            else:
                self._send(200, result)
        except APIError as error:
            self._post_error(error.status, str(error))
        except (TimeoutError, socket.timeout):
            self._post_error(408, "The upload timed out. Check the connection and try again.")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._post_error(500, "Analysis could not complete. Check the input and try again.")
        finally:
            self.close_connection = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port (default: 8765)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    server_class = ThreadingHTTPServer
    if ":" in args.host:
        class IPv6Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        server_class = IPv6Server
    try:
        server = server_class((args.host, args.port), DashboardHandler)
    except OSError:
        parser.exit(1, "Could not start the dashboard; check the host and choose an unused port.\n")
    display_host = "[%s]" % args.host if ":" in args.host else args.host
    print("Log dashboard: http://%s:%d (Ctrl+C to stop)" % (display_host, args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
