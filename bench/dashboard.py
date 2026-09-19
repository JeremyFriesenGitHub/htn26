"""Local log-review dashboard, with a dependency-free heuristic preview.

Run ``python3 -m bench.dashboard`` and open http://localhost:8765.
Trained scoring uses the existing bench.predict pipeline when its dependencies and
model artifacts are present. Uploaded logs remain in memory for the request only.
"""
from __future__ import annotations

import argparse
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
MODEL_NAMES = {"rules": "Heuristic preview", "gmm": "Gaussian mixture", "ae": "Deep autoencoder"}
MODEL_FILES = {"gmm": ("encoder.pkl", "gmm.pkl"),
               "ae": ("encoder.pkl", "ae_meta.pkl", "ae_models.pt")}
SCORING_LOCK = threading.Lock()
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

    def public(self, score, reasons):
        return {"id": self.id, "timestamp": self.timestamp.isoformat(),
                "ip": self.ip, "user": self.user, "method": self.method,
                "path": self.path, "status": self.status, "bytes": self.bytes,
                "score": float(score), "reasons": reasons, "raw": self.raw}


def parse_logs(logs):
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
    records = []
    for line_number, raw in enumerate(lines, 1):
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
    return records


def model_status():
    result = [{"id": "rules", "name": MODEL_NAMES["rules"], "available": True,
               "detail": "Local, deterministic request rules; no trained model or learned user baseline."}]
    for model, artifacts in MODEL_FILES.items():
        missing = [name for name in artifacts if not (STORE / name).is_file()]
        available = not missing
        detail = "Uses the saved model; scores are percentiles within this batch."
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


def score_rules(records):
    """Weighted indicators, with strictly prior same-actor login failures.

    The preview has no training state. Every request starts at 0.04, receives
    the weights below, and is capped at 0.99. These scores are not probabilities.
    Equal-time requests do not count as prior history for each other.
    """
    failures = defaultdict(deque)
    pending = []
    previous_time = None
    rows = []
    for record in sorted(records, key=lambda row: (row.timestamp, row.id)):
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
    return sorted(rows, key=lambda row: (-row["score"], row["id"]))


def score_trained(records, model):
    # Imports stay inside this path so the preview starts without ML packages.
    import pandas as pd
    from . import data, predict

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
        scored = predict.score_frame(frame, model=model)
    originals = {r.id: r for r in records}
    result = []
    seen = set()
    for _, row in scored.iterrows():
        source_id, score = int(row["src_line"]), float(row["score"])
        if source_id not in originals or source_id in seen or not math.isfinite(score) or not 0 <= score <= 1:
            raise APIError("The saved model returned invalid results. Check or regenerate the model store.", 503)
        seen.add(source_id)
        tags = str(row["reasons"])
        reasons = [tag for tag in tags.split(",") if tag and tag != "-"]
        result.append(originals[source_id].public(score, reasons))
    if len(result) != len(records):
        raise APIError("The saved model returned incomplete results. Check or regenerate the model store.", 503)
    return sorted(result, key=lambda row: (-row["score"], row["id"]))


def predict_payload(payload):
    start = time.perf_counter()
    if not isinstance(payload, dict):
        raise APIError("Send a JSON object with logs and model fields.")
    model = payload.get("model", "rules")
    if not isinstance(model, str) or model not in MODEL_NAMES:
        raise APIError("Choose rules, gmm, or ae as the model.")
    records = parse_logs(payload.get("logs"))
    if model == "rules":
        rows = score_rules(records)
        notice = ("Heuristic preview uses fixed request rules and earlier same-IP/user login failures "
                  "in this upload. It has no learned user baseline. Scores are review indicators, "
                  "not attack probabilities; legitimate activity can trigger them.")
    else:
        status = next(item for item in model_status()["models"] if item["id"] == model)
        if not status["available"]:
            raise APIError(status["detail"], 503)
        try:
            rows = score_trained(records, model)
        except APIError:
            raise
        except Exception:
            raise APIError("The saved model could not score this upload. Check that its artifacts "
                           "match the installed dependencies, or regenerate them with python -m bench.train.", 503) from None
        notice = ("Trained model scores are percentiles within this uploaded batch, not attack "
                  "probabilities. A high percentile only identifies a request that ranks highly "
                  "in this batch; it does not confirm an attack.")
    return {"model": model, "model_name": MODEL_NAMES[model],
            "mode": "heuristic" if model == "rules" else "trained",
            "score_kind": "heuristic" if model == "rules" else "percentile",
            "notice": notice, "elapsed_ms": round((time.perf_counter() - start) * 1000, 2), "rows": rows}


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
                     "/app.js": ("app.js", "application/javascript; charset=utf-8")}

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

    def do_POST(self):
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
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise APIError("The request body is incomplete.")
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                raise APIError("The request body must be valid UTF-8 JSON.") from None
            self._send(200, predict_payload(payload))
        except APIError as error:
            self._send(error.status, {"error": str(error)})
        except (TimeoutError, socket.timeout):
            self._send(408, {"error": "The upload timed out. Try a smaller file."})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._send(500, {"error": "Analysis could not complete. Check the input and try again."})
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
