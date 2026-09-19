"""Run with python3 -m unittest discover -s tests -v; no ML packages required."""
from datetime import timedelta
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from bench import dashboard


def log(*, second=0, hour=12, user="alex", ip="192.0.2.10", status=200,
        path="/dashboard", method="GET", size="1024", timestamp=None):
    timestamp = timestamp or "19/Sep/2026:%02d:00:%02d -0400" % (hour, second)
    return '%s - %s [%s] "%s %s HTTP/1.1" %s %s' % (
        ip, user, timestamp, method, path, status, size)


class ParsingTests(unittest.TestCase):
    def test_common_combined_ipv6_and_blank_line_source_ids(self):
        common = log(size="-")
        combined = log(ip="2001:db8::1") + ' "https://example.org/" "Example \\"quoted\\" agent"'
        records = dashboard.parse_logs("\n" + common + "\r\n\n" + combined + "\n")
        self.assertEqual([r.id for r in records], [2, 4])
        self.assertEqual(records[0].bytes, 0)
        self.assertEqual(records[0].raw, common)
        self.assertEqual(records[1].ip, "2001:db8::1")
        self.assertEqual(records[0].timestamp.utcoffset(), timedelta(hours=-4))

    def test_errors_name_original_physical_line(self):
        with self.assertRaisesRegex(dashboard.APIError, "Line 3:"):
            dashboard.parse_logs(log() + "\n\ninvalid input")

    def test_zero_padded_ipv4_is_decimal_and_keeps_original_spelling(self):
        common = log(ip="10.0.9.05")
        combined = log(ip="010.000.009.008") + ' "-" "Example agent"'
        records = dashboard.parse_logs(common + "\n" + combined)
        self.assertEqual([record.ip for record in records], ["10.0.9.05", "010.000.009.008"])
        self.assertEqual([record.raw for record in records], [common, combined])

    def test_html_escaped_ip_token_does_not_change_path_or_raw_log(self):
        path = "/search?q=&lt;script&gt;&amp;page=1"
        common = log(ip="10.0.9.05&#x20;", path=path)
        combined = log(ip="10.0.9.05&nbsp;", path=path) + ' "-" "Example agent"'
        records = dashboard.parse_logs(common + "\n" + combined)
        self.assertEqual([record.ip for record in records], ["10.0.9.05", "10.0.9.05"])
        self.assertEqual([record.path for record in records], [path, path])
        self.assertEqual([record.raw for record in records], [common, combined])

    def test_padded_or_escaped_malformed_ips_still_fail(self):
        for ip in ("10.0.9.0256", "10.0.9.-05", "10.0.9.+05", "10.0.9.0x05",
                   "10.0.9.05.1", "10..9.05", "10.0.9.999&#x20;", "10.0.&#x20;9.05",
                   "10.0.9.05&amp;", "&#x20;10.0.9.05"):
            with self.subTest(ip=ip), self.assertRaisesRegex(dashboard.APIError, "invalid IP"):
                dashboard.parse_logs(log(ip=ip))

    def test_invalid_fields(self):
        bad_lines = [log(ip="999.1.1.1"), log(status=999), log(size="-8"),
                     log(timestamp="31/Feb/2026:10:00:00 +0000"),
                     log(timestamp="19/Sep/2026:10:00:00 +1260"),
                     log(timestamp="19/Sep/2026:10:00:00 +2400"),
                     log(size=str(2**53)), log(path="http://[invalid"),
                     log(path="https://example.org:invalid/"),
                     log(path="noslash"), log(path="/a\x00b")]
        for line in bad_lines:
            with self.subTest(line=line), self.assertRaises(dashboard.APIError):
                dashboard.parse_logs(line)

    def test_empty_nontext_and_surrogates_rejected(self):
        for value in (None, {}, [], 123, "", "\n \t\n", "\ud800"):
            with self.subTest(value=repr(value)), self.assertRaises(dashboard.APIError):
                dashboard.parse_logs(value)

    def test_per_line_sanity_and_trailing_newline(self):
        self.assertEqual(len(dashboard.parse_logs(log() + "\n" + log() + "\n")), 2)
        with mock.patch.object(dashboard, "MAX_LINE_BYTES", 20):
            with self.assertRaisesRegex(dashboard.APIError, "Line 1"):
                dashboard.parse_logs(log())


class RulesTests(unittest.TestCase):
    def analyze(self, lines):
        return {row["id"]: row for row in dashboard.score_rules(dashboard.parse_logs("\n".join(lines)))}

    def test_failure_history_uses_prior_time_not_file_order(self):
        lines = [log(second=40, method="POST", path="/api/auth/login"),
                 log(second=30, method="POST", path="/api/auth/login", status=401),
                 log(second=10, method="POST", path="/api/auth/login", status=401),
                 log(second=20, method="POST", path="/api/auth/login", status=401)]
        rows = self.analyze(lines)
        self.assertIn("3-prior-failed-logins-in-60s", rows[1]["reasons"])
        self.assertIn("login-success-after-failures", rows[1]["reasons"])
        self.assertFalse(any("prior-failed" in x for x in rows[2]["reasons"]))
        self.assertGreaterEqual(rows[1]["score"], 0.75)

    def test_actor_scope_and_window_do_not_leak(self):
        failures = [log(second=s, path="/login", status=401) for s in (0, 5, 10)]
        rows = self.analyze(failures + [log(second=20, path="/login", user="other"),
                                       log(second=20, path="/login", ip="192.0.2.11"),
                                       log(timestamp="19/Sep/2026:12:01:11 -0400", path="/login")])
        for number in (4, 5, 6):
            self.assertFalse(any("prior-failed" in x for x in rows[number]["reasons"]))

    def test_equal_timestamps_are_not_prior_history(self):
        lines = [log(second=0, path="/login", status=401) for _ in range(4)]
        lines.append(log(second=0, path="/login"))
        rows = self.analyze(lines)
        self.assertTrue(all(not any("prior-failed" in x for x in row["reasons"]) for row in rows.values()))

    def test_non_login_401_does_not_invent_failed_logins(self):
        rows = self.analyze([log(second=s, status=401) for s in (0, 5, 10)] + [log(second=20, path="/login")])
        self.assertNotIn("login-success-after-failures", rows[4]["reasons"])

    def test_weights_are_review_indicators_with_explanations(self):
        rows = self.analyze([log(), log(path="/download?file=%252e%252e%252fetc%252fpasswd", status=403),
                            log(method="POST", path="/api/admin/role_update"),
                            log(path="/exports/client_CONFIDENTIAL.zip", size=str(10 * 1024 * 1024))])
        self.assertEqual(rows[1]["reasons"], [])
        self.assertIn("suspicious-request-content", rows[2]["reasons"])
        self.assertIn("administrative-write", rows[3]["reasons"])
        self.assertIn("large-successful-response", rows[4]["reasons"])
        self.assertIn("bulk-or-sensitive-download", rows[4]["reasons"])
        self.assertGreater(rows[2]["score"], rows[1]["score"])
        self.assertTrue(all(0 <= row["score"] <= 1 for row in rows.values()))

    def test_encoded_url_delimiters_cannot_abort_a_valid_upload(self):
        # Accepted percent-encoded authority characters must not be reparsed as
        # URL syntax when scoring security logs. Keep the actual route intact.
        lines = [log(), log(method="POST", path="http://%5Bexample.org/api/admin/role_update"),
                 log(method="POST", path="/api%3Fv1/admin/permissions")]
        result = dashboard.predict_payload({"logs": "\n".join(lines), "model": "rules"})
        rows = {row["id"]: row for row in result["rows"]}
        self.assertEqual(len(rows), 3)
        self.assertIn("administrative-write", rows[2]["reasons"])
        self.assertIn("administrative-write", rows[3]["reasons"])
        self.assertEqual(rows[2]["raw"], lines[1])

    def test_sample_is_deterministic_varied_and_scores_sorted(self):
        sample = dashboard.sample_payload()
        self.assertEqual(sample, dashboard.sample_payload())
        result = dashboard.predict_payload({"logs": sample["logs"], "model": "rules"})
        rows = result["rows"]
        self.assertTrue(220 <= len(rows) <= 400)
        self.assertGreater(len({r["timestamp"][:10] for r in rows}), 3)
        self.assertEqual([r["score"] for r in rows], sorted([r["score"] for r in rows], reverse=True))
        self.assertTrue(any(r["score"] >= .75 for r in rows))
        self.assertTrue(any(r["score"] < .25 for r in rows))
        self.assertEqual(result["mode"], "heuristic")
        self.assertEqual(result["score_kind"], "heuristic")
        self.assertIn("no learned", result["notice"])


class ModelTests(unittest.TestCase):
    def test_missing_artifacts_do_not_import_ml_or_fall_back(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(dashboard, "STORE", Path(folder)), mock.patch.object(dashboard.importlib, "import_module") as importer:
                status = dashboard.model_status()
                # Only the dependency-free preview works without artifacts. Keyed by id so
                # adding a model does not break this on ordering.
                self.assertEqual({model["id"]: model["available"] for model in status["models"]},
                                 {"rules": True, "hybrid": False, "gmm": False, "ae": False})
                importer.assert_not_called()
                for model in ("gmm", "ae", "hybrid"):
                    with self.assertRaises(dashboard.APIError) as raised:
                        dashboard.predict_payload({"logs": log(), "model": model})
                    self.assertEqual(raised.exception.status, 503)

    def test_missing_dependency_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Path(folder)
            for name in ("encoder.pkl", "gmm.pkl"):
                (store / name).touch()
            with mock.patch.object(dashboard, "STORE", store), mock.patch.object(dashboard.importlib, "import_module", side_effect=ImportError("private path")):
                status = dashboard.model_status()["models"][1]
                self.assertFalse(status["available"])
                self.assertIn("numpy", status["detail"])
                self.assertNotIn("private path", status["detail"])

    def test_trained_failure_is_clear_and_does_not_leak_exception(self):
        status = {"models": [{"id": "gmm", "available": True}]}
        with mock.patch.object(dashboard, "model_status", return_value=status), mock.patch.object(dashboard, "score_trained", side_effect=RuntimeError("secret")):
            with self.assertRaises(dashboard.APIError) as raised:
                dashboard.predict_payload({"logs": log(), "model": "gmm"})
            self.assertEqual(raised.exception.status, 503)
            self.assertNotIn("secret", str(raised.exception))

    def test_invalid_payloads_are_rejected(self):
        for payload in ([], None, {"logs": log(), "model": []}, {"logs": log(), "model": "invented"}):
            with self.subTest(payload=payload), self.assertRaises(dashboard.APIError):
                dashboard.predict_payload(payload)

    def test_trained_adapter_preserves_physical_ids_and_raw_content(self):
        class Frame:
            def __init__(self, records):
                self.records = records

            def __getitem__(self, key):
                return [r[key] for r in self.records]

            def __setitem__(self, key, values):
                for record, value in zip(self.records, values):
                    record[key] = value

        def as_datetime(values, utc):
            self.assertTrue(utc)
            return SimpleNamespace(dt=SimpleNamespace(tz_convert=lambda _: values))

        def score(frame, model):
            self.assertEqual(model, "gmm")
            self.assertEqual(frame["src_line"], [2, 4])
            self.assertEqual(frame["ip"], ["10.0.9.05", "10.0.9.05"])
            return SimpleNamespace(iterrows=lambda: iter([
                (1, {"src_line": 4, "score": 1.0, "reasons": "rare-status,new-IP-for-user"}),
                (0, {"src_line": 2, "score": .5, "reasons": "-"})]))

        pandas = SimpleNamespace(DataFrame=Frame, to_datetime=as_datetime)
        data = SimpleNamespace(template=lambda path: path)
        predictor = SimpleNamespace(score_frame=score)
        import bench
        with mock.patch.dict(sys.modules, {"pandas": pandas, "bench.data": data, "bench.predict": predictor}), \
                mock.patch.object(bench, "data", data, create=True), \
                mock.patch.object(bench, "predict", predictor, create=True):
            source = "\n" + log(ip="10.0.9.05") + "\n\n" + log(ip="10.0.9.05&#x20;", path="/admin")
            records = dashboard.parse_logs(source)
            rows = dashboard.score_trained(records, "gmm")
        self.assertEqual([row["id"] for row in rows], [4, 2])
        self.assertEqual(rows[0]["raw"], log(ip="10.0.9.05&#x20;", path="/admin"))
        self.assertEqual(rows[0]["ip"], "10.0.9.05")
        self.assertEqual(rows[1]["reasons"], [])
        self.assertEqual(rows[0]["reasons"], ["rare-status", "new-IP-for-user"])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.DashboardHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path, method="GET", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_get_status_sample_and_static_allowlist(self):
        status, headers, body = self.request("/api/status")
        self.assertEqual(status, 200)
        details = json.loads(body)
        self.assertTrue(details["models"][0]["available"])
        self.assertIsNone(details["max_bytes"])
        self.assertIsNone(details["max_lines"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        status, _, body = self.request("/api/sample")
        self.assertEqual(status, 200)
        self.assertIn("Synthetic", json.loads(body)["name"])
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "index.html").write_text("<!doctype html><title>Dashboard</title>")
            with mock.patch.object(dashboard, "STATIC", Path(folder)):
                status, headers, body = self.request("/")
                self.assertEqual(status, 200)
                self.assertIn("text/html", headers["Content-Type"])
                self.assertIn(b"Dashboard", body)
        for path in ("/../README.md", "/%2e%2e/README.md", "/bench/dashboard.py", "/api/unknown"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_predict_round_trip(self):
        status, _, body = self.request("/api/predict", "POST", json.dumps({"logs": log(), "model": "rules"}),
                                       {"Content-Type": "application/json", "Origin": "http://127.0.0.1:%d" % self.port})
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result["rows"][0]["raw"], log())
        self.assertEqual(result["model"], "rules")

    def test_upload_over_previous_byte_and_line_limits(self):
        count = 25001
        logs = (log(path="/reports/quarterly/traffic/summary") + "\n") * count
        self.assertGreater(len(logs.encode("utf-8")), 2 * 1024 * 1024)
        self.assertGreater(count, 20000)
        status, _, body = self.request("/api/predict", "POST", json.dumps({"logs": logs, "model": "rules"}),
                                       {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        rows = json.loads(body)["rows"]
        self.assertEqual(len(rows), count)
        self.assertEqual(rows[-1]["id"], count)

    def test_rejected_json_content_type_and_invalid_logs(self):
        for body, headers, expected in (("{bad", {"Content-Type": "application/json"}, 400),
                                         ("[]", {"Content-Type": "application/json"}, 400),
                                         ("{}", {"Content-Type": "text/plain"}, 415),
                                         (json.dumps({"logs": "bad"}), {"Content-Type": "application/json"}, 400)):
            with self.subTest(body=body):
                status, _, response = self.request("/api/predict", "POST", body, headers)
                self.assertEqual(status, expected)
                self.assertIn("error", json.loads(response))

    def test_origin_and_host_protection(self):
        for headers in ({"Origin": "https://attacker.example"}, {"Origin": "null"},
                        {"Origin": "http://127.0.0.1:1"}, {"Sec-Fetch-Site": "cross-site"},
                        {"Host": "attacker.example:%d" % self.port}):
            with self.subTest(headers=headers):
                status, _, body = self.request("/api/predict", "POST", "{}", dict(headers, **{"Content-Type": "application/json"}))
                self.assertEqual(status, 403)
                self.assertIn("error", json.loads(body))
        self.assertEqual(self.request("/api/status", headers={"Host": "attacker.example:%d" % self.port})[0], 403)

    def test_missing_trained_model_returns_503(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(dashboard, "STORE", Path(folder)):
            status, _, body = self.request("/api/predict", "POST", json.dumps({"logs": log(), "model": "gmm"}),
                                           {"Content-Type": "application/json"})
        self.assertEqual(status, 503)
        self.assertIn("Missing model artifacts", json.loads(body)["error"])

    def test_content_length_bounds_and_duplicate_headers(self):
        for header, expected in (("Content-Length: nope", 411),
                                 ("Content-Length: %d" % (sys.maxsize + 1), 400),
                                 ("Content-Length: 2\r\nContent-Length: 2", 411),
                                 ("Transfer-Encoding: chunked", 400), ("", 411)):
            with self.subTest(header=header):
                sock = socket.create_connection(("127.0.0.1", self.port), timeout=3)
                request = ("POST /api/predict HTTP/1.0\r\nHost: 127.0.0.1:%d\r\n"
                           "Content-Type: application/json\r\n%s\r\n\r\n{}") % (self.port, header)
                sock.sendall(request.encode("ascii"))
                response = http.client.HTTPResponse(sock)
                response.begin()
                self.assertEqual(response.status, expected)
                self.assertIn("error", json.loads(response.read()))
                sock.close()


if __name__ == "__main__":
    unittest.main()
