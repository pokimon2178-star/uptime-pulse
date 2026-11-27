import json
import http.client
import os
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import MagicMock, patch

TEST_DIRECTORY = tempfile.TemporaryDirectory()
os.environ["DB_PATH"] = os.path.join(TEST_DIRECTORY.name, "pulse.sqlite3")

import app


class ProbeTests(unittest.TestCase):
    public_answer = [(None, None, None, None, ("1.1.1.1", 443))]

    def probe_with_status(self, scheme, code):
        class Response:
            status = code

            def close(self):
                pass

        class FakeConnection:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                self.requested = None

            def request(self, *args, **kwargs):
                self.requested = (args, kwargs)

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with patch.object(app.socket, "getaddrinfo", return_value=self.public_answer), \
             patch.object(app, "PinnedHTTPSConnection" if scheme == "https" else "PinnedHTTPConnection", side_effect=FakeConnection) as factory:
            result = app.probe_url(f"{scheme}://example.com/health?full=1")
        return result, factory

    def test_http_status_codes_report_reachability_separately(self):
        for code in (200, 301, 302, 399, 400, 404, 500, 503, 599):
            with self.subTest(code=code):
                result, _ = self.probe_with_status("http", code)
                self.assertEqual(result[0], "ONLINE")
                self.assertIsNotNone(result[1])
                self.assertEqual(result[2], code)

    def test_https_uses_tls_connection_and_keeps_redirect_status(self):
        result, factory = self.probe_with_status("https", 302)
        self.assertEqual(result[0], "ONLINE")
        self.assertEqual(result[2], 302)
        self.assertEqual(factory.call_args.kwargs["timeout"], app.REQUEST_TIMEOUT)

    def test_redirect_is_reported_without_following_location(self):
        result, factory = self.probe_with_status("https", 301)
        self.assertEqual(result[2], 301)
        self.assertEqual(factory.call_count, 1)

    def test_dns_tls_timeout_and_http_protocol_failures_are_offline(self):
        failures = (
            ("dns", lambda: patch.object(app.socket, "getaddrinfo", side_effect=socket.gaierror("no DNS"))),
            ("tls", lambda: patch.object(app, "PinnedHTTPSConnection", side_effect=ssl.SSLCertVerificationError("invalid cert"))),
            ("timeout", lambda: patch.object(app, "PinnedHTTPConnection", side_effect=TimeoutError("timeout"))),
            ("http", lambda: patch.object(app, "PinnedHTTPConnection", side_effect=ConnectionError("reset"))),
        )
        for name, patch_factory in failures:
            with self.subTest(failure=name):
                answer_patch = patch.object(app.socket, "getaddrinfo", side_effect=socket.gaierror("no DNS")) if name == "dns" else patch.object(app.socket, "getaddrinfo", return_value=self.public_answer)
                with patch_factory(), answer_patch:
                    result = app.probe_url("https://example.com/" if name == "tls" else "http://example.com/")
                self.assertEqual(result, ("OFFLINE", None, None))

    def test_non_public_dns_answer_is_blocked_before_connect(self):
        private_answer = [(None, None, None, None, ("127.0.0.1", 80))]
        with patch.object(app.socket, "getaddrinfo", return_value=private_answer), \
             patch.object(app, "PinnedHTTPConnection") as connection:
            self.assertEqual(app.probe_url("http://example.com/"), ("OFFLINE", None, None))
        connection.assert_not_called()


class URLValidationTests(unittest.TestCase):
    def test_normalizes_scheme_host_and_fragment(self):
        self.assertEqual(app.normalize_url(" EXAMPLE.com/path?q=1#fragment "), "https://example.com/path?q=1")

    def test_keeps_http_path_query_and_allowed_port(self):
        self.assertEqual(app.normalize_url("http://example.com:443/status?full=1#fragment"), "http://example.com:443/status?full=1")

    def test_rejects_localhosts_credentials_unsupported_scheme_and_port(self):
        for value in (
            "http://localhost", "http://localhost./", "http://service.local/", "http://internal.localhost/",
            "https://user:pass@example.com", "ftp://example.com", "https://example.com:8443",
        ):
            with self.subTest(url=value), self.assertRaises(ValueError):
                app.normalize_url(value)

    def test_rejects_control_characters_and_backslashes(self):
        for value in ("https://example.com/a\nHost: localhost", "https://example.com\\@127.0.0.1"):
            with self.subTest(url=value), self.assertRaises(ValueError):
                app.normalize_url(value)

    def test_rejects_private_dns_answers(self):
        for address in ("127.0.0.1", "10.0.0.1", "::1", "169.254.1.1"):
            answer = [(None, None, None, None, (address, 80))]
            with self.subTest(address=address), patch.object(app.socket, "getaddrinfo", return_value=answer):
                with self.assertRaises(OSError):
                    app.resolve_public_addresses("example.com", 80)

    def test_rejects_dns_answers_mixing_public_and_private_addresses(self):
        answers = [
            (None, None, None, None, ("1.1.1.1", 80)),
            (None, None, None, None, ("10.0.0.1", 80)),
        ]
        with patch.object(app.socket, "getaddrinfo", return_value=answers):
            with self.assertRaises(OSError):
                app.resolve_public_addresses("example.com", 80)


class PinnedConnectionTests(unittest.TestCase):
    def test_http_connection_dials_the_validated_ip(self):
        connection = app.PinnedHTTPConnection("example.com", 80, ip="1.1.1.1")
        fake_socket = MagicMock()
        with patch.object(app.socket, "create_connection", return_value=fake_socket) as create_connection:
            connection.connect()
        self.assertIs(connection.sock, fake_socket)
        self.assertEqual(create_connection.call_args.args[0], ("1.1.1.1", 80))
        connection.close()

    def test_https_connection_keeps_hostname_for_tls_sni(self):
        context = MagicMock()
        fake_socket = MagicMock()
        wrapped_socket = MagicMock()
        context.wrap_socket.return_value = wrapped_socket
        with patch.object(app.ssl, "_create_default_https_context", return_value=context):
            connection = app.PinnedHTTPSConnection("example.com", 443, ip="1.1.1.1")
        with patch.object(app.socket, "create_connection", return_value=fake_socket):
            connection.connect()
        self.assertIs(connection.sock, wrapped_socket)
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], "example.com")
        connection.close()

    def test_https_keeps_certificate_and_hostname_verification_enabled(self):
        connection = app.PinnedHTTPSConnection("example.com", 443, ip="1.1.1.1")
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        app.DB_CONN.close()
        self.directory = tempfile.TemporaryDirectory()
        app.DB_PATH = os.path.join(self.directory.name, "pulse.sqlite3")
        app.DB_CONN = app.init_db()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        app.DB_CONN.close()
        self.directory.cleanup()

    def request(self, path, method="GET", payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        request = Request(self.base_url + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as response:
            with response:
                return response.code, json.loads(response.read())

    def raw_request(self, path, body, headers):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_api_persists_and_returns_http_code_independently_of_online_status(self):
        with patch.object(app, "probe_url", return_value=("ONLINE", 42, 503)):
            code, target = self.request("/api/targets", "POST", {"name": "Example", "url": "https://example.com"})
        self.assertEqual(code, 201)
        self.assertEqual(target["status"], "ONLINE")
        self.assertEqual(target["http_status"], 503)
        self.assertFalse(target["http_success"])
        self.assertEqual(self.request("/api/targets")[1][0]["http_status"], 503)
        with patch.object(app, "probe_url", return_value=("ONLINE", 31, 200)):
            _, success = self.request("/api/targets", "POST", {"url": "https://success.example"})
        self.assertTrue(success["http_success"])

    def test_api_rejects_ssrf_target_before_probe(self):
        with patch.object(app, "probe_url") as probe:
            code, payload = self.request("/api/targets", "POST", {"url": "http://localhost"})
        self.assertEqual(code, 400)
        self.assertIn("Local hostnames", payload["error"])
        probe.assert_not_called()

    def test_api_rejects_invalid_and_oversized_json(self):
        code, payload = self.raw_request("/api/targets", b"{invalid", {"Content-Type": "application/json"})
        self.assertEqual(code, 400)
        self.assertEqual(payload["error"], "Invalid JSON")
        code, payload = self.raw_request(
            "/api/targets", b"", {"Content-Type": "application/json", "Content-Length": str(app.MAX_REQUEST_BODY + 1)}
        )
        self.assertEqual(code, 413)
        self.assertEqual(payload["error"], "Request body is too large")

    def test_duplicate_target_is_rejected_without_reprobing(self):
        with patch.object(app, "probe_url", return_value=("ONLINE", 1, 200)) as probe:
            self.assertEqual(self.request("/api/targets", "POST", {"url": "https://example.com"})[0], 201)
            code, payload = self.request("/api/targets", "POST", {"url": "https://example.com"})
        self.assertEqual(code, 409)
        self.assertIn("already", payload["error"])
        self.assertEqual(probe.call_count, 1)

    def test_delete_and_health_endpoints(self):
        with patch.object(app, "probe_url", return_value=("ONLINE", 1, 200)):
            _, target = self.request("/api/targets", "POST", {"url": "https://example.com"})
        self.assertEqual(self.request("/api/health"), (200, {"status": "ok"}))
        self.assertEqual(self.request(f"/api/targets/{target['id']}", "DELETE"), (200, {"deleted": target["id"]}))

    def test_check_all_probes_in_parallel_and_serializes_rounds(self):
        with app.DB_LOCK:
            for i in range(4):
                app.DB_CONN.execute(
                    "INSERT INTO targets (name, url, created_at) VALUES (?, ?, ?)",
                    (str(i), f"https://example{i}.com/", app.now_iso()),
                )
            app.DB_CONN.commit()
        active = 0
        peak = 0
        counter_lock = threading.Lock()

        def probe(_url):
            nonlocal active, peak
            with counter_lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            with counter_lock:
                active -= 1
            return "ONLINE", 10, 404

        with patch.object(app, "probe_url", side_effect=probe):
            rounds = [threading.Thread(target=app.check_all_targets) for _ in range(2)]
            for round_thread in rounds:
                round_thread.start()
            for round_thread in rounds:
                round_thread.join(timeout=3)
        self.assertTrue(all(not round_thread.is_alive() for round_thread in rounds))
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 4)
        with app.DB_LOCK:
            rows = app.DB_CONN.execute("SELECT status, http_status FROM targets").fetchall()
        self.assertEqual(rows, [("ONLINE", 404)] * 4)

    def test_legacy_database_is_migrated_in_place(self):
        legacy_path = os.path.join(self.directory.name, "legacy.sqlite3")
        legacy = sqlite3.connect(legacy_path)
        legacy.execute(
            "CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE, "
            "status TEXT DEFAULT 'PENDING', latency_ms INTEGER, last_checked TEXT, created_at TEXT NOT NULL)"
        )
        legacy.commit()
        legacy.close()
        original_path = app.DB_PATH
        app.DB_PATH = legacy_path
        try:
            migrated = app.init_db()
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(targets)")}
            migrated.close()
        finally:
            app.DB_PATH = original_path
        self.assertIn("http_status", columns)


if __name__ == "__main__":
    unittest.main()
