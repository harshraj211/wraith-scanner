import threading
import time
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import requests
from flask import Flask, redirect, request
from werkzeug.serving import make_server

from scanner.core.async_engine import AsyncScanEngine, build_url_param_pairs
from scanner.modules.idor_scanner import IDORScanner
from scanner.modules.redirect_scanner import RedirectScanner
from scanner.modules.ssrf_scanner import SSRFScanner
from scanner.modules.xss_scanner import XSSScanner
from test_app.vulnerable_app import app as vulnerable_app


class FakeOOBClient:
    def __init__(self):
        self._available = False

    @property
    def available(self) -> bool:
        return False

    def get_payload_url(self, tag: str = "") -> str:
        return ""

    def poll(self, seconds: int = 3):
        return []

    def close(self):
        return None


@contextmanager
def run_app(app: Flask):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def build_aux_app() -> Flask:
    app = Flask(__name__)

    @app.route("/redir")
    def redir():
        target = request.args.get("next", "/")
        return f'<meta http-equiv="refresh" content="0;url={target}"><p>Redirecting</p>'

    @app.route("/fixed")
    def fixed():
        return redirect("https://example.com", code=302)

    @app.route("/meta")
    def meta():
        return 'instance-id\nami-12345678\nlocal-ipv4\ncomputeMetadata\n'

    @app.route("/fetch")
    def fetch():
        target = request.args.get("url", "http://127.0.0.1/none")
        try:
            return requests.get(target, timeout=2).text
        except Exception as exc:
            return str(exc), 502

    return app


class SecurityRegressionTests(unittest.TestCase):
    def test_xss_reflected_form_detected(self):
        with run_app(vulnerable_app) as base_url:
            scanner = XSSScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/comment",
                "method": "post",
                "inputs": [
                    {"name": "name", "value": "tester"},
                    {"name": "comment", "value": "hello"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "xss-reflected")
        self.assertGreaterEqual(findings[0]["confidence"], 78)

    def test_dom_xss_sink_tracking_detects_runtime_innerhtml_flow(self):
        with run_app(vulnerable_app) as base_url:
            scanner = XSSScanner(timeout=5)
            findings = scanner.scan_url(f"{base_url}/dom", {"dom": "hello"})

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "xss-dom")
        self.assertIn("instrumented dom sink", findings[0]["evidence"].lower())

    def test_idor_detected_with_object_change_evidence(self):
        with run_app(vulnerable_app) as base_url:
            scanner = IDORScanner(timeout=5)
            findings = scanner.scan_url(f"{base_url}/profile", {"id": "1"})

        self.assertTrue(findings)
        finding = findings[0]
        self.assertEqual(finding["type"], "idor")
        self.assertIn("Object identifier changed", finding["evidence"])
        self.assertGreaterEqual(finding["confidence"], 84)

    def test_idor_detected_on_rest_style_path_object(self):
        with run_app(vulnerable_app) as base_url:
            scanner = IDORScanner(timeout=5)
            findings = scanner.scan_url(f"{base_url}/api/users/1", {"view": "summary"})

        self.assertTrue(findings)
        finding = findings[0]
        self.assertEqual(finding["type"], "idor")
        self.assertEqual(finding["param"], "path:users")
        self.assertIn("Object identifier changed from 1 to 2", finding["evidence"])
        self.assertGreaterEqual(finding["confidence"], 84)

    def test_async_pipeline_keeps_path_targets_and_strips_query_before_scan(self):
        with run_app(vulnerable_app) as base_url:
            targets = build_url_param_pairs([f"{base_url}/api/users/1?view=summary"])
            engine = AsyncScanEngine(max_concurrent=4, timeout=5)
            with ThreadPoolExecutor(max_workers=1) as pool:
                findings = pool.submit(
                    engine.scan_urls_sync,
                    targets,
                    [IDORScanner(timeout=5)],
                ).result(timeout=10)

        self.assertEqual(targets, [(f"{base_url}/api/users/1", {"view": "summary"})])
        self.assertTrue(findings)
        self.assertEqual(findings[0]["param"], "path:users")

    def test_redirect_scanner_flags_param_controlled_redirect(self):
        with run_app(build_aux_app()) as base_url:
            scanner = RedirectScanner(timeout=5)
            findings = scanner.scan_url(f"{base_url}/redir", {"next": "/"})

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "open-redirect")
        self.assertEqual(findings[0]["redirect_method"], "meta")

    def test_redirect_scanner_ignores_fixed_external_redirect(self):
        with run_app(build_aux_app()) as base_url:
            scanner = RedirectScanner(timeout=5)
            findings = scanner.scan_url(f"{base_url}/fixed", {"next": "/"})

        self.assertEqual(findings, [])

    @patch("scanner.modules.ssrf_scanner._OOBClient", FakeOOBClient)
    def test_ssrf_scanner_ignores_echoed_fetch_errors(self):
        with run_app(build_aux_app()) as base_url:
            with patch("scanner.modules.ssrf_scanner.SSRF_TARGETS", [("http://127.0.0.1:1/meta", "dead_target")]):
                with patch("scanner.modules.ssrf_scanner.SSRF_HEADERS", []):
                    scanner = SSRFScanner(timeout=2)
                    findings = scanner.scan_url(f"{base_url}/fetch", {"url": "http://example.com"})

        self.assertEqual(findings, [])

    @patch("scanner.modules.ssrf_scanner._OOBClient", FakeOOBClient)
    def test_ssrf_scanner_detects_meaningful_inband_fetch(self):
        with run_app(build_aux_app()) as base_url:
            with patch("scanner.modules.ssrf_scanner.SSRF_TARGETS", [(f"{base_url}/meta", "local_meta")]):
                with patch("scanner.modules.ssrf_scanner.SSRF_HEADERS", []):
                    scanner = SSRFScanner(timeout=2)
                    findings = scanner.scan_url(f"{base_url}/fetch", {"url": "http://example.com"})

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "ssrf")
        self.assertEqual(findings[0]["target"], "local_meta")


if __name__ == "__main__":
    unittest.main()
