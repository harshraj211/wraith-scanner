import threading
import time
import unittest
from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from werkzeug.serving import make_server

from scanner.modules.cmdi_scanner import CMDIScanner
from scanner.core.crawler import WebCrawler
from scanner.modules.path_traversal_scanner import PathTraversalScanner
from scanner.modules.sqli_scanner import SQLiScanner
from scanner.modules.ssti_scanner import SSTIScanner
from scanner.modules.xxe_scanner import XXEScanner
from scanner.modules.xss_scanner import XSSScanner
from scanner.utils.auth_manager import AuthManager
from test_app.vulnerable_app import app as vulnerable_app


@contextmanager
def run_app(app):
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


class ApiDiscoveryAndJsonScanningTests(unittest.TestCase):
    def _build_api_auth_session(self):
        auth = AuthManager()
        auth.set_bearer_token("test-bearer-token")
        auth.set_api_key("X-API-Key", "header-key-123", "header")
        auth.set_api_key("sessionid", "secure-session-789", "cookie")
        auth.set_api_key("api_token", "query-key-456", "query")
        return auth.get_session()

    def test_crawler_imports_openapi_json_targets(self):
        with run_app(vulnerable_app) as base_url:
            crawler = WebCrawler(base_url, max_depth=1, timeout=5)
            with patch.object(WebCrawler, "_playwright_available", return_value=False):
                results = crawler.crawl()

        self.assertIn(f"{base_url}/api/users/1?view=summary", results["urls"])

        json_forms = [
            form for form in results["forms"]
            if form.get("content_type") == "application/json"
        ]
        self.assertTrue(
            any(form.get("action") == f"{base_url}/api/comment" for form in json_forms)
        )
        self.assertTrue(
            any(form.get("action") == f"{base_url}/api/search" for form in json_forms)
        )
        self.assertTrue(
            any(form.get("action") == f"{base_url}/api/run" for form in json_forms)
        )
        self.assertTrue(
            any(form.get("action") == f"{base_url}/api/file" for form in json_forms)
        )
        self.assertTrue(
            any(form.get("action") == f"{base_url}/api/template" for form in json_forms)
        )
        self.assertTrue(
            any(form.get("action") == f"{base_url}/api/xml" for form in results["forms"])
        )

    def test_xss_scanner_detects_reflected_xss_in_json_body(self):
        with run_app(vulnerable_app) as base_url:
            scanner = XSSScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/api/comment",
                "method": "post",
                "content_type": "application/json",
                "body_format": "json",
                "inputs": [
                    {"name": "name", "value": "tester"},
                    {"name": "comment", "value": "hello"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "xss-reflected")
        self.assertGreaterEqual(findings[0]["confidence"], 78)

    def test_sqli_scanner_detects_error_based_sqli_in_json_body(self):
        with run_app(vulnerable_app) as base_url:
            scanner = SQLiScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/api/search",
                "method": "post",
                "content_type": "application/json",
                "body_format": "json",
                "inputs": [
                    {"name": "q", "value": "admin"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "sqli-error")
        self.assertIn("unrecognized token", findings[0]["evidence"].lower())

    def test_cmdi_scanner_detects_command_execution_in_json_body(self):
        with run_app(vulnerable_app) as base_url:
            scanner = CMDIScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/api/run",
                "method": "post",
                "content_type": "application/json",
                "body_format": "json",
                "inputs": [
                    {"name": "command", "value": "status"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "command-injection")

    def test_path_traversal_scanner_detects_json_body_file_read(self):
        with run_app(vulnerable_app) as base_url:
            scanner = PathTraversalScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/api/file",
                "method": "post",
                "content_type": "application/json",
                "body_format": "json",
                "inputs": [
                    {"name": "file", "value": "report.txt"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "path-traversal")

    def test_ssti_scanner_detects_json_body_template_execution(self):
        with run_app(vulnerable_app) as base_url:
            scanner = SSTIScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/api/template",
                "method": "post",
                "content_type": "application/json",
                "body_format": "json",
                "inputs": [
                    {"name": "template", "value": "Hello world"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "ssti")

    def test_xxe_scanner_detects_xml_body_endpoint(self):
        with run_app(vulnerable_app) as base_url:
            scanner = XXEScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/api/xml",
                "method": "post",
                "content_type": "application/xml",
                "body_format": "xml",
                "inputs": [
                    {"name": "xml", "value": "<root />"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "xxe")

    def test_crawler_imports_openapi_security_context_for_protected_api_targets(self):
        with run_app(vulnerable_app) as base_url:
            crawler = WebCrawler(
                base_url,
                max_depth=1,
                timeout=5,
                session=self._build_api_auth_session(),
            )
            with patch.object(WebCrawler, "_playwright_available", return_value=False):
                results = crawler.crawl()

        secure_form = next(
            form for form in results["forms"]
            if form.get("action") == f"{base_url}/api/secure/reflect"
        )
        secure_query_url = next(
            url for url in results["urls"]
            if url.startswith(f"{base_url}/api/secure/query?")
        )

        self.assertEqual(
            secure_form.get("extra_headers", {}).get("Authorization"),
            "Bearer test-bearer-token",
        )
        self.assertEqual(
            secure_form.get("extra_headers", {}).get("X-API-Key"),
            "header-key-123",
        )
        self.assertEqual(
            secure_form.get("extra_cookies", {}).get("sessionid"),
            "secure-session-789",
        )
        self.assertIn(
            "X-Trace",
            {item.get("name") for item in secure_form.get("header_inputs", [])},
        )
        self.assertIn(
            "theme",
            {item.get("name") for item in secure_form.get("cookie_inputs", [])},
        )

        secure_query_params = parse_qs(urlparse(secure_query_url).query)
        self.assertEqual(secure_query_params.get("api_token"), ["query-key-456"])
        self.assertEqual(secure_query_params.get("item"), ["sample"])

    def test_xss_scanner_detects_authenticated_header_or_cookie_xss_from_openapi_form(self):
        with run_app(vulnerable_app) as base_url:
            session = self._build_api_auth_session()
            crawler = WebCrawler(base_url, max_depth=1, timeout=5, session=session)
            with patch.object(WebCrawler, "_playwright_available", return_value=False):
                results = crawler.crawl()

            secure_form = next(
                form for form in results["forms"]
                if form.get("action") == f"{base_url}/api/secure/reflect"
            )
            scanner = XSSScanner(timeout=5, session=session)
            findings = scanner.scan_form(secure_form)

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "xss-reflected")
        self.assertIn(findings[0]["param"], {"X-Trace", "theme"})
        self.assertGreaterEqual(findings[0]["confidence"], 78)


if __name__ == "__main__":
    unittest.main()
