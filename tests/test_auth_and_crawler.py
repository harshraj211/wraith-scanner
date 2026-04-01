import threading
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from werkzeug.serving import make_server

from scanner.core.crawler import WebCrawler
from scanner.utils.auth_manager import AuthManager, extract_browser_storage_auth
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


class AuthAndCrawlerTests(unittest.TestCase):
    def test_auth_manager_extracts_and_ingests_browser_storage_tokens(self):
        storage = {
            "localStorage": {
                "authState": '{"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}',
            },
            "sessionStorage": {},
        }

        extracted = extract_browser_storage_auth(storage)
        self.assertEqual(
            extracted.get("authorization"),
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        )

        auth = AuthManager()
        self.assertTrue(auth.ingest_browser_storage(storage))
        self.assertEqual(
            auth.get_session().headers.get("Authorization"),
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        )

    def test_auth_manager_logs_into_session_protected_area(self):
        with run_app(vulnerable_app) as base_url:
            auth = AuthManager()
            success = auth.login_form(
                f"{base_url}/auth/login",
                "admin",
                "admin123",
                username_field="user_name",
                password_field="user_pass",
            )

            self.assertTrue(success)
            dashboard = auth.get_session().get(f"{base_url}/auth/dashboard", timeout=5)

        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Authenticated Dashboard", dashboard.text)
        self.assertIn("Logout", dashboard.text)

    def test_crawler_needs_authenticated_session_for_protected_links(self):
        with run_app(vulnerable_app) as base_url:
            unauth_crawler = WebCrawler(f"{base_url}/auth/dashboard", max_depth=1, timeout=5)
            with patch.object(WebCrawler, "_playwright_available", return_value=False):
                unauth_results = unauth_crawler.crawl()

            auth = AuthManager()
            success = auth.login_form(
                f"{base_url}/auth/login",
                "admin",
                "admin123",
                username_field="user_name",
                password_field="user_pass",
            )
            self.assertTrue(success)

            auth_crawler = WebCrawler(
                f"{base_url}/auth/dashboard",
                max_depth=1,
                timeout=5,
                session=auth.get_session(),
            )
            with patch.object(WebCrawler, "_playwright_available", return_value=False):
                auth_results = auth_crawler.crawl()

        unauth_urls = set(unauth_results["urls"])
        auth_urls = set(auth_results["urls"])
        auth_forms = auth_results["forms"]

        self.assertNotIn(f"{base_url}/auth/records?id=1", unauth_urls)
        self.assertIn(f"{base_url}/auth/records?id=1", auth_urls)
        self.assertTrue(any(form.get("action") == f"{base_url}/auth/report" for form in auth_forms))


if __name__ == "__main__":
    unittest.main()
