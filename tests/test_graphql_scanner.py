import threading
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from werkzeug.serving import make_server

from scanner.core.crawler import WebCrawler
from scanner.modules.graphql_scanner import GraphQLScanner
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


class GraphQLScannerTests(unittest.TestCase):
    def test_crawler_synthesizes_graphql_form(self):
        with run_app(vulnerable_app) as base_url:
            crawler = WebCrawler(base_url, max_depth=1, timeout=5)
            with patch.object(WebCrawler, "_playwright_available", return_value=False):
                results = crawler.crawl()

        graphql_forms = [
            form for form in results["forms"]
            if form.get("graphql") and form.get("action") == f"{base_url}/graphql"
        ]
        self.assertTrue(graphql_forms)
        self.assertEqual(graphql_forms[0].get("body_format"), "graphql")

    def test_graphql_scanner_detects_introspection_and_injection_findings(self):
        with run_app(vulnerable_app) as base_url:
            scanner = GraphQLScanner(timeout=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/graphql",
                "method": "post",
                "content_type": "application/json",
                "body_format": "graphql",
                "graphql": True,
                "inputs": [
                    {"name": "query", "value": "query IntrospectionQuery { __typename }"},
                ],
            })

        finding_types = {finding["type"] for finding in findings}
        self.assertIn("graphql-introspection", finding_types)
        self.assertIn("xss-reflected", finding_types)
        self.assertIn("sqli-error", finding_types)


if __name__ == "__main__":
    unittest.main()
