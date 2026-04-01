import asyncio
import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from werkzeug.serving import make_server

from scanner.core.crawler import WebCrawler
from scanner.core.live_scan import LiveDiscoveryScanner
from scanner.core.workflows import execute_workflow, load_workflows, workflow_matches
from scanner.modules.xss_scanner import XSSScanner
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


class _FakeLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector
        self.first = self

    async def click(self, timeout=None):
        self.page.actions.append(("click", self.selector, timeout))

    async def fill(self, value, timeout=None):
        self.page.actions.append(("fill", self.selector, value, timeout))

    async def press(self, key, timeout=None):
        self.page.actions.append(("press", self.selector, key, timeout))

    async def select_option(self, value=None, timeout=None):
        self.page.actions.append(("select", self.selector, value, timeout))

    async def check(self, timeout=None):
        self.page.actions.append(("check", self.selector, timeout))

    async def uncheck(self, timeout=None):
        self.page.actions.append(("uncheck", self.selector, timeout))


class _FakePage:
    def __init__(self):
        self.url = "http://example.test/start"
        self.actions = []

    def locator(self, selector):
        return _FakeLocator(self, selector)

    async def goto(self, url, wait_until=None, timeout=None):
        self.url = url
        self.actions.append(("goto", url, wait_until, timeout))

    async def wait_for_timeout(self, ms):
        self.actions.append(("wait", ms))

    async def wait_for_selector(self, selector, timeout=None):
        self.actions.append(("wait_for_selector", selector, timeout))

    async def wait_for_url(self, pattern, timeout=None):
        self.actions.append(("wait_for_url", pattern, timeout))

    async def evaluate(self, script, arg=None):
        self.actions.append(("evaluate", script, arg))


class LiveScanAndWorkflowTests(unittest.TestCase):
    def test_live_discovery_scanner_scans_forms_during_crawl(self):
        with run_app(vulnerable_app) as base_url:
            live_scanner = LiveDiscoveryScanner(
                form_scanners=[XSSScanner(timeout=5)],
            )
            crawler = WebCrawler(
                base_url,
                max_depth=1,
                timeout=5,
                discovery_callback=live_scanner.handle_discovery,
            )
            with patch.object(WebCrawler, "_playwright_available", return_value=False):
                results = crawler.crawl()

        self.assertTrue(results["forms"])
        self.assertTrue(live_scanner.findings)
        self.assertIn(
            "xss-reflected",
            {finding["type"] for finding in live_scanner.findings},
        )

    def test_workflow_loader_and_executor_support_macro_files(self):
        workflow_doc = {
            "workflows": [
                {
                    "name": "login-sequence",
                    "match": "/auth/login",
                    "steps": [
                        {"action": "goto", "url": "/auth/login"},
                        {"action": "fill", "selector": "#user", "value": "admin"},
                        {"action": "fill", "selector": "#pass", "value": "admin123"},
                        {"action": "click", "selector": "button[type=submit]"},
                        {"action": "wait", "selector": "#dashboard"},
                        {"action": "set_storage", "storage": "localStorage", "key": "token", "value": "abc123"},
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            workflow_path = Path(tmpdir) / "workflow.json"
            workflow_path.write_text(json.dumps(workflow_doc), encoding="utf-8")
            workflows = load_workflows(workflow_path)

        self.assertEqual(len(workflows), 1)
        self.assertTrue(workflow_matches(workflows[0], "http://example.test/auth/login"))

        page = _FakePage()
        trace_box = {}
        error_box = {}

        def runner():
            try:
                trace_box["trace"] = asyncio.run(
                    execute_workflow(
                        page,
                        workflows[0],
                        "http://example.test",
                        timeout_ms=5000,
                    )
                )
            except Exception as exc:  # pragma: no cover
                error_box["error"] = exc

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        thread.join(timeout=5)

        if error_box:
            raise error_box["error"]
        trace = trace_box["trace"]

        self.assertTrue(trace)
        self.assertTrue(all(step["status"] == "ok" for step in trace))
        self.assertIn(("goto", "http://example.test/auth/login", "domcontentloaded", 5000), page.actions)
        self.assertIn(("fill", "#user", "admin", 5000), page.actions)
        self.assertTrue(any(action[0] == "evaluate" for action in page.actions))


if __name__ == "__main__":
    unittest.main()
