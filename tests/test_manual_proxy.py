import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import requests
from flask import Flask, request
from werkzeug.serving import make_server

from scanner.manual.proxy import ProxyConfig, WraithProxyController
from scanner.storage.repository import StorageRepository


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


def build_target_app() -> Flask:
    app = Flask(__name__)

    @app.route("/hello", methods=["GET", "POST"])
    def hello():
        return f"hello {request.args.get('name', 'wraith')}"

    return app


def proxied_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    return session


class ManualProxyTests(unittest.TestCase):
    def test_http_proxy_captures_and_persists_exchange(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_target_app()) as base_url:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            proxy = WraithProxyController()
            try:
                status = proxy.start(
                    repo,
                    ProxyConfig(
                        scan_id="proxy-scan",
                        target_base_url=base_url,
                        scope=[base_url],
                        auth_role="user_a",
                    ),
                )
                proxy_url = f"http://{status['host']}:{status['port']}"
                response = proxied_session().get(
                    f"{base_url}/hello?name=tester",
                    headers={"Authorization": "Bearer secret-token-value"},
                    proxies={"http": proxy_url},
                    timeout=5,
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.text, "hello tester")
                saved = repo.list_requests("proxy-scan", {"source": "proxy", "auth_role": "user_a"})
                self.assertEqual(len(saved), 1)
                self.assertEqual(saved[0]["headers"]["Authorization"], "[REDACTED]")
                stored_response = repo.get_response_for_request(saved[0]["request_id"])
                self.assertEqual(stored_response["status_code"], 200)
            finally:
                proxy.stop()
                repo.close()

    def test_proxy_blocks_out_of_scope_urls(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_target_app()) as base_url:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            proxy = WraithProxyController()
            try:
                status = proxy.start(
                    repo,
                    ProxyConfig(
                        scan_id="proxy-scope",
                        target_base_url=base_url,
                        scope=[f"{base_url}/allowed"],
                    ),
                )
                proxy_url = f"http://{status['host']}:{status['port']}"
                response = proxied_session().get(
                    f"{base_url}/hello",
                    proxies={"http": proxy_url},
                    timeout=5,
                )

                self.assertEqual(response.status_code, 403)
                self.assertEqual(repo.list_requests("proxy-scope", {"source": "proxy"}), [])
            finally:
                proxy.stop()
                repo.close()

    def test_intercept_can_hold_and_forward_pending_request(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_target_app()) as base_url:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            proxy = WraithProxyController()
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                status = proxy.start(
                    repo,
                    ProxyConfig(
                        scan_id="proxy-intercept",
                        target_base_url=base_url,
                        scope=[base_url],
                        intercept_enabled=True,
                        intercept_timeout_sec=5,
                    ),
                )
                proxy_url = f"http://{status['host']}:{status['port']}"
                future = executor.submit(
                    lambda: proxied_session().get(
                        f"{base_url}/hello?name=held",
                        proxies={"http": proxy_url},
                        timeout=10,
                    )
                )

                pending = []
                for _ in range(30):
                    pending = proxy.list_pending()
                    if pending:
                        break
                    time.sleep(0.05)
                self.assertEqual(len(pending), 1)
                self.assertTrue(proxy.decide(pending[0]["request_id"], "forward"))

                response = future.result(timeout=10)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.text, "hello held")
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
                proxy.stop()
                repo.close()

    def test_intercept_can_modify_request_before_forward(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_target_app()) as base_url:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            proxy = WraithProxyController()
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                status = proxy.start(
                    repo,
                    ProxyConfig(
                        scan_id="proxy-edit",
                        target_base_url=base_url,
                        scope=[base_url],
                        intercept_enabled=True,
                        intercept_timeout_sec=5,
                    ),
                )
                proxy_url = f"http://{status['host']}:{status['port']}"
                future = executor.submit(
                    lambda: proxied_session().get(
                        f"{base_url}/hello?name=original",
                        proxies={"http": proxy_url},
                        timeout=10,
                    )
                )

                pending = []
                for _ in range(30):
                    pending = proxy.list_pending()
                    if pending:
                        break
                    time.sleep(0.05)
                self.assertEqual(len(pending), 1)
                self.assertTrue(
                    proxy.decide(
                        pending[0]["request_id"],
                        "forward",
                        {"url": f"{base_url}/hello?name=edited"},
                    )
                )

                response = future.result(timeout=10)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.text, "hello edited")
                saved = repo.list_requests("proxy-edit", {"source": "proxy"})
                self.assertEqual(len(saved), 1)
                self.assertTrue(any("name=edited" in item["url"] for item in saved))
                self.assertEqual(proxy.status()["modified_count"], 1)
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
                proxy.stop()
                repo.close()


if __name__ == "__main__":
    unittest.main()
