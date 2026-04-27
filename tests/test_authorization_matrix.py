import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from api_server import app as api_app
from scanner.core.authorization_matrix import run_authorization_matrix
from scanner.core.models import AuthProfile, RequestRecord, ScanConfig
from scanner.storage.repository import StorageRepository


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


def build_bola_app():
    app = Flask(__name__)

    @app.get("/api/invoices/<invoice_id>")
    def read_invoice(invoice_id):
        session = request.cookies.get("session")
        if session not in {"user_a", "user_b"}:
            return jsonify({"error": "forbidden"}), 403
        # Intentionally vulnerable demo behavior: user_b can read user_a's object.
        return jsonify({
            "id": invoice_id,
            "owner": "user_a",
            "email": "alice@example.test",
            "total": 120,
        })

    @app.post("/api/invoices/<invoice_id>")
    def update_invoice(invoice_id):
        return jsonify({"updated": invoice_id})

    return app


class AuthorizationMatrixTests(unittest.TestCase):
    def _repo_with_scan_and_request(self, tmpdir, base_url, *, method="GET"):
        repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
        scan = ScanConfig(scan_id="authz-scan", target_base_url=base_url, scope=[base_url])
        repo.create_scan(scan)
        repo.save_request(
            RequestRecord.create(
                scan_id=scan.scan_id,
                source="import",
                method=method,
                url=f"{base_url}/api/invoices/1001",
                auth_role="user_a",
            )
        )
        return repo, scan

    def test_matrix_replays_object_request_and_persists_bola_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_bola_app()) as base_url:
            repo, scan = self._repo_with_scan_and_request(tmpdir, base_url)
            try:
                result = run_authorization_matrix(
                    repository=repo,
                    scan_id=scan.scan_id,
                    auth_profiles=[
                        AuthProfile("", "User A", base_url, "user_a", "cookie", cookies={"session": "user_a"}),
                        AuthProfile("", "User B", base_url, "user_b", "cookie", cookies={"session": "user_b"}),
                    ],
                    max_requests=5,
                    timeout=5,
                    safety_mode="safe",
                )

                self.assertEqual(result.compared_requests, 1)
                self.assertEqual(len(result.findings), 1)
                self.assertEqual(result.findings[0]["vuln_type"], "idor")
                self.assertEqual(result.findings[0]["auth_role"], "user_b")
                self.assertEqual(len(repo.list_requests(scan.scan_id, {"source": "authz"})), 2)
                self.assertEqual(len(repo.list_findings(scan.scan_id, {"vuln_type": "idor"})), 1)
                artifacts = repo.list_evidence_artifacts(finding_id=result.findings[0]["finding_id"])
                self.assertEqual(len(artifacts), 1)
                self.assertEqual(artifacts[0]["artifact_type"], "diff")
            finally:
                repo.close()

    def test_matrix_safe_mode_skips_state_changing_requests(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_bola_app()) as base_url:
            repo, scan = self._repo_with_scan_and_request(tmpdir, base_url, method="POST")
            try:
                result = run_authorization_matrix(
                    repository=repo,
                    scan_id=scan.scan_id,
                    auth_profiles=[
                        AuthProfile("", "User A", base_url, "user_a", "cookie", cookies={"session": "user_a"}),
                        AuthProfile("", "User B", base_url, "user_b", "cookie", cookies={"session": "user_b"}),
                    ],
                    safety_mode="safe",
                )

                self.assertEqual(result.compared_requests, 0)
                self.assertEqual(len(result.findings), 0)
                self.assertIn("safe mode", result.skipped_requests[0]["reason"])
            finally:
                repo.close()

    def test_authz_matrix_api_runs_against_corpus(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_bola_app()) as base_url:
            repo, scan = self._repo_with_scan_and_request(tmpdir, base_url)
            try:
                with patch("api_server._storage_repo", return_value=repo):
                    client = api_app.test_client()
                    response = client.post(
                        "/api/authz/matrix/run",
                        json={
                            "scan_id": scan.scan_id,
                            "auth_profiles": [
                                {"type": "cookie", "role": "user_a", "cookies": {"session": "user_a"}},
                                {"type": "cookie", "role": "user_b", "cookies": {"session": "user_b"}},
                            ],
                            "max_requests": 5,
                        },
                    )

                self.assertEqual(response.status_code, 200, response.get_json())
                payload = response.get_json()
                self.assertEqual(payload["compared_requests"], 1)
                self.assertEqual(len(payload["findings"]), 1)
                self.assertEqual(payload["findings"][0]["auth_role"], "user_b")
            finally:
                repo.close()


if __name__ == "__main__":
    unittest.main()
