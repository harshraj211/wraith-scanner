import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from api_server import app as api_app
from flask import Flask, redirect, request
from werkzeug.serving import make_server

from scanner.core.models import Finding, ScanConfig
from scanner.exploitation.evidence import persist_proof_result
from scanner.exploitation.executors.redirect import OpenRedirectProofExecutor
from scanner.exploitation.models import ProofContext
from scanner.exploitation.planner import create_proof_task
from scanner.exploitation.policy import ProofPolicyEngine
from scanner.exploitation.registry import default_registry
from scanner.exploitation.runner import run_proof_coroutine
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


def redirect_app() -> Flask:
    app = Flask(__name__)

    @app.route("/redir")
    def redir():
        return redirect(request.args.get("next", "/"), code=302)

    return app


class ProofModeTests(unittest.TestCase):
    def test_planner_and_registry_select_safe_open_redirect_executor(self):
        finding = Finding.from_legacy(
            {
                "type": "open-redirect",
                "url": "https://app.example.test/redir?next=/",
                "param": "next",
                "confidence": 95,
                "evidence": "Header redirect to external host",
            },
            target_url="https://app.example.test",
            scan_id="scan-proof",
        )
        task = create_proof_task(finding)
        registry = default_registry()

        self.assertIn("open_redirect_controlled_redirect", task.allowed_techniques)
        self.assertIsNotNone(registry.get("open_redirect_controlled_redirect"))

    def test_policy_blocks_out_of_scope_target(self):
        finding = Finding.from_legacy(
            {
                "type": "open-redirect",
                "url": "https://outside.example.test/redir?next=/",
                "param": "next",
                "confidence": 95,
            },
            target_url="https://outside.example.test",
            scan_id="scan-proof",
        )
        task = create_proof_task(finding)
        scan = ScanConfig(
            scan_id="scan-proof",
            target_base_url="https://app.example.test",
            scope=["https://app.example.test"],
        )

        decision = ProofPolicyEngine().validate(
            finding=finding,
            task=task,
            scan_config=scan,
            technique_id="open_redirect_controlled_redirect",
        )

        self.assertFalse(decision.allowed)
        self.assertIn("outside", decision.reason)

    def test_open_redirect_executor_proves_without_following_redirect(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(redirect_app()) as base_url:
            repo = StorageRepository(str(Path(tmpdir) / "proof.sqlite3"))
            scan = ScanConfig(scan_id="scan-proof", target_base_url=base_url, scope=[base_url])
            repo.create_scan(scan)
            finding = Finding.from_legacy(
                {
                    "type": "open-redirect",
                    "url": f"{base_url}/redir?next=/",
                    "param": "next",
                    "confidence": 95,
                    "evidence": "Header redirect changed with next parameter",
                },
                target_url=base_url,
                scan_id=scan.scan_id,
            )
            repo.save_finding(finding)
            task = create_proof_task(finding)
            repo.save_proof_task(task)

            try:
                result = run_proof_coroutine(
                    OpenRedirectProofExecutor().execute(
                        task,
                        ProofContext(
                            finding=finding,
                            scan_config=scan,
                            repository=repo,
                            controlled_redirect_url="https://wraith-proof.invalid",
                        ),
                    )
                )
                artifact_ids = persist_proof_result(repo, finding=finding, task=task, result=result)

                self.assertEqual(result.result, "succeeded")
                self.assertEqual(len(result.attempts), 1)
                self.assertEqual(len(artifact_ids), 1)
                self.assertEqual(repo.get_finding(finding.finding_id)["proof_status"], "succeeded")
                self.assertEqual(repo.get_proof_task(task.task_id)["result"], "succeeded")
                proof_requests = repo.list_requests(scan.scan_id, {"source": "proof"})
                self.assertEqual(len(proof_requests), 1)
                stored_response = repo.get_response_for_request(proof_requests[0]["request_id"])
                self.assertEqual(stored_response["status_code"], 302)
            finally:
                repo.close()

    def test_proof_api_creates_and_runs_open_redirect_task(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(redirect_app()) as base_url:
            repo = StorageRepository(str(Path(tmpdir) / "proof-api.sqlite3"))
            try:
                scan = ScanConfig(scan_id="scan-proof-api", target_base_url=base_url, scope=[base_url])
                repo.create_scan(scan)
                finding = Finding.from_legacy(
                    {
                        "type": "open-redirect",
                        "url": f"{base_url}/redir?next=/",
                        "param": "next",
                        "confidence": 95,
                        "evidence": "Header redirect changed with next parameter",
                    },
                    target_url=base_url,
                    scan_id=scan.scan_id,
                )
                repo.save_finding(finding)

                with patch("api_server._storage_repo", return_value=repo):
                    client = api_app.test_client()
                    created = client.post(f"/api/proof/{finding.finding_id}/task", json={"safety_mode": "safe"})
                    self.assertEqual(created.status_code, 200)
                    task_id = created.get_json()["task"]["task_id"]

                    run = client.post(f"/api/proof/{task_id}/run", json={})
                    self.assertEqual(run.status_code, 200, run.get_json())
                    self.assertEqual(run.get_json()["result"]["result"], "succeeded")

                self.assertEqual(repo.get_finding(finding.finding_id)["proof_status"], "succeeded")
            finally:
                repo.close()


if __name__ == "__main__":
    unittest.main()
