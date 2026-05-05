import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_server import app
from scanner.core.models import EvidenceArtifact, Finding, ProofTask, RequestRecord, ResponseRecord, ScanConfig
from scanner.storage.repository import StorageRepository


class CorpusApiTests(unittest.TestCase):
    def test_corpus_request_and_finding_endpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            scan = ScanConfig(scan_id="scan-corpus", target_base_url="https://app.example.test")
            repo.create_scan(scan)
            request_record = RequestRecord.create(
                scan_id=scan.scan_id,
                source="replay",
                method="POST",
                url="https://app.example.test/api/items",
                headers={"Authorization": "Bearer secret-token-value"},
                body={"name": "demo"},
                auth_role="user_a",
            )
            repo.save_request(request_record)
            repo.save_response(
                ResponseRecord.create(
                    request_id=request_record.request_id,
                    status_code=201,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"id": "item-1"}),
                    response_time_ms=12,
                )
            )
            finding = Finding.from_legacy(
                {
                    "type": "idor",
                    "url": request_record.url,
                    "param": "id",
                    "evidence": "role diff",
                    "confidence": 90,
                },
                target_url=scan.target_base_url,
                scan_id=scan.scan_id,
                auth_role="user_a",
            )
            repo.save_finding(finding)

            with patch("api_server._storage_repo", return_value=repo):
                client = app.test_client()
                list_response = client.get(
                    "/api/corpus/scan-corpus/requests?source=replay&status_code=201&auth_role=user_a"
                )
                self.assertEqual(list_response.status_code, 200)
                payload = list_response.get_json()
                self.assertEqual(payload["count"], 1)
                self.assertEqual(payload["requests"][0]["headers"]["Authorization"], "[REDACTED]")

                detail_response = client.get(f"/api/corpus/request/{request_record.request_id}")
                self.assertEqual(detail_response.status_code, 200)
                detail = detail_response.get_json()
                self.assertEqual(detail["request"]["request_id"], request_record.request_id)
                self.assertEqual(detail["response"]["status_code"], 201)

                findings_response = client.get("/api/corpus/scan-corpus/findings?vuln_type=idor")
                self.assertEqual(findings_response.status_code, 200)
                self.assertEqual(findings_response.get_json()["count"], 1)

                manual_response = client.post(
                    "/api/corpus/scan-corpus/findings/manual",
                    json={
                        "request_id": request_record.request_id,
                        "title": "Manual access control note",
                        "vuln_type": "idor",
                        "severity": "high",
                        "parameter_name": "id",
                        "evidence": "Observed object swap manually.",
                    },
                )
                self.assertEqual(manual_response.status_code, 201)
                manual = manual_response.get_json()["finding"]
                self.assertEqual(manual["discovery_method"], "manual")
                self.assertIn(request_record.request_id, manual["metadata"]["request_id"])
                self.assertIn("Request evidence", manual["discovery_evidence"])
                artifacts = manual_response.get_json()["artifacts"]
                self.assertEqual({item["artifact_type"] for item in artifacts}, {"request", "response", "log"})
                self.assertEqual(len(manual["metadata"]["artifact_ids"]), 3)
                request_artifact = next(item for item in artifacts if item["artifact_type"] == "request")
                self.assertIn("[REDACTED]", request_artifact["inline_excerpt"])
                self.assertNotIn("secret-token-value", request_artifact["inline_excerpt"])

                linked_artifacts = client.get(f"/api/evidence/artifacts?finding_id={manual['finding_id']}")
                self.assertEqual(linked_artifacts.status_code, 200)
                self.assertEqual(linked_artifacts.get_json()["count"], 3)
            repo.close()

    def test_manual_compare_responses_returns_diff_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            scan = ScanConfig(scan_id="scan-diff", target_base_url="https://app.example.test")
            repo.create_scan(scan)
            req_a = RequestRecord.create(scan_id=scan.scan_id, source="manual", method="GET", url="https://app.example.test/a")
            req_b = RequestRecord.create(scan_id=scan.scan_id, source="manual", method="GET", url="https://app.example.test/b")
            repo.save_request(req_a)
            repo.save_request(req_b)
            repo.save_response(ResponseRecord.create(request_id=req_a.request_id, status_code=200, headers={"Content-Type": "text/html"}, body="old", response_time_ms=10))
            repo.save_response(ResponseRecord.create(request_id=req_b.request_id, status_code=500, headers={"Content-Type": "text/html"}, body="new body", response_time_ms=25))
            finding = Finding.from_legacy({"type": "manual", "title": "Manual diff", "url": req_b.url, "confidence": 80}, target_url=scan.target_base_url, scan_id=scan.scan_id)
            repo.save_finding(finding)

            with patch("api_server._storage_repo", return_value=repo):
                client = app.test_client()
                response = client.post("/api/manual/compare-responses", json={
                    "baseline_request_id": req_a.request_id,
                    "candidate_request_id": req_b.request_id,
                    "finding_id": finding.finding_id,
                })
                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertEqual(payload["diff"]["status_delta"], "200 -> 500")
                self.assertTrue(payload["diff"]["body_changed"])
                self.assertEqual(payload["artifact"]["artifact_type"], "diff")
            repo.close()

    def test_manual_replay_saves_sanitized_exchange(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))

            class FakeResponse:
                status_code = 202
                headers = {"Content-Type": "text/plain", "Set-Cookie": "sessionid=secret"}
                text = "accepted"

            with patch("api_server._storage_repo", return_value=repo), patch(
                "api_server.requests.request", return_value=FakeResponse()
            ) as replay:
                client = app.test_client()
                response = client.post(
                    "/api/manual/replay",
                    json={
                        "method": "POST",
                        "url": "https://app.example.test/api/replay",
                        "headers": {"Authorization": "Bearer secret-token-value"},
                        "body": "marker=1",
                        "source": "fuzzer",
                    },
                )

                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertTrue(payload["scan_id"].startswith("manual_"))
                self.assertEqual(payload["response"]["status_code"], 202)
                self.assertEqual(payload["request"]["headers"]["Authorization"], "[REDACTED]")
                replay.assert_called_once()

                saved = repo.list_requests(payload["scan_id"], {"source": "fuzzer"})
                self.assertEqual(len(saved), 1)
                self.assertEqual(saved[0]["headers"]["Authorization"], "[REDACTED]")
            repo.close()

    def test_proof_task_and_evidence_listing_endpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            scan = ScanConfig(scan_id="scan-proof", target_base_url="https://app.example.test")
            repo.create_scan(scan)
            finding = Finding.from_legacy(
                {
                    "type": "open-redirect",
                    "url": "https://app.example.test/login?next=/dashboard",
                    "param": "next",
                    "evidence": "redirect candidate",
                    "confidence": 95,
                },
                target_url=scan.target_base_url,
                scan_id=scan.scan_id,
            )
            repo.save_finding(finding)
            task = ProofTask(
                task_id="",
                finding_id=finding.finding_id,
                safety_mode="safe",
                allowed_techniques=["open_redirect_controlled_redirect"],
                status="completed",
                result="succeeded",
            )
            repo.save_proof_task(task)
            artifact = EvidenceArtifact(
                artifact_id="",
                finding_id=finding.finding_id,
                task_id=task.task_id,
                artifact_type="diff",
                inline_excerpt="redirect Location header changed",
            )
            repo.save_evidence_artifact(artifact)

            with patch("api_server._storage_repo", return_value=repo):
                client = app.test_client()
                tasks = client.get(f"/api/proof/tasks?finding_id={finding.finding_id}")
                self.assertEqual(tasks.status_code, 200)
                self.assertEqual(tasks.get_json()["count"], 1)
                self.assertEqual(tasks.get_json()["tasks"][0]["task_id"], task.task_id)

                artifacts = client.get(f"/api/evidence/artifacts?task_id={task.task_id}")
                self.assertEqual(artifacts.status_code, 200)
                self.assertEqual(artifacts.get_json()["count"], 1)
                self.assertEqual(artifacts.get_json()["artifacts"][0]["artifact_type"], "diff")
            repo.close()

    def test_manual_replay_blocks_destructive_methods_in_safe_mode(self):
        with patch("api_server._storage_repo", return_value=None):
            client = app.test_client()
            response = client.post(
                "/api/manual/replay",
                json={"method": "DELETE", "url": "https://app.example.test/api/item/1"},
            )
            self.assertEqual(response.status_code, 400)

    def test_manual_proxy_lifecycle_endpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            client = app.test_client()
            with patch("api_server._storage_repo", return_value=repo):
                start = client.post(
                    "/api/manual/proxy/start",
                    json={
                        "scan_id": "proxy-api",
                        "target_base_url": "http://127.0.0.1:5000",
                        "scope": ["http://127.0.0.1:5000"],
                        "port": 0,
                    },
                )
                self.assertEqual(start.status_code, 200)
                self.assertTrue(start.get_json()["running"])

                intercept = client.post("/api/manual/proxy/intercept", json={"enabled": True})
                self.assertEqual(intercept.status_code, 200)
                self.assertTrue(intercept.get_json()["intercept_enabled"])

                status = client.get("/api/manual/proxy/status")
                self.assertEqual(status.status_code, 200)
                self.assertEqual(status.get_json()["scan_id"], "proxy-api")

                pending = client.get("/api/manual/proxy/pending")
                self.assertEqual(pending.status_code, 200)
                self.assertEqual(pending.get_json()["count"], 0)

                stop = client.post("/api/manual/proxy/stop")
                self.assertEqual(stop.status_code, 200)
                self.assertFalse(stop.get_json()["running"])
            repo.close()


if __name__ == "__main__":
    unittest.main()
