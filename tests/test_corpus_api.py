import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_server import app
from scanner.core.models import Finding, RequestRecord, ResponseRecord, ScanConfig
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
                    },
                )

                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertTrue(payload["scan_id"].startswith("manual_"))
                self.assertEqual(payload["response"]["status_code"], 202)
                self.assertEqual(payload["request"]["headers"]["Authorization"], "[REDACTED]")
                replay.assert_called_once()

                saved = repo.list_requests(payload["scan_id"], {"source": "manual"})
                self.assertEqual(len(saved), 1)
                self.assertEqual(saved[0]["headers"]["Authorization"], "[REDACTED]")
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
