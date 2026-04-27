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


if __name__ == "__main__":
    unittest.main()
