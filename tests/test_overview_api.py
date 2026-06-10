import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_server import DAST_MODULES, active_scans, app
from scanner.core.models import Finding, RequestRecord, ScanConfig
from scanner.storage.repository import StorageRepository


class OverviewApiTests(unittest.TestCase):
    def test_overview_returns_operator_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            scan = ScanConfig(scan_id="scan-overview", target_base_url="https://app.example.test")
            repo.create_scan(scan)
            repo.save_request(
                RequestRecord.create(
                    scan_id=scan.scan_id,
                    source="crawler",
                    method="GET",
                    url="https://app.example.test/admin",
                )
            )
            finding = Finding.from_legacy(
                {
                    "type": "xss",
                    "url": "https://app.example.test/search",
                    "param": "q",
                    "severity": "critical",
                    "confidence": 95,
                },
                target_url=scan.target_base_url,
                scan_id=scan.scan_id,
            )
            repo.save_finding(finding)

            previous_scans = dict(active_scans)
            active_scans.clear()
            active_scans["scan-overview"] = {
                "status": "completed",
                "target": scan.target_base_url,
                "mode": "dast",
                "scan_type": "DAST",
                "started_at": "2026-06-10T10:00:00+00:00",
                "completed_at": "2026-06-10T10:02:00+00:00",
                "canonical_findings": [finding.to_dict()],
                "total_vulnerabilities": 1,
                "report_path": "reports/scan-overview.pdf",
            }

            try:
                with patch("api_server._storage_repo", return_value=repo), patch(
                    "api_server._find_semgrep", return_value="semgrep"
                ):
                    response = app.test_client().get("/api/overview")
                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertEqual(payload["service"]["status"], "online")
                self.assertEqual(payload["storage"]["status"], "ready")
                self.assertEqual(payload["storage"]["scan_count"], 1)
                self.assertEqual(payload["storage"]["request_count"], 1)
                self.assertEqual(payload["storage"]["finding_count"], 1)
                self.assertEqual(payload["active_scans"]["completed"], 1)
                self.assertEqual(payload["active_scans"]["recent"][0]["scan_id"], "scan-overview")
                self.assertEqual(payload["risk"]["severity"]["critical"], 1)
                self.assertEqual(payload["capabilities"]["dast_module_count"], len(DAST_MODULES))
                self.assertTrue(payload["capabilities"]["semgrep"]["ready"])
            finally:
                active_scans.clear()
                active_scans.update(previous_scans)
                repo.close()


if __name__ == "__main__":
    unittest.main()
