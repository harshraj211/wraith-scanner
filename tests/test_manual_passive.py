import tempfile
import unittest
from pathlib import Path

from scanner.core.models import RequestRecord, ResponseRecord, ScanConfig
from scanner.manual.passive import run_passive_checks
from scanner.storage.repository import StorageRepository


class ManualPassiveTests(unittest.TestCase):
    def test_passive_checks_create_header_findings_from_corpus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with StorageRepository(str(Path(tmpdir) / "wraith.sqlite3")) as repo:
                scan = ScanConfig(scan_id="passive-scan", target_base_url="https://app.example")
                repo.create_scan(scan)
                request = RequestRecord.create(
                    scan_id=scan.scan_id,
                    source="proxy",
                    method="GET",
                    url="https://app.example/dashboard",
                    headers={},
                    auth_role="manual",
                )
                repo.save_request(request)
                repo.save_response(ResponseRecord.create(
                    request_id=request.request_id,
                    status_code=200,
                    headers={"Content-Type": "text/html"},
                    body="<html><title>App</title></html>",
                ))

                result = run_passive_checks(repo, scan.scan_id)

                self.assertGreaterEqual(result["count"], 3)
                titles = {finding["title"] for finding in result["findings"]}
                self.assertIn("Missing Content-Security-Policy header", titles)
                self.assertIn("Missing HSTS header", titles)
                stored = repo.list_findings(scan.scan_id, {"vuln_type": "header-missing"})
                self.assertEqual(len(stored), result["count"])


if __name__ == "__main__":
    unittest.main()
