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
                    headers={
                        "Content-Type": "text/html",
                        "Set-Cookie": "session=abc123; Path=/",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true",
                    },
                    body="<html><title>App</title></html>",
                ))

                result = run_passive_checks(repo, scan.scan_id)

                self.assertGreaterEqual(result["count"], 7)
                titles = {finding["title"] for finding in result["findings"]}
                self.assertIn("Missing Content-Security-Policy header", titles)
                self.assertIn("Missing HSTS header", titles)
                self.assertIn("Cookie missing Secure flag", titles)
                self.assertIn("Cookie missing HttpOnly flag", titles)
                self.assertIn("Credentialed wildcard CORS", titles)
                self.assertIn("Sensitive response may be cacheable", titles)
                stored_headers = repo.list_findings(scan.scan_id, {"vuln_type": "header-missing"})
                self.assertGreaterEqual(len(stored_headers), 3)


if __name__ == "__main__":
    unittest.main()
