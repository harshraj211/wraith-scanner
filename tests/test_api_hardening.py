import tempfile
import unittest
from pathlib import Path

from api_server import active_scans, app
from scanner.security.target_policy import TargetPolicyError, validate_http_target
from scanner.storage.repository import StorageRepository


class ApiHardeningTests(unittest.TestCase):
    def test_target_policy_blocks_private_targets_by_default(self):
        with self.assertRaises(TargetPolicyError):
            validate_http_target("http://127.0.0.1:5000")

        with self.assertRaises(TargetPolicyError):
            validate_http_target("http://169.254.169.254/latest/meta-data/")

    def test_target_policy_allows_private_targets_in_lab_mode(self):
        validate_http_target("http://127.0.0.1:5000", safety_mode="lab")

    def test_target_policy_allows_public_nat64_targets(self):
        validate_http_target("http://[64:ff9b::d8c6:4fc3]/", resolve_dns=False)

    def test_target_policy_blocks_private_nat64_targets(self):
        with self.assertRaises(TargetPolicyError):
            validate_http_target("http://[64:ff9b::7f00:1]/", resolve_dns=False)

    def test_scan_endpoint_rejects_private_target_before_launch(self):
        client = app.test_client()
        response = client.post(
            "/api/scan",
            json={"url": "http://127.0.0.1:5000", "auth": {"safety_mode": "safe"}},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("targets require lab mode", response.get_json()["error"])

    def test_manual_replay_rejects_private_target_before_request(self):
        client = app.test_client()
        response = client.post(
            "/api/manual/replay",
            json={"method": "GET", "url": "http://127.0.0.1:5000/admin"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("targets require lab mode", response.get_json()["error"])

    def test_download_rejects_report_path_outside_reports_directory(self):
        previous_scans = dict(active_scans)
        active_scans.clear()
        active_scans["escape-test"] = {
            "status": "completed",
            "target": "https://app.example.test",
            "report_path": str(Path(__file__).resolve()),
        }
        try:
            response = app.test_client().get("/api/download/escape-test")
            self.assertEqual(response.status_code, 404)
        finally:
            active_scans.clear()
            active_scans.update(previous_scans)

    def test_scan_state_persists_and_restores(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "wraith.sqlite3")
            repo = StorageRepository(db_path)
            repo.save_scan_state("scan-state", {
                "status": "completed",
                "target": "https://app.example.test",
                "mode": "dast",
                "total_vulnerabilities": 2,
            })
            repo.close()

            reopened = StorageRepository(db_path)
            state = reopened.get_scan_state("scan-state")
            states = reopened.list_scan_states()
            self.assertEqual(state["status"], "completed")
            self.assertEqual(states["scan-state"]["total_vulnerabilities"], 2)
            reopened.close()


if __name__ == "__main__":
    unittest.main()
