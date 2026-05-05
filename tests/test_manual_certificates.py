import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_server import app
from scanner.manual.certificates import WraithCAManager


class ManualCertificateTests(unittest.TestCase):
    def test_ca_manager_generates_status_without_exporting_private_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = WraithCAManager(Path(tmpdir) / "certs")
            before = manager.status()
            self.assertTrue(before.available)
            self.assertFalse(before.generated)

            after = manager.generate()
            payload = after.to_dict()
            self.assertTrue(after.generated)
            self.assertTrue(after.https_interception_ready)
            self.assertTrue(Path(after.certificate_path).exists())
            self.assertTrue(manager.key_path.exists())
            self.assertNotIn(str(manager.key_path), json.dumps(payload))
            self.assertEqual(len(after.fingerprint_sha256), 64)

    def test_ca_api_status_generate_download_and_guide(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = WraithCAManager(Path(tmpdir) / "certs")
            client = app.test_client()
            with patch("api_server.manual_ca", manager):
                status_response = client.get("/api/manual/proxy/ca/status")
                self.assertEqual(status_response.status_code, 200)
                self.assertFalse(status_response.get_json()["generated"])

                generate_response = client.post("/api/manual/proxy/ca/generate", json={})
                self.assertEqual(generate_response.status_code, 200)
                self.assertTrue(generate_response.get_json()["generated"])

                guide_response = client.get("/api/manual/proxy/ca/guide")
                self.assertEqual(guide_response.status_code, 200)
                self.assertIn("steps", guide_response.get_json())

                download_response = client.get("/api/manual/proxy/ca/download")
                self.assertEqual(download_response.status_code, 200)
                self.assertIn("BEGIN CERTIFICATE", download_response.get_data(as_text=True))
                download_response.close()


if __name__ == "__main__":
    unittest.main()
