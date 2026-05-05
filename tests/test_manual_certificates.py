import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography import x509

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

    def test_ca_manager_generates_scoped_leaf_certificate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = WraithCAManager(Path(tmpdir) / "certs")
            missing = manager.leaf_status("https://app.example.test:8443/login")
            self.assertFalse(missing.generated)
            self.assertFalse(missing.can_generate)

            manager.generate()
            leaf = manager.generate_leaf_certificate("https://app.example.test:8443/login")
            payload = leaf.to_dict()
            self.assertTrue(leaf.generated)
            self.assertEqual(leaf.hostname, "app.example.test")
            self.assertTrue(Path(leaf.certificate_path).exists())
            self.assertNotIn(".key", json.dumps(payload))
            self.assertEqual(len(leaf.fingerprint_sha256), 64)

            cert = x509.load_pem_x509_certificate(Path(leaf.certificate_path).read_bytes())
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertIn("app.example.test", names.get_values_for_type(x509.DNSName))

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

    def test_ca_api_generates_leaf_certificate_after_ca_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = WraithCAManager(Path(tmpdir) / "certs")
            client = app.test_client()
            with patch("api_server.manual_ca", manager):
                blocked = client.post("/api/manual/proxy/ca/leaf/generate", json={"host": "api.example.test"})
                self.assertEqual(blocked.status_code, 409)
                self.assertFalse(blocked.get_json()["generated"])

                client.post("/api/manual/proxy/ca/generate", json={})
                generated = client.post("/api/manual/proxy/ca/leaf/generate", json={"host": "api.example.test"})
                self.assertEqual(generated.status_code, 200)
                self.assertTrue(generated.get_json()["generated"])
                self.assertEqual(generated.get_json()["hostname"], "api.example.test")

                status = client.get("/api/manual/proxy/ca/leaf/status?host=api.example.test")
                self.assertEqual(status.status_code, 200)
                self.assertTrue(status.get_json()["generated"])


if __name__ == "__main__":
    unittest.main()
