import unittest

from scanner.modules.sast_scanner import SASTScanner


class SASTSecretDetectionTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SASTScanner()

    def test_detects_json_style_api_key(self):
        content = '{"apiKey": "super-secret-key-123456789"}'
        findings = self.scanner._scan_secrets(content, "config.json")

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "hardcoded-api-key")

    def test_detects_env_style_unquoted_secret(self):
        content = "JWT_SECRET=VerySecretValue123ABCxyz"
        findings = self.scanner._scan_secrets(content, ".env")

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "hardcoded-token")

    def test_detects_multiline_private_key_block_once(self):
        content = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArandomcontent1234567890
anotherlineofkeymaterial0987654321
-----END RSA PRIVATE KEY-----"""
        findings = self.scanner._scan_secrets(content, "id_rsa")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "private-key")
        self.assertEqual(findings[0]["line"], 1)

    def test_detects_high_entropy_contextual_token(self):
        content = 'ACCESS_TOKEN = "AbCdEf1234567890GhIjKlMn+/="'
        findings = self.scanner._scan_secrets(content, "settings.py")

        self.assertTrue(any(f["type"] == "hardcoded-token" for f in findings))

    def test_ignores_high_entropy_non_secret_identifier(self):
        content = 'BUILD_ID = "AbCdEf1234567890GhIjKlMn+/="'
        findings = self.scanner._scan_secrets(content, "settings.py")

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
