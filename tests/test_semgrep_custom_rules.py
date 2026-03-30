import tempfile
import unittest
from pathlib import Path

from scanner.modules.semgrep_scanner import CUSTOM_RULES, SemgrepScanner


class SemgrepCustomRulesTests(unittest.TestCase):
    def test_custom_rules_include_new_python_web_rules(self):
        expected_rule_ids = [
            "custom-python-template-xss",
            "custom-python-open-redirect",
            "custom-python-ssrf-request-input",
            "custom-python-path-traversal-request-input",
            "custom-python-sqli-string-build",
            "custom-python-unsafe-deserialization",
            "custom-python-weak-password-hash",
        ]

        for rule_id in expected_rule_ids:
            self.assertIn(f"- id: {rule_id}", CUSTOM_RULES)

    def test_write_custom_rules_persists_new_rules(self):
        scanner = SemgrepScanner()
        with tempfile.TemporaryDirectory() as tmp:
            path = scanner._write_custom_rules(tmp)
            self.assertIsNotNone(path)
            content = Path(path).read_text(encoding="utf-8")

        self.assertIn("custom-python-open-redirect", content)
        self.assertIn("custom-python-ssrf-request-input", content)

    def test_rule_type_mapping_covers_new_rules(self):
        scanner = SemgrepScanner()
        self.assertEqual(scanner._map_rule_to_type("custom-python-open-redirect", {}), "redirect")
        self.assertEqual(scanner._map_rule_to_type("custom-python-ssrf-request-input", {}), "ssrf")
        self.assertEqual(scanner._map_rule_to_type("custom-python-path-traversal-request-input", {}), "path-traversal")
        self.assertEqual(scanner._map_rule_to_type("custom-python-unsafe-deserialization", {}), "deserialization")
        self.assertEqual(scanner._map_rule_to_type("custom-python-weak-password-hash", {}), "crypto")


if __name__ == "__main__":
    unittest.main()
