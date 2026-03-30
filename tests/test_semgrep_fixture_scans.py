import shutil
import tempfile
import unittest
from pathlib import Path

from scanner.modules.semgrep_scanner import SemgrepScanner


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "semgrep"


class SemgrepFixtureScanTests(unittest.TestCase):
    def _scan_fixture(self, fixture_name: str, language: str):
        scanner = SemgrepScanner()
        if not scanner.check_semgrep_installed():
            self.skipTest("semgrep is not installed in this environment")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            shutil.copy2(FIXTURES_DIR / fixture_name, tmp_path / fixture_name)
            findings = scanner.scan_repo(str(tmp_path), {"primary_language": language})

        self.assertTrue(findings, "expected at least one semgrep finding from fixture")
        return findings

    def test_python_fixture_hits_expected_custom_rules(self):
        findings = self._scan_fixture("python_fixture_app.py", "python")
        rule_ids = {finding["rule_id"] for finding in findings}

        self.assertTrue(
            {
                "custom-python-template-xss",
                "custom-python-open-redirect",
                "custom-python-ssrf-request-input",
                "custom-python-path-traversal-request-input",
                "custom-python-sqli-string-build",
                "custom-python-unsafe-deserialization",
                "custom-python-weak-password-hash",
            }.issubset(rule_ids)
        )

    def test_javascript_fixture_hits_expected_custom_rules(self):
        findings = self._scan_fixture("javascript_fixture_app.js", "javascript")
        rule_ids = {finding["rule_id"] for finding in findings}

        self.assertTrue(
            {
                "custom-express-reflected-xss",
                "custom-express-open-redirect",
                "custom-express-ssrf",
                "custom-express-path-traversal",
                "custom-express-sqli",
            }.issubset(rule_ids)
        )


if __name__ == "__main__":
    unittest.main()
