import tempfile
import unittest
from pathlib import Path

from scanner.integrations.template_trust import (
    apply_template_trust,
    load_template_trust,
    save_template_trust,
)


class TemplateTrustTests(unittest.TestCase):
    def test_save_and_load_template_trust_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "trust.json"
            saved = save_template_trust(
                {
                    "allowed_tags": ["cve", "exposure"],
                    "denied_tags": ["dos", "bruteforce"],
                    "allowed_template_paths": [str(Path(tmpdir) / "templates")],
                    "notes": "approved test templates",
                },
                path=path,
            )
            loaded = load_template_trust(path=path)

            self.assertEqual(saved.allowed_tags, loaded.allowed_tags)
            self.assertEqual(loaded.denied_tags, ["bruteforce", "dos"])
            self.assertIn("approved", loaded.notes)

    def test_apply_template_trust_filters_tags_and_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed = Path(tmpdir) / "allowed"
            blocked = Path(tmpdir) / "blocked"
            allowed.mkdir()
            blocked.mkdir()
            trust = save_template_trust(
                {
                    "allowed_tags": ["cve"],
                    "denied_tags": ["destructive", "dos"],
                    "allowed_template_paths": [str(allowed)],
                    "denied_template_paths": [str(blocked)],
                },
                path=Path(tmpdir) / "trust.json",
            )

            result = apply_template_trust(
                templates=[str(allowed / "http"), str(blocked / "bad.yaml")],
                tags=["cve", "rce"],
                exclude_tags=["fuzz"],
                config=trust,
            )

            self.assertEqual(result["tags"], ["cve"])
            self.assertIn("destructive", result["exclude_tags"])
            self.assertIn("dos", result["exclude_tags"])
            self.assertIn("fuzz", result["exclude_tags"])
            self.assertEqual(result["templates"], [str(allowed / "http")])
            self.assertEqual(result["blocked_templates"], [str(blocked / "bad.yaml")])
            self.assertTrue(result["warnings"])


if __name__ == "__main__":
    unittest.main()
