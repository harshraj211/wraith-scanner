import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.modules.sast_scanner import SASTScanner


class SASTDependencyParserTests(unittest.TestCase):
    def _collect_packages(self, repo_path: str):
        captured = {}

        def fake_query(packages):
            captured["packages"] = packages
            return [[] for _ in packages]

        scanner = SASTScanner()
        with patch("scanner.modules.sast_scanner.query_osv", side_effect=fake_query):
            findings = scanner._scan_dependencies(repo_path)

        self.assertEqual(findings, [])
        return captured.get("packages", [])

    def test_package_lock_takes_precedence_over_package_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"dependencies":{"lodash":"^4.17.20"}}',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                '{"name":"demo","lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.20"}},"node_modules/lodash":{"version":"4.17.21"}}}',
                encoding="utf-8",
            )

            packages = self._collect_packages(tmp)

        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["name"], "lodash")
        self.assertEqual(packages[0]["version"], "4.17.21")
        self.assertTrue(packages[0]["file"].endswith("package-lock.json"))

    def test_poetry_lock_takes_precedence_over_pyproject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                """
[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
flask = "^3.0.0"
""".strip(),
                encoding="utf-8",
            )
            (root / "poetry.lock").write_text(
                """
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "flask"
version = "3.0.2"
""".strip(),
                encoding="utf-8",
            )

            packages = self._collect_packages(tmp)

        self.assertEqual(
            {(pkg["name"], pkg["version"]) for pkg in packages},
            {("requests", "2.31.0"), ("flask", "3.0.2")},
        )
        self.assertTrue(all(pkg["file"].endswith("poetry.lock") for pkg in packages))

    def test_parses_pyproject_go_mod_composer_and_pipfile_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                """
[project]
name = "demo"
version = "0.1.0"
dependencies = [
  "fastapi>=0.110.0",
  "uvicorn (==0.29.0)"
]
""".strip(),
                encoding="utf-8",
            )
            (root / "go.mod").write_text(
                """
module example.com/demo

require (
    github.com/gin-gonic/gin v1.9.1
)
""".strip(),
                encoding="utf-8",
            )
            (root / "composer.lock").write_text(
                """
{
  "packages": [
    {"name": "laravel/framework", "version": "v10.48.4"}
  ]
}
""".strip(),
                encoding="utf-8",
            )
            (root / "Pipfile.lock").write_text(
                """
{
  "default": {
    "requests": {"version": "==2.31.0"}
  }
}
""".strip(),
                encoding="utf-8",
            )

            packages = self._collect_packages(tmp)

        package_keys = {(pkg["ecosystem"], pkg["name"], pkg["version"]) for pkg in packages}
        self.assertIn(("PyPI", "fastapi", "0.110.0"), package_keys)
        self.assertIn(("PyPI", "uvicorn", "0.29.0"), package_keys)
        self.assertIn(("PyPI", "requests", "2.31.0"), package_keys)
        self.assertIn(("Go", "github.com/gin-gonic/gin", "1.9.1"), package_keys)
        self.assertIn(("Packagist", "laravel/framework", "10.48.4"), package_keys)


if __name__ == "__main__":
    unittest.main()
