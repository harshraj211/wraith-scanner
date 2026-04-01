import importlib
import py_compile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


class StartupSmokeTests(unittest.TestCase):
    def test_core_entrypoints_compile(self):
        targets = [
            REPO_ROOT / "main.py",
            REPO_ROOT / "api_server.py",
            REPO_ROOT / "scanner" / "utils" / "waf_evasion.py",
            REPO_ROOT / "scanner" / "modules" / "xss_scanner.py",
            REPO_ROOT / "scanner" / "modules" / "path_traversal_scanner.py",
        ]

        for path in targets:
            py_compile.compile(str(path), doraise=True)

    def test_core_entrypoints_import(self):
        modules = [
            "main",
            "api_server",
            "scanner.modules.xss_scanner",
            "scanner.modules.sqli_scanner",
            "scanner.modules.path_traversal_scanner",
            "scanner.modules.semgrep_scanner",
        ]

        for module_name in modules:
            imported = importlib.import_module(module_name)
            self.assertIsNotNone(imported)

    def test_xss_scanner_exposes_stored_xss_sweep(self):
        module = importlib.import_module("scanner.modules.xss_scanner")
        self.assertTrue(hasattr(module.XSSScanner, "check_stored"))


if __name__ == "__main__":
    unittest.main()
