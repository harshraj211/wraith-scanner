import unittest

from desktop.wraith_desktop import api_server_path, frontend_build_dir, project_root


class DesktopLauncherTests(unittest.TestCase):
    def test_project_root_points_to_repo(self):
        root = project_root()
        self.assertTrue((root / "api_server.py").exists())

    def test_expected_runtime_paths(self):
        root = project_root()
        self.assertEqual(api_server_path(root), root / "api_server.py")
        self.assertEqual(frontend_build_dir(root), root / "scanner-terminal" / "build")


if __name__ == "__main__":
    unittest.main()
