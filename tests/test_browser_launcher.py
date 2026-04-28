import unittest

from scanner.manual.browser_launcher import WraithBrowserController, proxy_server_from_status


class BrowserLauncherTests(unittest.TestCase):
    def test_proxy_server_from_running_status(self):
        self.assertEqual(
            proxy_server_from_status({"running": True, "host": "127.0.0.1", "port": 8081}),
            "http://127.0.0.1:8081",
        )

    def test_proxy_server_ignores_stopped_status(self):
        self.assertEqual(proxy_server_from_status({"running": False, "port": 8081}), "")

    def test_open_requires_proxy_when_proxy_mode_enabled(self):
        controller = WraithBrowserController()
        result = controller.open(
            target_url="http://127.0.0.1:5000",
            scan_id="manual_test",
            use_proxy=True,
            proxy_status={"running": False},
        )

        self.assertFalse(result.ok)
        self.assertFalse(result.running)
        self.assertIn("Manual proxy is not running", result.error)


if __name__ == "__main__":
    unittest.main()
