import threading
import time
import unittest
from contextlib import contextmanager

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from scanner.modules.race_scanner import RaceConditionScanner


@contextmanager
def run_app(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def build_race_app():
    app = Flask(__name__)
    state = {"redeemed": 0}

    @app.route("/api/redeem", methods=["POST"])
    def redeem():
        payload = request.get_json(silent=True) or {}
        if payload.get("coupon") != "RACE":
            return jsonify({"status": "invalid"}), 400

        snapshot = state["redeemed"]
        time.sleep(0.15)
        if snapshot == 0:
            state["redeemed"] += 1
            return jsonify({"status": "redeemed", "count": state["redeemed"]})
        return jsonify({"status": "already redeemed"}), 409

    return app


class RaceScannerTests(unittest.TestCase):
    def test_race_scanner_flags_parallel_redemption(self):
        with run_app(build_race_app()) as base_url:
            scanner = RaceConditionScanner(timeout=5, attempts=5, max_workers=5)
            findings = scanner.scan_form({
                "action": f"{base_url}/api/redeem",
                "method": "post",
                "content_type": "application/json",
                "body_format": "json",
                "inputs": [
                    {"name": "coupon", "value": "RACE"},
                ],
            })

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "race-condition")
        self.assertIn("parallel requests looked successful", findings[0]["evidence"].lower())


if __name__ == "__main__":
    unittest.main()
