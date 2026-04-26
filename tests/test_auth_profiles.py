import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

import requests
from flask import Flask, request
from werkzeug.serving import make_server

from scanner.core.models import AuthProfile
from scanner.utils.auth_manager import AuthManager
from scanner.utils.auth_profiles import (
    apply_auth_profile_to_session,
    apply_playwright_storage_state_to_session,
    build_auth_profile_from_config,
    check_session,
    playwright_context_kwargs,
    storage_from_playwright_state,
)


@contextmanager
def run_health_app():
    app = Flask(__name__)

    @app.route("/health")
    def health():
        if request.headers.get("Authorization") == "Bearer test-token":
            return "<html><title>ok</title><main id='dashboard'>Authenticated Dashboard</main></html>"
        return "Login required", 401

    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


class AuthProfileTests(unittest.TestCase):
    def test_build_and_apply_static_header_cookie_profile(self):
        profile = build_auth_profile_from_config(
            {
                "type": "header",
                "role": "user_a",
                "headers": {"X-API-Key": "secret-key"},
                "cookies": {"sessionid": "session-value"},
            },
            base_url="https://app.example.test",
        )
        session = requests.Session()
        result = apply_auth_profile_to_session(profile, session)

        self.assertTrue(result.applied)
        self.assertEqual(profile.role, "user_a")
        self.assertEqual(session.headers["X-API-Key"], "secret-key")
        self.assertEqual(session.cookies.get("sessionid"), "session-value")

    def test_bearer_profile_sets_authorization_header(self):
        profile = build_auth_profile_from_config(
            {"type": "bearer", "token": "test-token", "role": "api"},
            base_url="https://api.example.test",
        )
        session = requests.Session()
        result = apply_auth_profile_to_session(profile, session)

        self.assertTrue(result.applied)
        self.assertEqual(session.headers["Authorization"], "Bearer test-token")

    def test_playwright_storage_state_promotes_cookies_and_local_storage_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "storage_state.json"
            state = {
                "cookies": [
                    {
                        "name": "sessionid",
                        "value": "cookie-value",
                        "domain": "app.example.test",
                        "path": "/",
                    }
                ],
                "origins": [
                    {
                        "origin": "https://app.example.test",
                        "localStorage": [
                            {
                                "name": "authState",
                                "value": json.dumps(
                                    {
                                        "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
                                    }
                                ),
                            }
                        ],
                    }
                ],
            }
            state_path.write_text(json.dumps(state), encoding="utf-8")

            session = requests.Session()
            result = apply_playwright_storage_state_to_session(
                str(state_path),
                session,
                base_url="https://app.example.test",
            )

        self.assertTrue(result.applied)
        self.assertEqual(session.cookies.get("sessionid"), "cookie-value")
        self.assertEqual(
            session.headers["Authorization"],
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        )

    def test_playwright_context_kwargs_reuses_existing_storage_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text("{}", encoding="utf-8")
            profile = AuthProfile(
                profile_id="",
                name="browser",
                base_url="https://app.example.test",
                role="user",
                auth_type="playwright_storage",
                storage_state_path=str(state_path),
            )

            self.assertEqual(playwright_context_kwargs(profile), {"storage_state": str(state_path)})

    def test_session_health_check_uses_profile_auth_and_selector(self):
        with run_health_app() as base_url:
            profile = build_auth_profile_from_config(
                {
                    "type": "bearer",
                    "token": "test-token",
                    "role": "user_a",
                    "session_health_check": {
                        "health_check_url": f"{base_url}/health",
                        "expected_status": 200,
                        "expected_text": "Authenticated Dashboard",
                        "expected_selector": "#dashboard",
                        "negative_text": "Login required",
                    },
                },
                base_url=base_url,
            )
            result = check_session(profile, timeout=5)

        self.assertTrue(result.healthy)
        self.assertEqual(result.status_code, 200)

    def test_session_health_check_reports_unhealthy_when_negative_text_matches(self):
        with run_health_app() as base_url:
            profile = AuthProfile(
                profile_id="",
                name="bad",
                base_url=base_url,
                role="anonymous",
                auth_type="anonymous",
                session_health_check={
                    "health_check_url": f"{base_url}/health",
                    "negative_text": "Login required",
                },
            )
            result = check_session(profile, timeout=5)

        self.assertEqual(result.status, "unhealthy")
        self.assertIn("negative text", result.reason)

    def test_auth_manager_applies_profile_to_shared_session(self):
        auth = AuthManager()
        profile = build_auth_profile_from_config(
            {"type": "bearer", "token": "test-token", "role": "api"},
            base_url="https://api.example.test",
        )
        result = auth.apply_auth_profile(profile)

        self.assertTrue(result.applied)
        self.assertTrue(auth.is_authenticated)
        self.assertEqual(auth.get_session().headers["Authorization"], "Bearer test-token")

    def test_storage_from_playwright_state_filters_origin(self):
        state = {
            "origins": [
                {
                    "origin": "https://wrong.example.test",
                    "localStorage": [{"name": "token", "value": "wrong"}],
                },
                {
                    "origin": "https://app.example.test",
                    "localStorage": [{"name": "token", "value": "right"}],
                },
            ]
        }

        storage = storage_from_playwright_state(state, base_url="https://app.example.test")

        self.assertEqual(storage["localStorage"], {"token": "right"})


if __name__ == "__main__":
    unittest.main()

