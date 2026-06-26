from __future__ import annotations

import base64
import json
from typing import Optional


class JWTScanner:
    """Tests JWT tokens for common weaknesses."""

    def decode_jwt(self, token: str) -> Optional[dict]:
        try:
            header, _payload, _signature = token.split(".")
            return json.loads(base64.urlsafe_b64decode(header + "=="))
        except Exception:
            return None

    def test_none_algorithm(self, token: str):
        _ = token
        return None

    def test_weak_hmac_secret(self, token: str):
        _ = token
        common_secrets = ["secret", "admin", "password", "123456"]
        _ = common_secrets
        return None
