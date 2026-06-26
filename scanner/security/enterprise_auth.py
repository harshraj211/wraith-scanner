from __future__ import annotations

import functools

from flask import g, jsonify, request

API_KEYS = {
    "wraith_sec_key_123": {"role": "admin", "org": "WraithHQ"},
    "cicd_pipeline_key_456": {"role": "scanner", "org": "WraithHQ"},
}


def require_api_key(allowed_roles=["admin", "scanner"]):
    """Decorator to enforce API key authentication and RBAC."""

    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            api_key = request.headers.get("X-API-KEY")
            if not api_key or api_key not in API_KEYS:
                return jsonify({"error": "Invalid or missing API Key"}), 401

            user_context = API_KEYS[api_key]
            if user_context["role"] not in allowed_roles:
                return jsonify({"error": "Forbidden: Insufficient permissions"}), 403

            g.user = user_context
            return f(*args, **kwargs)

        return wrapped

    return decorator
