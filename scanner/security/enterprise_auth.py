from __future__ import annotations

import functools

from flask import g, jsonify, request

API_KEYS = {
    "wraith_sec_key_123": {"role": "admin", "tenant_id": "org_wraith_hq", "org": "WraithHQ"},
    "acme_corp_key_999": {"role": "scanner", "tenant_id": "org_acme_corp", "org": "AcmeCorp"},
    "cicd_pipeline_key_456": {"role": "scanner", "tenant_id": "org_acme_corp", "org": "AcmeCorp"},
}


def require_api_key(allowed_roles=["admin", "scanner"]):
    """Decorator to enforce API key authentication, RBAC, and Tenant isolation."""

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
            g.tenant_id = user_context["tenant_id"]
            g.role = user_context["role"]
            return f(*args, **kwargs)

        return wrapped

    return decorator
