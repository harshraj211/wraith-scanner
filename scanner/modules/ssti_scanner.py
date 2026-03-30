"""
A03: Server-Side Template Injection (SSTI) Scanner

Tests parameters for template expression evaluation across
Jinja2, Twig, Freemarker, Velocity, and Smarty engines.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests
from scanner.utils.request_metadata import (
    build_request_context,
    form_request_parts,
    injectable_locations,
)


# Payloads that produce detectable output if evaluated
SSTI_PAYLOADS = [
    # Math expressions — engine-agnostic detection
    ('{{7*7}}',          '49',   'Jinja2/Twig expression evaluated'),
    ('${7*7}',           '49',   'Freemarker/Velocity expression evaluated'),
    ('<%= 7*7 %>',       '49',   'ERB/EJS expression evaluated'),
    ('{{7*\'7\'}}',      '7777777', 'Jinja2 string multiply — confirms Jinja2'),
    ('#{7*7}',           '49',   'Ruby/Slim expression evaluated'),
    ('{7*7}',            '49',   'Smarty expression evaluated'),
    ('*{7*7}',           '49',   'Spring SpEL expression evaluated'),
    ('%{7*7}',           '49',   'Freemarker alternate syntax'),
]


class SSTIScanner:
    """Scanner for Server-Side Template Injection."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        for param in params:
            print(f"Testing SSTI on: {param}")
            original = str(params.get(param, ''))
            result = self._probe_param(url, param, original, params, 'GET')
            if result:
                findings.append(result)
        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        action = form_data.get('action', '')
        method = (form_data.get('method') or 'GET').upper()
        if not action:
            return findings
        request_parts = form_request_parts(form_data)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, param in injectable_locations(body_fields, header_fields, cookie_fields):
            print(f"Testing SSTI on form param: {param}")
            result = self._probe_param(action, param, '', request_parts, method, body_format, location)
            if result:
                findings.append(result)
        return findings

    # ------------------------------------------------------------------
    # Async methods (native aiohttp — used by AsyncScanEngine v3)
    # ------------------------------------------------------------------

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings = []
        for param in params:
            original = str(params.get(param, ''))
            result = await self._probe_param_async(url, param, original, params, 'GET', http)
            if result:
                findings.append(result)
        return findings

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings = []
        action = form.get('action', '')
        method = (form.get('method') or 'GET').upper()
        if not action:
            return findings
        request_parts = form_request_parts(form)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, param in injectable_locations(body_fields, header_fields, cookie_fields):
            result = await self._probe_param_async(action, param, '', request_parts, method, http, body_format, location)
            if result:
                findings.append(result)
        return findings

    async def _probe_param_async(self, url, param, original, request_parts, method, http, body_format="form", target_location="body"):
        try:
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
            baseline_data, baseline_headers, baseline_cookies = build_request_context(
                body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                target_location, param, 'SSTI_BASELINE_12345'
            )
            baseline_resp = await self._send_async(http, url, method, baseline_data, baseline_headers, baseline_cookies, body_format)
            if not baseline_resp or 'SSTI_BASELINE_12345' not in (baseline_resp.text or ''):
                return None
        except Exception:
            return None

        for payload, expected, description in SSTI_PAYLOADS:
            try:
                data, headers, cookies = build_request_context(
                    body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                    target_location, param, payload
                )
                resp = await self._send_async(http, url, method, data, headers, cookies, body_format)
                if resp:
                    text = resp.text or ''
                    if expected in text:
                        return {
                            'vulnerable': True,
                            'type': 'ssti',
                            'param': param,
                            'payload': payload,
                            'evidence': f'{description}. Output "{expected}" found in response.',
                            'confidence': 95,
                            'url': url,
                        }
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------
    # Sync internals (kept for standalone / fallback use)
    # ------------------------------------------------------------------

    def _probe_param(
        self, url, param, original, request_parts, method, body_format="form", target_location="body"
    ) -> Optional[Dict[str, Any]]:
        # First get a baseline to detect reflected value
        try:
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
            baseline_data, baseline_headers, baseline_cookies = build_request_context(
                body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                target_location, param, 'SSTI_BASELINE_12345'
            )
            baseline_resp = self._send_sync(url, method, baseline_data, baseline_headers, baseline_cookies, body_format)

            # Parameter must be reflected for SSTI to be detectable
            if 'SSTI_BASELINE_12345' not in (baseline_resp.text or ''):
                return None  # Not reflected, skip — reduces false positives

        except requests.RequestException:
            return None

        # Now test payloads
        for payload, expected, description in SSTI_PAYLOADS:
            try:
                data, headers, cookies = build_request_context(
                    body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                    target_location, param, payload
                )

                resp = self._send_sync(url, method, data, headers, cookies, body_format)

                text = resp.text or ''
                if expected in text:
                    print(f"SSTI confirmed on {param}: {description}")
                    return {
                        'vulnerable': True,
                        'type': 'ssti',
                        'param': param,
                        'payload': payload,
                        'evidence': f'{description}. Output "{expected}" found in response.',
                        'confidence': 95,
                        'url': url,
                    }

            except requests.RequestException as exc:
                print(f"SSTI test failed on {param}: {exc}")

        return None

    def _form_body_format(self, form: Dict[str, Any]) -> str:
        if form.get("body_format") == "json":
            return "json"
        content_type = str(form.get("content_type", "")).lower()
        if "application/json" in content_type:
            return "json"
        return "form"

    def _send_sync(self, url: str, method: str, data: Dict[str, Any], headers: Dict[str, str], cookies: Dict[str, str], body_format: str):
        if method.upper() == 'GET':
            return self.session.get(url, params=data, headers=headers or None, cookies=cookies or None, timeout=self.timeout)
        if body_format == "json":
            return self.session.request(
                method.upper(),
                url,
                json=data,
                timeout=self.timeout,
                headers={**(headers or {}), "Content-Type": "application/json"},
                cookies=cookies or None,
            )
        return self.session.request(method.upper(), url, data=data, headers=headers or None, cookies=cookies or None, timeout=self.timeout)

    async def _send_async(self, http, url: str, method: str, data: Dict[str, Any], headers: Dict[str, str], cookies: Dict[str, str], body_format: str):
        if method.upper() == 'GET':
            return await http.get(url, params=data, headers=headers or None, cookies=cookies or None)
        if body_format == "json":
            return await http.request(
                method.upper(),
                url,
                json=data,
                headers={**(headers or {}), "Content-Type": "application/json"},
                cookies=cookies or None,
            )
        return await http.request(method.upper(), url, data=data, headers=headers or None, cookies=cookies or None)
