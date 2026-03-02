"""
A10: Server-Side Request Forgery (SSRF) Scanner

Injects internal/cloud metadata URLs into URL-like parameters
and detects responses indicating server-side fetches.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


# SSRF probe targets — internal/metadata endpoints
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS EC2 metadata
    "http://169.254.169.254/computeMetadata/v1/",     # GCP metadata
    "http://169.254.169.254/metadata/instance",       # Azure metadata
    "http://127.0.0.1/",                              # localhost
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",                                  # IPv6 localhost
    "http://internal/",
    "http://192.168.0.1/",                            # LAN gateway
    "http://10.0.0.1/",
]

# Indicators of successful SSRF in response
SSRF_INDICATORS = [
    r'"instanceId"',           # AWS/GCP metadata
    r'"privateIp"',
    r'"hostname":\s*"[^"]+',
    r'ami-[a-z0-9]+',          # AWS AMI ID
    r'local-ipv4',
    r'instance-id',
    r'computeMetadata',
    r'<title>.*Apache.*</title>',  # Internal Apache
    r'<title>.*nginx.*</title>',
    r'root:.*:/bin/',          # Internal service leaking /etc/passwd
]

# Parameter names likely to hold URLs
URL_PARAM_NAMES = [
    'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
    'path', 'redirect', 'endpoint', 'target', 'fetch', 'load',
    'file', 'image', 'img', 'document', 'resource', 'proxy',
    'callback', 'webhook', 'next', 'return', 'goto',
]


class SSRFScanner:
    """Scanner for A10: Server-Side Request Forgery."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test URL parameters for SSRF."""
        findings = []
        ssrf_params = self._identify_ssrf_params(params)

        for param in ssrf_params:
            print(f"Testing SSRF on parameter: {param}")
            for payload in SSRF_PAYLOADS:
                result = self._test_ssrf(url, param, params, payload, method='GET')
                if result:
                    findings.append(result)
                    break  # Move to next param once confirmed

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for SSRF."""
        findings = []
        action = form_data.get('action', '')
        method = (form_data.get('method') or 'GET').upper()
        inputs = form_data.get('inputs', [])

        if not action or not inputs:
            return findings

        baseline = {inp.get('name', ''): '' for inp in inputs if inp.get('name')}
        ssrf_params = self._identify_ssrf_params(baseline)

        for param in ssrf_params:
            print(f"Testing SSRF on form param: {param}")
            for payload in SSRF_PAYLOADS:
                result = self._test_ssrf(action, param, baseline, payload, method=method)
                if result:
                    findings.append(result)
                    break

        return findings

    def _identify_ssrf_params(self, params: Dict[str, Any]) -> List[str]:
        """Find parameters likely to accept URLs."""
        found = []
        for name, value in params.items():
            name_lower = name.lower()
            if any(kw in name_lower for kw in URL_PARAM_NAMES):
                found.append(name)
                continue
            if value and isinstance(value, str):
                sv = value.strip()
                if sv.startswith(('http://', 'https://', '//')):
                    found.append(name)
        return found

    def _test_ssrf(
        self,
        url: str,
        param: str,
        params: Dict[str, Any],
        payload: str,
        method: str = 'GET',
    ) -> Optional[Dict[str, Any]]:
        """Inject SSRF payload and check response for indicators."""
        try:
            data = params.copy()
            data[param] = payload

            if method.upper() == 'GET':
                resp = self.session.get(url, params=data, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=data, timeout=self.timeout)

            text = resp.text or ''
            status = resp.status_code

            for indicator in SSRF_INDICATORS:
                if re.search(indicator, text, re.IGNORECASE):
                    print(f"SSRF confirmed on {param} with payload {payload}")
                    return {
                        'vulnerable': True,
                        'type': 'ssrf',
                        'param': param,
                        'payload': payload,
                        'evidence': f'Response contains internal indicator: {indicator}',
                        'confidence': 90,
                        'url': url,
                    }

            # Heuristic: server fetched the URL if response contains expected content
            # from well-known internal endpoints
            if status == 200 and any(kw in text.lower() for kw in [
                'instance', 'metadata', 'internal', 'localhost'
            ]):
                return {
                    'vulnerable': True,
                    'type': 'ssrf',
                    'param': param,
                    'payload': payload,
                    'evidence': f'Possible SSRF: status 200 with internal content keywords in response',
                    'confidence': 65,
                    'url': url,
                }

        except requests.RequestException as exc:
            print(f"SSRF test failed for {param}: {exc}")

        return None