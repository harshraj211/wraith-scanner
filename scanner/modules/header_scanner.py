"""
A05: Security Misconfiguration — HTTP Security Headers Scanner

Checks for missing or misconfigured security response headers.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests


# (header, recommended_value_hint, description, confidence)
REQUIRED_HEADERS = [
    ('X-Content-Type-Options',    'nosniff',
     'Missing X-Content-Type-Options. Browsers may MIME-sniff responses, enabling XSS.', 80),
    ('X-Frame-Options',           'DENY or SAMEORIGIN',
     'Missing X-Frame-Options. Page can be embedded in iframes (clickjacking risk).', 80),
    ('Content-Security-Policy',   'defined',
     'Missing Content-Security-Policy. No protection against XSS and data injection.', 85),
    ('Referrer-Policy',           'defined',
     'Missing Referrer-Policy. Full URLs may be leaked in Referer headers.', 70),
    ('Permissions-Policy',        'defined',
     'Missing Permissions-Policy (formerly Feature-Policy). Browser features unrestricted.', 65),
    ('X-XSS-Protection',          '0 or 1; mode=block',
     'Missing X-XSS-Protection header (legacy, but still checked by older browsers).', 60),
]

DANGEROUS_HEADER_VALUES = [
    ('Server',            r'.+',          'Server header discloses software version.', 60),
    ('X-Powered-By',      r'.+',          'X-Powered-By discloses technology stack.', 65),
    ('X-AspNet-Version',  r'.+',          'X-AspNet-Version discloses .NET version.', 70),
    ('X-Generator',       r'.+',          'X-Generator discloses CMS/framework version.', 65),
]


class HeaderScanner:
    """Scanner for A05: Security Misconfiguration via HTTP headers."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Check response headers for security misconfigurations."""
        findings = []
        print(f"Checking security headers on: {url}")

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"Header scan failed for {url}: {exc}")
            return findings

        headers = resp.headers

        # Missing required headers
        for header, hint, evidence, confidence in REQUIRED_HEADERS:
            if header.lower() not in {k.lower() for k in headers.keys()}:
                findings.append({
                    'vulnerable': True,
                    'type': 'header-missing',
                    'param': header,
                    'payload': 'N/A',
                    'evidence': evidence,
                    'confidence': confidence,
                    'url': url,
                })

        # Information-disclosing headers
        for header, pattern, evidence, confidence in DANGEROUS_HEADER_VALUES:
            value = headers.get(header, '')
            if value:
                findings.append({
                    'vulnerable': True,
                    'type': 'header-info-disclosure',
                    'param': header,
                    'payload': 'N/A',
                    'evidence': f'{evidence} Value: {value[:80]}',
                    'confidence': confidence,
                    'url': url,
                })

        # CSP quality check
        csp = headers.get('Content-Security-Policy', '')
        if csp:
            findings.extend(self._check_csp_quality(url, csp))

        # CORS misconfiguration
        findings.extend(self._check_cors(url, resp))

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []  # Header checks are URL-level

    def _check_csp_quality(self, url: str, csp: str) -> List[Dict[str, Any]]:
        findings = []
        csp_lower = csp.lower()

        if "'unsafe-inline'" in csp_lower:
            findings.append({
                'vulnerable': True,
                'type': 'header-weak-csp',
                'param': 'Content-Security-Policy',
                'payload': 'N/A',
                'evidence': "CSP contains 'unsafe-inline' which allows inline scripts — negates XSS protection.",
                'confidence': 85,
                'url': url,
            })

        if "'unsafe-eval'" in csp_lower:
            findings.append({
                'vulnerable': True,
                'type': 'header-weak-csp',
                'param': 'Content-Security-Policy',
                'payload': 'N/A',
                'evidence': "CSP contains 'unsafe-eval' which allows eval() — weakens XSS protection.",
                'confidence': 80,
                'url': url,
            })

        if 'default-src *' in csp_lower or "default-src 'none'" not in csp_lower and 'default-src' not in csp_lower:
            findings.append({
                'vulnerable': True,
                'type': 'header-weak-csp',
                'param': 'Content-Security-Policy',
                'payload': 'N/A',
                'evidence': "CSP missing or overly permissive default-src directive.",
                'confidence': 70,
                'url': url,
            })

        return findings

    def _check_cors(self, url: str, resp: requests.Response) -> List[Dict[str, Any]]:
        findings = []
        acao = resp.headers.get('Access-Control-Allow-Origin', '')

        if acao == '*':
            findings.append({
                'vulnerable': True,
                'type': 'header-cors-wildcard',
                'param': 'Access-Control-Allow-Origin',
                'payload': 'N/A',
                'evidence': 'CORS wildcard (*) allows any origin to read responses. Dangerous on authenticated endpoints.',
                'confidence': 75,
                'url': url,
            })

        # Check if CORS reflects arbitrary Origin
        try:
            probe_resp = self.session.get(
                url,
                headers={'Origin': 'https://evil.example.com'},
                timeout=self.timeout,
            )
            reflected_acao = probe_resp.headers.get('Access-Control-Allow-Origin', '')
            acac = probe_resp.headers.get('Access-Control-Allow-Credentials', '')

            if reflected_acao == 'https://evil.example.com' and acac.lower() == 'true':
                findings.append({
                    'vulnerable': True,
                    'type': 'header-cors-reflect-origin',
                    'param': 'Access-Control-Allow-Origin',
                    'payload': 'Origin: https://evil.example.com',
                    'evidence': (
                        'CORS reflects arbitrary Origin with Access-Control-Allow-Credentials: true. '
                        'Attacker can make credentialed cross-origin requests.'
                    ),
                    'confidence': 95,
                    'url': url,
                })
        except requests.RequestException:
            pass

        return findings