"""
A05: Security Misconfiguration — HTTP Security Headers Scanner

Checks for missing or misconfigured security response headers.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

# Version pattern: matches things like Apache/2.4.51, nginx/1.21.6, PHP/8.1.2
_VERSION_RE = re.compile(r'\d+\.\d+(?:\.\d+)?')


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

        # Information-disclosing headers — version-specific vs generic
        # Cloud providers / CDN names that carry no exploitable info
        _GENERIC_SERVERS = {
            'vercel', 'cloudflare', 'netlify', 'heroku', 'aws',
            'amazons3', 'gws', 'gse', 'cloudfront', 'akamai',
            'fastly', 'fly', 'railway', 'render', 'digitalocean',
        }

        for header, pattern, evidence, confidence in DANGEROUS_HEADER_VALUES:
            value = headers.get(header, '')
            if value:
                has_version = bool(_VERSION_RE.search(value))
                is_generic_server = (
                    header.lower() == 'server'
                    and not has_version
                    and value.strip().lower().split('/')[0].split()[0] in _GENERIC_SERVERS
                )

                if is_generic_server:
                    # "Server: Vercel" — informational, not exploitable
                    findings.append({
                        'vulnerable': True,
                        'type': 'header-info-disclosure-generic',
                        'param': header,
                        'payload': 'N/A',
                        'evidence': f'Server header present but only discloses cloud/CDN provider. Value: {value[:80]}',
                        'confidence': 30,
                        'url': url,
                    })
                elif has_version:
                    # "Apache/2.4.51 (Ubuntu)" — version enables targeted exploits
                    findings.append({
                        'vulnerable': True,
                        'type': 'header-info-disclosure-versioned',
                        'param': header,
                        'payload': 'N/A',
                        'evidence': f'{evidence} Value: {value[:80]}',
                        'confidence': confidence,
                        'url': url,
                    })
                else:
                    # Generic non-cloud disclosure (e.g. "nginx" without version)
                    findings.append({
                        'vulnerable': True,
                        'type': 'header-info-disclosure-generic',
                        'param': header,
                        'payload': 'N/A',
                        'evidence': f'{evidence} Value: {value[:80]} (no version disclosed)',
                        'confidence': 40,
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
            # Check if endpoint appears to handle authentication
            has_auth_indicators = any([
                resp.headers.get('Set-Cookie', ''),
                'authorization' in (resp.headers.get('WWW-Authenticate', '').lower()),
                resp.headers.get('X-Auth-Token', ''),
            ])
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            # Wildcard + credentials is impossible per spec, so browsers block it.
            # On public endpoints without auth this is benign.
            if has_auth_indicators:
                findings.append({
                    'vulnerable': True,
                    'type': 'header-cors-wildcard',
                    'param': 'Access-Control-Allow-Origin',
                    'payload': 'N/A',
                    'evidence': (
                        'CORS wildcard (*) on an endpoint that sets authentication-related headers. '
                        'If the endpoint returns user-specific data, this is exploitable.'
                    ),
                    'confidence': 75,
                    'url': url,
                })
            else:
                findings.append({
                    'vulnerable': True,
                    'type': 'header-cors-wildcard-public',
                    'param': 'Access-Control-Allow-Origin',
                    'payload': 'N/A',
                    'evidence': (
                        'CORS wildcard (*) set on a public endpoint with no authentication indicators. '
                        'This is acceptable for public APIs and static content.'
                    ),
                    'confidence': 30,
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