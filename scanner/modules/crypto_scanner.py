"""
A02: Cryptographic Failures Scanner

Checks: HTTP vs HTTPS, HSTS, insecure cookies, weak TLS, 
sensitive data exposure, mixed content, HTTP form submissions.
"""
from __future__ import annotations

import re
import ssl
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


SENSITIVE_DATA_PATTERNS = [
    (r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+', 'Plaintext password in response'),
    (r'\b(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', 'API key exposed'),
    (r'\b(?:secret|token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', 'Secret/token exposed'),
    (r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})', 'Credit card number detected'),
    (r'\bSSN\s*[:=]?\s*\d{3}-\d{2}-\d{4}\b', 'SSN pattern detected'),
]

WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'IDEA', 'RC2']


class CryptoScanner:
    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        findings = []
        parsed = urlparse(url)
        print(f"Running crypto checks on: {url}")

        findings.extend(self._check_http_usage(url, parsed))

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"Failed to fetch {url} for crypto checks: {exc}")
            return findings

        findings.extend(self._check_hsts(url, resp, parsed))
        findings.extend(self._check_cookie_security(url, resp, parsed))
        findings.extend(self._check_sensitive_data(url, resp))
        findings.extend(self._check_mixed_content(url, resp, parsed))

        if parsed.scheme == 'https':
            findings.extend(self._check_tls_config(url, parsed))
        if parsed.scheme == 'http':
            findings.extend(self._check_https_redirect(url))

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        action = form_data.get('action', '')
        method = (form_data.get('method') or 'GET').upper()
        if method == 'POST' and action.startswith('http://'):
            return [{
                'vulnerable': True,
                'type': 'crypto-http-form-submission',
                'param': 'form-action',
                'payload': 'N/A',
                'evidence': f'POST form submits data over unencrypted HTTP: {action}',
                'confidence': 95,
                'url': action,
            }]
        return []

    def _check_http_usage(self, url, parsed):
        if parsed.scheme == 'http':
            return [{
                'vulnerable': True,
                'type': 'crypto-plaintext-http',
                'param': 'scheme',
                'payload': 'N/A',
                'evidence': 'Site served over unencrypted HTTP. Traffic visible to network attackers.',
                'confidence': 100,
                'url': url,
            }]
        return []

    def _check_https_redirect(self, url):
        findings = []
        https_url = url.replace('http://', 'https://', 1)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            loc = resp.headers.get('Location', '')
            if resp.status_code not in (301, 302, 307, 308) or 'https://' not in loc:
                try:
                    self.session.get(https_url, timeout=self.timeout)
                    findings.append({
                        'vulnerable': True,
                        'type': 'crypto-no-https-redirect',
                        'param': 'redirect',
                        'payload': 'N/A',
                        'evidence': f'HTTP does not redirect to HTTPS. HTTPS available at {https_url}.',
                        'confidence': 90,
                        'url': url,
                    })
                except Exception:
                    pass
        except requests.RequestException:
            pass
        return findings

    def _check_hsts(self, url, resp, parsed):
        if parsed.scheme != 'https':
            return []
        hsts = resp.headers.get('Strict-Transport-Security', '')
        if not hsts:
            return [{
                'vulnerable': True,
                'type': 'crypto-missing-hsts',
                'param': 'Strict-Transport-Security',
                'payload': 'N/A',
                'evidence': 'HSTS header absent. HTTP downgrade (MITM) attacks possible.',
                'confidence': 90,
                'url': url,
            }]
        match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
        if match and int(match.group(1)) < 31536000:
            return [{
                'vulnerable': True,
                'type': 'crypto-weak-hsts',
                'param': 'Strict-Transport-Security',
                'payload': 'N/A',
                'evidence': f'HSTS max-age={match.group(1)}s < 31536000s (1 year). Short duration weakens protection.',
                'confidence': 80,
                'url': url,
            }]
        return []

    def _check_cookie_security(self, url, resp, parsed):
        findings = []
        keywords = {'session', 'sess', 'auth', 'token', 'jwt', 'login', 'user', 'id'}
        raw_sc = resp.headers.get('Set-Cookie', '').lower()

        for cookie in resp.cookies:
            name_lower = cookie.name.lower()
            if not any(kw in name_lower for kw in keywords):
                continue

            issues = []
            rest = getattr(cookie, '_rest', {}) or {}

            if not cookie.secure and parsed.scheme == 'https':
                issues.append('missing Secure flag')

            if not (rest.get('HttpOnly') or rest.get('httponly') or 'httponly' in raw_sc):
                issues.append('missing HttpOnly flag (JS-accessible)')

            samesite = rest.get('SameSite') or rest.get('samesite') or ''
            if not samesite:
                issues.append('missing SameSite attribute')
            elif samesite.lower() == 'none' and not cookie.secure:
                issues.append('SameSite=None without Secure')

            if issues:
                findings.append({
                    'vulnerable': True,
                    'type': 'crypto-insecure-cookie',
                    'param': cookie.name,
                    'payload': 'N/A',
                    'evidence': f'Cookie "{cookie.name}": {"; ".join(issues)}',
                    'confidence': 85,
                    'url': url,
                })
        return findings

    def _check_sensitive_data(self, url, resp):
        ct = resp.headers.get('Content-Type', '').lower()
        if not any(t in ct for t in ['html', 'json', 'text', 'xml']):
            return []
        text = resp.text or ''
        for pattern, description in SENSITIVE_DATA_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                sample = str(matches[0])[:60]
                return [{
                    'vulnerable': True,
                    'type': 'crypto-sensitive-data-exposure',
                    'param': 'response-body',
                    'payload': 'N/A',
                    'evidence': f'{description}. Match sample: {sample}',
                    'confidence': 80,
                    'url': url,
                }]
        return []

    def _check_mixed_content(self, url, resp, parsed):
        if parsed.scheme != 'https':
            return []
        if 'html' not in resp.headers.get('Content-Type', '').lower():
            return []
        matches = re.findall(
            r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
            resp.text or '', re.IGNORECASE
        )
        if matches:
            return [{
                'vulnerable': True,
                'type': 'crypto-mixed-content',
                'param': 'html-resource',
                'payload': 'N/A',
                'evidence': f'HTTPS page loads HTTP resource: {matches[0][:100]}',
                'confidence': 90,
                'url': url,
            }]
        return []

    def _check_tls_config(self, url, parsed):
        findings = []
        host = parsed.hostname
        port = parsed.port or 443

        # Test for deprecated TLS 1.0
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=self.timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        findings.append({
                            'vulnerable': True,
                            'type': 'crypto-weak-tls-version',
                            'param': 'tls-version',
                            'payload': 'TLS 1.0',
                            'evidence': 'Server accepts deprecated TLS 1.0. Minimum: TLS 1.2.',
                            'confidence': 95,
                            'url': url,
                        })
            except (ssl.SSLError, OSError):
                pass

        # Certificate validity + cipher check
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as tls:
                    cipher = tls.cipher()
                    if cipher:
                        for weak in WEAK_CIPHERS:
                            if weak.upper() in cipher[0].upper():
                                findings.append({
                                    'vulnerable': True,
                                    'type': 'crypto-weak-cipher',
                                    'param': 'tls-cipher',
                                    'payload': cipher[0],
                                    'evidence': f'Weak cipher: {cipher[0]}. Use AES-GCM or ChaCha20.',
                                    'confidence': 85,
                                    'url': url,
                                })
                                break
        except ssl.SSLCertVerificationError as e:
            findings.append({
                'vulnerable': True,
                'type': 'crypto-invalid-certificate',
                'param': 'tls-certificate',
                'payload': 'N/A',
                'evidence': f'Certificate validation failed: {str(e)[:120]}',
                'confidence': 95,
                'url': url,
            })
        except (OSError, ssl.SSLError):
            pass

        return findings