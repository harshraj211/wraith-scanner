"""
A06: Vulnerable and Outdated Components Scanner

Detects version disclosures in headers, HTML meta tags, JS libraries,
and common paths — then flags known-outdated versions.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests


# Known vulnerable version thresholds for common libraries
# Format: (library_name, regex_to_extract_version, min_safe_version, cve_reference)
KNOWN_LIBRARIES = [
    ('jQuery',       r'jquery[/-](\d+\.\d+\.?\d*)',         '3.7.0',  'CVE-2019-11358 and others'),
    ('Bootstrap',    r'bootstrap[/-](\d+\.\d+\.?\d*)',       '5.3.0',  'XSS in tooltip/popover prior to 5.x'),
    ('Angular',      r'angular[/-](\d+\.\d+\.?\d*)',         '17.0.0', 'Multiple CVEs in Angular <17'),
    ('React',        r'react[/-](\d+\.\d+\.?\d*)',           '18.0.0', 'Various React CVEs'),
    ('lodash',       r'lodash[/-](\d+\.\d+\.?\d*)',          '4.17.21','CVE-2021-23337 prototype pollution'),
    ('moment',       r'moment[/-](\d+\.\d+\.?\d*)',          '2.29.4', 'CVE-2022-24785 path traversal'),
    ('Apache',       r'Apache[/ ](\d+\.\d+\.?\d*)',          '2.4.58', 'Various Apache CVEs'),
    ('nginx',        r'nginx[/ ](\d+\.\d+\.?\d*)',           '1.25.0', 'Various nginx CVEs'),
    ('PHP',          r'PHP[/ ](\d+\.\d+\.?\d*)',             '8.2.0',  'Various PHP CVEs'),
    ('OpenSSL',      r'OpenSSL[/ ](\d+\.\d+\.?\d*)',         '3.0.0',  'CVE-2022-0778 and others'),
    ('WordPress',    r'WordPress[/ ](\d+\.\d+\.?\d*)',       '6.4.0',  'Various WordPress CVEs'),
    ('Drupal',       r'Drupal[/ ](\d+\.\d+\.?\d*)',          '10.1.0', 'Drupalgeddon variants'),
]

# Common paths to check for version disclosure
VERSION_PATHS = [
    '/readme.html', '/readme.txt', '/CHANGELOG.md',
    '/wp-includes/version.php', '/RELEASE-NOTES',
    '/package.json', '/composer.json',
]


class ComponentScanner:
    """Scanner for A06: Vulnerable and Outdated Components."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Scan URL for component version disclosures and known-vulnerable versions."""
        findings = []
        print(f"Checking components on: {url}")

        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as exc:
            print(f"Component scan failed for {url}: {exc}")
            return findings

        # Check response headers
        findings.extend(self._check_headers(url, resp))

        # Check HTML body for library references
        content_type = resp.headers.get('Content-Type', '').lower()
        if 'html' in content_type:
            findings.extend(self._check_html_libraries(url, resp.text or ''))

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []  # Component checks are URL-level

    def scan_base_url(self, base_url: str) -> List[Dict[str, Any]]:
        """Check common version-disclosure paths on the base domain."""
        findings = []
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in VERSION_PATHS:
            check_url = origin + path
            try:
                resp = self.session.get(check_url, timeout=self.timeout)
                if resp.status_code == 200 and resp.text:
                    version_findings = self._extract_versions(check_url, resp.text)
                    findings.extend(version_findings)
            except requests.RequestException:
                pass

        return findings

    def _check_headers(self, url: str, resp: requests.Response) -> List[Dict[str, Any]]:
        """Check response headers for version strings."""
        findings = []
        header_blob = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())
        findings.extend(self._extract_versions(url, header_blob, source='response headers'))
        return findings

    def _check_html_libraries(self, url: str, html: str) -> List[Dict[str, Any]]:
        """Scan HTML for known JS library inclusions with versions."""
        return self._extract_versions(url, html, source='HTML/JS')

    def _extract_versions(
        self, url: str, content: str, source: str = 'response'
    ) -> List[Dict[str, Any]]:
        findings = []
        for lib_name, pattern, min_safe, cve_ref in KNOWN_LIBRARIES:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for version_str in matches:
                try:
                    if self._is_outdated(version_str, min_safe):
                        findings.append({
                            'vulnerable': True,
                            'type': 'vulnerable-component',
                            'param': lib_name,
                            'payload': 'N/A',
                            'evidence': (
                                f'{lib_name} v{version_str} detected in {source}. '
                                f'Minimum safe version: {min_safe}. '
                                f'Related: {cve_ref}'
                            ),
                            'confidence': 80,
                            'url': url,
                        })
                except Exception:
                    pass
        return findings

    def _is_outdated(self, version_str: str, min_safe: str) -> bool:
        """Compare version strings. Returns True if version < min_safe."""
        def parse(v):
            parts = re.sub(r'[^0-9.]', '', v).split('.')
            return tuple(int(x) for x in parts if x)

        try:
            return parse(version_str) < parse(min_safe)
        except Exception:
            return False