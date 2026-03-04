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

# Paths to check for version disclosure (framework-agnostic only)
VERSION_PATHS = [
    '/readme.txt', '/CHANGELOG.md', '/RELEASE-NOTES',
    '/package.json',
]

# CMS-specific paths — only checked when CMS fingerprint is present
WORDPRESS_PATHS = [
    '/wp-includes/version.php', '/wp-login.php',
    '/readme.html',             # WP ships one by default
]
PHP_PATHS = ['/composer.json']


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
        """Check common version-disclosure paths on the base domain.

        Guards against SPA catch-all routing: if a probed path returns
        the same HTML shell as the main page, it's a client-side 200
        and NOT a real file — skip it.
        """
        findings = []
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # ── Fingerprint main page to detect SPA catch-all routing ──
        main_body_hash = None
        spa_marker = None   # robust SPA shell indicator
        _SPA_MARKERS = [
            '<app-root',         # Angular
            'id="root"',         # React
            'id="__next"',       # Next.js
            'id="app"',          # Vue
            'data-reactroot',    # React (older)
        ]
        try:
            main_resp = self.session.get(base_url, timeout=self.timeout)
            if main_resp.status_code == 200 and main_resp.text:
                main_body_hash = hash(main_resp.text[:3000])
                for marker in _SPA_MARKERS:
                    if marker in main_resp.text:
                        spa_marker = marker
                        break
        except requests.RequestException:
            pass

        # Detect WordPress to decide whether to probe WP-specific paths
        is_wordpress = False
        try:
            resp = self.session.get(base_url, timeout=self.timeout)
            body = (resp.text or '')[:5000].lower()
            headers_blob = ' '.join(f'{k}: {v}' for k, v in resp.headers.items()).lower()
            is_wordpress = any(sig in body or sig in headers_blob for sig in [
                'wp-content', 'wp-includes', 'wordpress', 'wp-json',
            ])
        except requests.RequestException:
            pass

        paths_to_check = list(VERSION_PATHS)
        if is_wordpress:
            paths_to_check.extend(WORDPRESS_PATHS)
            paths_to_check.extend(PHP_PATHS)

        for path in paths_to_check:
            check_url = origin + path
            try:
                resp = self.session.get(check_url, timeout=self.timeout)
                if resp.status_code != 200 or not resp.text:
                    continue

                # SPA catch-all guard (hash comparison)
                if main_body_hash is not None:
                    if hash(resp.text[:3000]) == main_body_hash:
                        continue

                # SPA catch-all guard (marker detection — catches
                # Angular/React/Vue/Next shells even when nonces/tokens
                # cause hash mismatches)
                if spa_marker and spa_marker in resp.text:
                    continue

                # Only extract from text-like responses
                ct = resp.headers.get('Content-Type', '').lower()
                if not any(t in ct for t in ('text/', 'json', 'xml')):
                    continue

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