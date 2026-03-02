"""
A03: Server-Side Template Injection (SSTI) Scanner

Tests parameters for template expression evaluation across
Jinja2, Twig, Freemarker, Velocity, and Smarty engines.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests


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
        inputs = form_data.get('inputs', [])
        if not action or not inputs:
            return findings

        baseline = {inp.get('name', ''): '' for inp in inputs if inp.get('name')}
        for param in baseline:
            print(f"Testing SSTI on form param: {param}")
            result = self._probe_param(action, param, '', baseline, method)
            if result:
                findings.append(result)
        return findings

    def _probe_param(
        self, url, param, original, params, method
    ) -> Optional[Dict[str, Any]]:
        # First get a baseline to detect reflected value
        try:
            baseline_data = params.copy()
            baseline_data[param] = 'SSTI_BASELINE_12345'
            if method.upper() == 'GET':
                baseline_resp = self.session.get(url, params=baseline_data, timeout=self.timeout)
            else:
                baseline_resp = self.session.post(url, data=baseline_data, timeout=self.timeout)

            # Parameter must be reflected for SSTI to be detectable
            if 'SSTI_BASELINE_12345' not in (baseline_resp.text or ''):
                return None  # Not reflected, skip — reduces false positives

        except requests.RequestException:
            return None

        # Now test payloads
        for payload, expected, description in SSTI_PAYLOADS:
            try:
                data = params.copy()
                data[param] = payload

                if method.upper() == 'GET':
                    resp = self.session.get(url, params=data, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data=data, timeout=self.timeout)

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