"""Open redirect scanner with baseline-aware proof."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


COMMON_REDIRECT_PARAMS = [
    "url",
    "redirect",
    "next",
    "return",
    "returnUrl",
    "goto",
    "target",
    "destination",
    "continue",
    "out",
]

TEST_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://google.com",
    "http://example.com",
]


class RedirectScanner:
    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        redirect_params = self._extract_redirect_params(params)
        if not redirect_params:
            return findings

        baseline_targets = self._fetch_sync_redirect_targets(url, params)
        for param in redirect_params:
            print(f"Testing open redirect on parameter: {param}")
            for payload in TEST_PAYLOADS:
                print(f"  Trying payload: {payload}")
                try:
                    vuln = self._test_redirect(url, param, params, payload, baseline_targets)
                    if vuln:
                        findings.append(vuln)
                        break
                except requests.RequestException as exc:
                    print(f"Request failed during redirect test for {param} with payload {payload}: {exc}")
                    continue
        return findings

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        redirect_params = self._extract_redirect_params(params)
        if not redirect_params:
            return findings

        baseline_targets = await self._fetch_async_redirect_targets(url, params, http)
        for param in redirect_params:
            for payload in TEST_PAYLOADS:
                vuln = await self._test_redirect_async(url, param, params, payload, baseline_targets, http)
                if vuln:
                    findings.append(vuln)
                    break
        return findings

    async def _test_redirect_async(self, url, param_name, params, test_domain, baseline_targets, http):
        mutated = params.copy()
        mutated[param_name] = test_domain
        resp = await http.get(url, params=mutated, allow_redirects=False)
        if not resp:
            return None
        candidates = self._extract_redirect_targets(resp.text or "", resp.headers)
        return self._build_finding(param_name, test_domain, baseline_targets, candidates)

    def _extract_redirect_params(self, params: Dict[str, Any]) -> List[str]:
        found: List[str] = []
        lower_names = {k.lower(): k for k in params.keys()}

        for candidate in COMMON_REDIRECT_PARAMS:
            if candidate.lower() in lower_names:
                found.append(lower_names[candidate.lower()])

        for name, value in params.items():
            if name in found or value is None:
                continue
            sv = str(value).strip()
            if sv.startswith("http://") or sv.startswith("https://") or sv.startswith("//"):
                found.append(name)
        return found

    def _test_redirect(
        self,
        url: str,
        param_name: str,
        params: Dict[str, Any],
        test_domain: str,
        baseline_targets: List[Tuple[str, str]],
    ) -> Optional[Dict[str, Any]]:
        mutated = params.copy()
        mutated[param_name] = test_domain
        resp = self.session.get(url, params=mutated, timeout=self.timeout, allow_redirects=False)
        candidates = self._extract_redirect_targets(resp.text or "", resp.headers)
        return self._build_finding(param_name, test_domain, baseline_targets, candidates)

    def _fetch_sync_redirect_targets(self, url: str, params: Dict[str, Any]) -> List[Tuple[str, str]]:
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return []
        return self._extract_redirect_targets(resp.text or "", resp.headers)

    async def _fetch_async_redirect_targets(self, url: str, params: Dict[str, Any], http) -> List[Tuple[str, str]]:
        resp = await http.get(url, params=params, allow_redirects=False)
        if not resp:
            return []
        return self._extract_redirect_targets(resp.text or "", resp.headers)

    def _extract_redirect_targets(self, text: str, headers: Dict[str, Any]) -> List[Tuple[str, str]]:
        targets: List[Tuple[str, str]] = []

        location = headers.get("Location", "")
        if location:
            targets.append(("header", location.strip()))

        meta_match = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?([^"\'\>]+)["\']?',
            text,
            re.IGNORECASE,
        )
        if meta_match:
            content = meta_match.group(1)
            url_match = re.search(r"url\s*=\s*([^;]+)", content, re.IGNORECASE)
            if url_match:
                targets.append(("meta", url_match.group(1).strip().strip('"').strip("'")))

        js_pattern = re.compile(
            r"(window\.location|location\.href|location\.assign|location\.replace)\s*\(?\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        )
        for match in js_pattern.finditer(text):
            targets.append(("javascript", match.group(2).strip()))

        return targets

    def _build_finding(
        self,
        param_name: str,
        test_domain: str,
        baseline_targets: List[Tuple[str, str]],
        candidate_targets: List[Tuple[str, str]],
    ) -> Optional[Dict[str, Any]]:
        baseline_set = {(m, self._normalize_target(t)) for m, t in baseline_targets}

        for method, target in candidate_targets:
            normalized = self._normalize_target(target)
            if not self._target_matches_payload(target, test_domain):
                continue
            if (method, normalized) in baseline_set:
                continue
            evidence = f"{method.title()} redirect to: {target}"
            confidence = {"header": 95, "meta": 84, "javascript": 82}.get(method, 80)
            return {
                "vulnerable": True,
                "type": "open-redirect",
                "param": param_name,
                "payload": test_domain,
                "evidence": evidence,
                "confidence": confidence,
                "redirect_method": method,
            }
        return None

    def _target_matches_payload(self, location: str, test_domain: str) -> bool:
        loc_host = self._extract_host(location)
        payload_host = self._extract_host(test_domain)
        return bool(loc_host and payload_host and loc_host == payload_host)

    def _extract_host(self, location: str) -> str:
        loc = (location or "").strip()
        if loc.startswith("//"):
            loc = "http:" + loc
        parsed = urlparse(loc)
        if not parsed.netloc:
            return ""
        return parsed.netloc.lower()

    def _normalize_target(self, location: str) -> str:
        loc = (location or "").strip()
        if loc.startswith("//"):
            loc = "http:" + loc
        parsed = urlparse(loc)
        if not parsed.netloc:
            return loc.lower()
        path = parsed.path or "/"
        return f"{parsed.netloc.lower()}{path}"
