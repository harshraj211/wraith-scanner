"""
CSRF (Cross-Site Request Forgery) scanner module.

Detects missing or weak CSRF protection on forms that perform
state-changing operations.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

import requests


class CSRFScanner:
    """Scanner for CSRF vulnerabilities."""

    # Keywords whose presence in a field name strongly indicates a CSRF token.
    # Deliberately specific to avoid false negatives on unrelated 'token' fields.
    CSRF_FIELD_KEYWORDS = [
        'csrf',
        'xsrf',
        '_token',          # Laravel, Symfony
        'authenticity_token',  # Rails
        'anti_csrf',
        'anti-csrf',
        '__requestverificationtoken',  # ASP.NET
    ]

    # Pre-authentication form actions we skip — only exact path segments, not substrings.
    PREAUTH_PATH_SEGMENTS = {
        'login', 'logout', 'register', 'signin', 'signup', 'search', 'auth',
    }

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or self._default_session()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyse a parsed form for missing CSRF protection.

        Parameters
        ----------
        form_data:
            A dict with keys ``action`` (str URL), ``method`` (str),
            and ``inputs`` (list of dicts with at least a ``name`` key).

        Returns
        -------
        List of finding dicts (empty when no issue is detected).
        """
        findings: List[Dict[str, Any]] = []

        action: Optional[str] = form_data.get("action")
        method: str = (form_data.get("method") or "GET").upper()
        inputs: List[Dict[str, Any]] = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        # Only test state-changing methods
        if method not in {"POST", "PUT", "DELETE", "PATCH"}:
            return findings

        # Skip pre-auth / non-mutating forms — match on individual path segments
        # so that e.g. /account/login is skipped but /account/settings is NOT.
        if self._is_preauth_action(action):
            print(f"Skipping CSRF check for pre-auth/search form: {action}")
            return findings

        print(f"Testing form {action} for CSRF protection...")

        # --- Static check: does the form itself carry a CSRF token? ---
        if self._check_csrf_token(inputs):
            return findings  # Token present in form — no finding needed

        # --- Dynamic check: fetch the page and look for tokens / SameSite cookies ---
        try:
            resp = self.session.get(action, timeout=self.timeout)
        except requests.RequestException as exc:
            print(f"Request failed during CSRF test for {action}: {exc}")
            return findings

        page_html: str = resp.text or ""

        if self._page_has_csrf_token(page_html):
            return findings  # Token injected dynamically — likely protected

        if self._has_samesite_protection(resp):
            return findings  # SameSite cookie defence in place

        # No protection found — record the finding
        auth_required = self._detect_auth_context(resp, page_html)
        confidence = 85 if auth_required else 70
        exploitability = (
            "Requires authenticated user and state-changing action"
            if auth_required
            else "Authentication context unknown — may require manual verification"
        )

        print(f"CSRF protection missing on {action} (auth_required={auth_required})")
        findings.append({
            "vulnerable": True,
            "type": "csrf",
            "param": "form",
            "payload": "N/A",
            "evidence": (
                f"Form method is {method}. No anti-CSRF token found in form inputs, "
                "page HTML, or SameSite cookie attributes."
            ),
            "confidence": confidence,
            "url": action,
            "exploitability": exploitability,
            "auth_required": auth_required,
        })

        return findings

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """CSRF is primarily a form-based vulnerability; URL scanning is a no-op."""
        return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_session() -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": "vuln-scanner/1.0"})
        return session

    def _is_preauth_action(self, action: str) -> bool:
        """
        Return True only when a pre-auth keyword appears as a discrete path
        segment, avoiding false matches on substrings like /account/settings.
        """
        # Normalise to path only (strip query string / fragment)
        path = action.split("?")[0].split("#")[0].lower()
        
        segments = set()
        for s in path.split("/"):
            if s:
                # Strip the extension (e.g., 'login.asp' becomes 'login')
                base_name, _ = os.path.splitext(s)
                segments.add(base_name)
                
        return bool(segments & self.PREAUTH_PATH_SEGMENTS)

    def _check_csrf_token(self, inputs: List[Dict[str, Any]]) -> bool:
        """Return True if any form input looks like a CSRF token field."""
        for inp in inputs:
            name = inp.get("name", "").lower()
            if any(keyword in name for keyword in self.CSRF_FIELD_KEYWORDS):
                return True
        return False

    @staticmethod
    def _page_has_csrf_token(html: str) -> bool:
        """Return True if the page HTML contains recognisable CSRF token patterns."""
        patterns = [
            r'csrf[_-]?token',
            r'authenticity[_-]?token',
            r'anti[_-]?csrf',
            r'__requestverificationtoken',
            r'xsrf[_-]?token',
        ]
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _has_samesite_protection(response: requests.Response) -> bool:
        """
        Return True if every session-like cookie carries SameSite=Strict or
        SameSite=Lax, indicating a cookie-based CSRF defence is in place.
        """
        session_cookie_names = {'session', 'sessionid', 'auth', 'token', 'jwt'}
        session_cookies = [
            c for c in response.cookies
            if any(kw in c.name.lower() for kw in session_cookie_names)
        ]
        if not session_cookies:
            return False

        for cookie in session_cookies:
            samesite = (cookie._rest.get("SameSite") or "").lower()  # type: ignore[attr-defined]
            if samesite not in {"strict", "lax"}:
                return False
        return True

    def _detect_auth_context(self, response: requests.Response, html_content: str) -> bool:
        """
        Return True when heuristics suggest the page lives behind authentication.

        Checks:
        - Presence of session-like cookies
        - Auth-indicating keywords in the HTML
        - Protected URL path segments
        """
        # Session cookies
        session_cookie_names = {'session', 'sessionid', 'auth', 'token', 'jwt'}
        for cookie in response.cookies:
            if any(kw in cookie.name.lower() for kw in session_cookie_names):
                return True

        # Auth keywords in HTML
        auth_keywords = [
            'logout', 'sign out', 'my account', 'dashboard', 'profile',
            'settings', 'admin', 'logged in as',
        ]
        for keyword in auth_keywords:
            if re.search(re.escape(keyword), html_content, re.IGNORECASE):
                return True

        # Protected path segments
        protected_segments = {'/admin/', '/account/', '/profile/', '/settings/', '/dashboard/'}
        url = response.url
        if any(seg in url for seg in protected_segments):
            return True

        return False
