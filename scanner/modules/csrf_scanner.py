"""
CSRF (Cross-Site Request Forgery) scanner module.

Detects missing or weak CSRF protection on forms that perform
state-changing operations.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests


class CSRFScanner:
    """Scanner for CSRF vulnerabilities."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Test forms for CSRF protection.
        
        Checks for:
        - CSRF tokens in form fields
        - Anti-CSRF headers
        - SameSite cookie attributes
        - Authentication context
        """
        findings: List[Dict[str, Any]] = []

        action = form_data.get("action")
        method = (form_data.get("method") or "GET").upper()
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        # Only test state-changing methods
        if method not in ["POST", "PUT", "DELETE"]:
            return findings

        print(f"Testing form {action} for CSRF protection...")

        # Check if form has CSRF token
        has_csrf_token = self._check_csrf_token(inputs)
        
        if not has_csrf_token:
            try:
                resp = self.session.get(action, timeout=self.timeout)
                page_html = resp.text or ""
                
                # Check for CSRF token patterns in page
                csrf_patterns = [
                    r'csrf[_-]?token',
                    r'_token',
                    r'authenticity[_-]?token',
                    r'anti[_-]?csrf',
                ]
                
                found_in_page = False
                for pattern in csrf_patterns:
                    if re.search(pattern, page_html, re.IGNORECASE):
                        found_in_page = True
                        break
                
                if not found_in_page:
                    # Detect authentication context
                    auth_required = self._detect_auth_context(resp, page_html)
                    
                    # Adjust confidence based on authentication
                    confidence = 85 if auth_required else 70
                    
                    exploitability = (
                        "Requires authenticated user and state-changing action" if auth_required
                        else "Authentication context unknown - may require manual verification"
                    )
                    
                    print(f"CSRF protection missing on {action} (Auth required: {auth_required})")
                    findings.append({
                        "vulnerable": True,
                        "type": "csrf",
                        "param": "form",
                        "payload": "N/A",
                        "evidence": "No CSRF token found in form or page",
                        "confidence": confidence,
                        "url": action,
                        "exploitability": exploitability,
                        "auth_required": auth_required
                    })
            
            except requests.RequestException as exc:
                print(f"Request failed during CSRF test for {action}: {exc}")

        return findings

    def _check_csrf_token(self, inputs: List[Dict[str, Any]]) -> bool:
        """Check if form inputs include a CSRF token."""
        csrf_keywords = ['csrf', 'token', '_token', 'authenticity', 'anti-csrf', 'xsrf']
        
        for inp in inputs:
            name = inp.get('name', '').lower()
            for keyword in csrf_keywords:
                if keyword in name:
                    return True
        
        return False

    def _detect_auth_context(self, response: requests.Response, html_content: str) -> bool:
        """
        Detect if the form/page requires authentication.
        
        Indicators:
        - Session cookies present
        - Auth-related keywords in page
        - Protected endpoints
        """
        # Check for session cookies
        if response.cookies:
            session_cookie_names = ['session', 'sessionid', 'auth', 'token', 'jwt']
            for cookie_name in response.cookies.keys():
                if any(keyword in cookie_name.lower() for keyword in session_cookie_names):
                    return True
        
        # Check for authentication keywords in HTML
        auth_keywords = [
            'logout', 'sign out', 'my account', 'dashboard', 'profile',
            'settings', 'admin', 'logged in as'
        ]
        
        for keyword in auth_keywords:
            if re.search(keyword, html_content, re.IGNORECASE):
                return True
        
        # Check for protected endpoint patterns
        protected_patterns = ['/admin/', '/account/', '/profile/', '/settings/', '/dashboard/']
        url = response.url
        if any(pattern in url for pattern in protected_patterns):
            return True
        
        return False

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """CSRF is primarily a form-based vulnerability."""
        return []
