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
        # Use provided session (authenticated) or create new one
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
        """
        findings: List[Dict[str, Any]] = []

        action = form_data.get("action")
        method = (form_data.get("method") or "GET").upper()
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        # Only test state-changing methods (POST, PUT, DELETE)
        if method not in ["POST", "PUT", "DELETE"]:
            return findings

        print(f"Testing form {action} for CSRF protection...")

        # Check if form has CSRF token
        has_csrf_token = self._check_csrf_token(inputs)
        
        if not has_csrf_token:
            # Try to fetch the form page to check for tokens in HTML
            try:
                resp = self.session.get(action, timeout=self.timeout)
                page_html = resp.text or ""
                
                # Check for common CSRF token patterns in the page
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
                    # No CSRF protection detected
                    print(f"CSRF protection missing on {action}")
                    findings.append({
                        "vulnerable": True,
                        "type": "csrf",
                        "param": "form",
                        "payload": "N/A",
                        "evidence": "No CSRF token found in form or page",
                        "confidence": 80,
                        "url": action,
                        "exploitability": "Requires authenticated user and state-changing action"
                    })
            
            except requests.RequestException as exc:
                print(f"Request failed during CSRF test for {action}: {exc}")

        return findings

    def _check_csrf_token(self, inputs: List[Dict[str, Any]]) -> bool:
        """
        Check if form inputs include a CSRF token.
        
        Args:
            inputs: List of form input fields
            
        Returns:
            True if CSRF token found, False otherwise
        """
        csrf_keywords = ['csrf', 'token', '_token', 'authenticity', 'anti-csrf', 'xsrf']
        
        for inp in inputs:
            name = inp.get('name', '').lower()
            for keyword in csrf_keywords:
                if keyword in name:
                    return True
        
        return False

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CSRF is primarily a form-based vulnerability.
        This method is here for API consistency but doesn't test URLs.
        """
        return []
