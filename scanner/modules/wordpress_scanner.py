"""WordPress and CMS detection and vulnerability scanner."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
import requests


class WordPressScanner:
    """Detect and scan WordPress sites for common vulnerabilities."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        # Use provided session (authenticated) or create new one
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Detect WordPress and check for vulnerabilities."""
        findings: List[Dict[str, Any]] = []
        
        # Detect if site is WordPress
        is_wp, version = self._detect_wordpress(url)
        
        if not is_wp:
            return findings
        
        print(f"WordPress detected! Version: {version or 'Unknown'}")
        
        # Check for common WordPress vulnerabilities
        findings.extend(self._check_xmlrpc(url))
        findings.extend(self._check_readme(url))
        findings.extend(self._check_user_enumeration(url))
        findings.extend(self._check_directory_listing(url))
        
        return findings

    def _detect_wordpress(self, url: str) -> tuple:
        """Detect if site is WordPress and get version."""
        try:
            resp = self.session.get(url, timeout=self.timeout)
            text = resp.text or ""
            
            # Check for WordPress indicators
            wp_indicators = [
                'wp-content', 'wp-includes', 'wordpress',
                'wp-json', '/wp-admin/'
            ]
            
            is_wp = any(indicator in text.lower() for indicator in wp_indicators)
            
            if not is_wp:
                return False, None
            
            # Try to get version
            version_match = re.search(r'wordpress[/\s]+(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
            version = version_match.group(1) if version_match else None
            
            # Also check meta generator tag
            if not version:
                meta_match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"', text)
                version = meta_match.group(1) if meta_match else None
            
            return True, version
            
        except requests.RequestException:
            return False, None

    def _check_xmlrpc(self, base_url: str) -> List[Dict[str, Any]]:
        """Check if XML-RPC is exposed (can be abused for DDoS)."""
        findings = []
        try:
            xmlrpc_url = base_url.rstrip('/') + '/xmlrpc.php'
            resp = self.session.get(xmlrpc_url, timeout=self.timeout)
            
            if resp.status_code == 200 and 'XML-RPC' in resp.text:
                print("Found exposed XML-RPC endpoint")
                findings.append({
                    "vulnerable": True,
                    "type": "wordpress-xmlrpc",
                    "param": "xmlrpc.php",
                    "payload": "N/A",
                    "evidence": "XML-RPC endpoint is accessible",
                    "confidence": 90,
                    "url": xmlrpc_url,
                })
        except requests.RequestException:
            pass
        
        return findings

    def _check_readme(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for exposed readme.html revealing version."""
        findings = []
        try:
            readme_url = base_url.rstrip('/') + '/readme.html'
            resp = self.session.get(readme_url, timeout=self.timeout)
            
            if resp.status_code == 200:
                print("Found exposed readme.html")
                findings.append({
                    "vulnerable": True,
                    "type": "wordpress-info-disclosure",
                    "param": "readme.html",
                    "payload": "N/A",
                    "evidence": "readme.html exposes WordPress version",
                    "confidence": 85,
                    "url": readme_url,
                })
        except requests.RequestException:
            pass
        
        return findings

    def _check_user_enumeration(self, base_url: str) -> List[Dict[str, Any]]:
        """Check if user enumeration is possible."""
        findings = []
        try:
            # Try ?author=1 parameter
            enum_url = base_url.rstrip('/') + '/?author=1'
            resp = self.session.get(enum_url, timeout=self.timeout, allow_redirects=False)
            
            # If redirects to /author/username, enumeration is possible
            if resp.status_code in [301, 302]:
                location = resp.headers.get('Location', '')
                if '/author/' in location:
                    print("User enumeration possible")
                    findings.append({
                        "vulnerable": True,
                        "type": "wordpress-user-enum",
                        "param": "author",
                        "payload": "?author=1",
                        "evidence": f"Redirects to {location}",
                        "confidence": 95,
                        "url": enum_url,
                    })
        except requests.RequestException:
            pass
        
        return findings

    def _check_directory_listing(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for directory listing in wp-content."""
        findings = []
        dirs_to_check = ['/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/']
        
        for dir_path in dirs_to_check:
            try:
                check_url = base_url.rstrip('/') + dir_path
                resp = self.session.get(check_url, timeout=self.timeout)
                
                if resp.status_code == 200 and 'Index of' in resp.text:
                    print(f"Directory listing enabled: {dir_path}")
                    findings.append({
                        "vulnerable": True,
                        "type": "wordpress-directory-listing",
                        "param": dir_path,
                        "payload": "N/A",
                        "evidence": f"Directory listing enabled on {dir_path}",
                        "confidence": 90,
                        "url": check_url,
                    })
            except requests.RequestException:
                pass
        
        return findings