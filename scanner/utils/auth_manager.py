"""Authentication manager for scanning protected areas."""
from typing import Optional, Dict
from urllib.parse import urljoin, urlparse
import requests


class AuthManager:
    """Manage authentication for scanning protected areas."""
    
    def __init__(self):
        self.session = requests.Session()
        self.is_authenticated = False
        self.auth_type = None
        self.credentials = {}
    
    def login_form(self, login_url: str, username: str, password: str, 
                   username_field: str = "username", password_field: str = "password") -> bool:
        """
        Login via HTML form.
        
        Args:
            login_url: URL of login page
            username: Username to login with
            password: Password to login with
            username_field: Name of username input field
            password_field: Name of password input field
        
        Returns:
            True if login successful, False otherwise
        """
        try:
            # First, get the login page to extract any CSRF tokens
            resp = self.session.get(login_url)
            
            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password,
            }
            
            # Try to find and include CSRF token if present
            import re
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            form = soup.find('form')

            submit_url = login_url
            submit_method = 'post'
            if form:
                action = (form.get('action') or '').strip()
                if action:
                    submit_url = urljoin(login_url, action)
                submit_method = (form.get('method') or 'post').lower()
            
            # Look for hidden inputs (often CSRF tokens)
            for hidden in soup.find_all('input', type='hidden'):
                name = hidden.get('name')
                value = hidden.get('value')
                if name and value:
                    login_data[name] = value
            
            # Submit login form
            if submit_method == 'get':
                login_resp = self.session.get(submit_url, params=login_data)
            else:
                login_resp = self.session.post(submit_url, data=login_data)
            
            # Check if login was successful
            # Common indicators: redirect, no error message, presence of logout link
            if login_resp.status_code in [200, 302, 303]:
                # Check for common failure indicators
                failure_indicators = ['invalid', 'incorrect', 'failed', 'error', 'wrong']
                text_lower = login_resp.text.lower()
                
                has_failure = any(indicator in text_lower for indicator in failure_indicators)
                has_logout = 'logout' in text_lower or 'sign out' in text_lower
                final_path = urlparse(getattr(login_resp, "url", submit_url)).path
                login_paths = {
                    urlparse(login_url).path,
                    urlparse(submit_url).path,
                }
                moved_away_from_login = final_path not in login_paths
                has_session_cookie = bool(self.session.cookies)
                redirected = bool(getattr(login_resp, "history", []))

                if not has_failure and (
                    has_logout or moved_away_from_login or has_session_cookie or redirected
                ):
                    self.is_authenticated = True
                    self.auth_type = 'form'
                    self.credentials = {'username': username, 'password': password}
                    print(f"[+] Successfully authenticated as {username}")
                    return True
            
            print(f"[-] Authentication failed for {username}")
            return False
            
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False
    
    def login_basic_auth(self, username: str, password: str) -> bool:
        """
        Set up HTTP Basic Authentication.
        
        Args:
            username: Username for basic auth
            password: Password for basic auth
        
        Returns:
            True (basic auth is set up, verification happens on first request)
        """
        from requests.auth import HTTPBasicAuth
        self.session.auth = HTTPBasicAuth(username, password)
        self.is_authenticated = True
        self.auth_type = 'basic'
        self.credentials = {'username': username, 'password': password}
        print(f"[+] Basic auth configured for {username}")
        return True
    
    def set_bearer_token(self, token: str) -> bool:
        """
        Set up Bearer token authentication (for APIs).
        
        Args:
            token: Bearer token
        
        Returns:
            True
        """
        self.session.headers.update({'Authorization': f'Bearer {token}'})
        self.is_authenticated = True
        self.auth_type = 'bearer'
        print("[+] Bearer token configured")
        return True
    
    def set_custom_headers(self, headers: Dict[str, str]) -> bool:
        """
        Add custom authentication headers.
        
        Args:
            headers: Dict of header name -> value
        
        Returns:
            True
        """
        self.session.headers.update(headers)
        self.is_authenticated = True
        self.auth_type = 'custom'
        print("[+] Custom headers configured")
        return True
    
    def get_session(self) -> requests.Session:
        """Get the authenticated session."""
        return self.session
    
    def logout(self) -> None:
        """Clear authentication."""
        self.session = requests.Session()
        self.is_authenticated = False
        self.auth_type = None
        self.credentials = {}
        print("[+] Logged out")


# Global auth manager
_auth_manager = AuthManager()


def get_auth_manager() -> AuthManager:
    """Get global auth manager instance."""
    return _auth_manager
