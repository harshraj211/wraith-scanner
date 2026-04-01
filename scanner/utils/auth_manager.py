"""Authentication manager for scanning protected areas."""
import json
import re
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse
import requests


_JWT_LIKE_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_TOKEN_KEYS = (
    "token",
    "access_token",
    "accessToken",
    "id_token",
    "idToken",
    "jwt",
    "bearer",
    "authorization",
)


def _extract_token_candidates(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _TOKEN_KEYS and isinstance(child, str) and child.strip():
                yield child.strip()
            yield from _extract_token_candidates(child)
    elif isinstance(value, list):
        for item in value:
            yield from _extract_token_candidates(item)


def extract_browser_storage_auth(storage: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    storage = storage or {}
    collected = {
        "authorization": None,
        "query_params": {},
        "sources": [],
    }

    for location in ("localStorage", "sessionStorage"):
        bucket = storage.get(location, {}) or {}
        for key, raw_value in bucket.items():
            if raw_value is None:
                continue
            value = str(raw_value).strip()
            if not value:
                continue

            key_lower = str(key).lower()
            if value.lower().startswith("bearer "):
                collected["authorization"] = value
                collected["sources"].append(f"{location}:{key}")
                return collected

            if _JWT_LIKE_RE.match(value) and any(token_key in key_lower for token_key in ("token", "jwt", "auth", "bearer")):
                collected["authorization"] = f"Bearer {value}"
                collected["sources"].append(f"{location}:{key}")
                return collected

            if any(token_key in key_lower for token_key in ("api_key", "apikey", "api-token")):
                collected["query_params"][str(key)] = value
                collected["sources"].append(f"{location}:{key}")

            if not value.startswith(("{", "[")):
                continue

            try:
                parsed = json.loads(value)
            except Exception:
                continue

            for candidate in _extract_token_candidates(parsed):
                candidate = str(candidate).strip()
                if candidate.lower().startswith("bearer "):
                    collected["authorization"] = candidate
                    collected["sources"].append(f"{location}:{key}")
                    return collected
                if _JWT_LIKE_RE.match(candidate):
                    collected["authorization"] = f"Bearer {candidate}"
                    collected["sources"].append(f"{location}:{key}")
                    return collected

    return collected


def apply_browser_storage_auth(session: requests.Session, storage: Dict[str, Dict[str, str]]) -> bool:
    extracted = extract_browser_storage_auth(storage)
    applied = False

    authorization = extracted.get("authorization")
    if authorization:
        session.headers.update({"Authorization": authorization})
        applied = True

    query_params = dict(getattr(session, "_default_query_params", {}) or {})
    if extracted.get("query_params"):
        query_params.update(extracted["query_params"])
        setattr(session, "_default_query_params", query_params)
        applied = True

    return applied


class AuthManager:
    """Manage authentication for scanning protected areas."""
    
    def __init__(self):
        self.session = requests.Session()
        self.is_authenticated = False
        self.auth_type = None
        self.credentials = {}
        self.query_params = {}
    
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
        self.credentials = {'token': token}
        print("[+] Bearer token configured")
        return True

    def set_api_key(self, name: str, value: str, location: str = "header") -> bool:
        """
        Configure API-key authentication for header, cookie, or query schemes.
        """
        location = (location or "header").lower()
        if location == "header":
            self.session.headers.update({name: value})
        elif location == "cookie":
            self.session.cookies.set(name, value)
        elif location == "query":
            self.query_params[name] = value
            setattr(self.session, "_default_query_params", dict(self.query_params))
        else:
            raise ValueError(f"Unsupported API key location: {location}")

        self.is_authenticated = True
        self.auth_type = 'api_key'
        self.credentials = {'name': name, 'value': value, 'location': location}
        print(f"[+] API key configured in {location}: {name}")
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

    def set_cookies(self, cookies: Dict[str, str]) -> bool:
        """
        Add custom cookies to the active session.
        """
        for name, value in (cookies or {}).items():
            self.session.cookies.set(name, value)
        if cookies:
            self.is_authenticated = True
            self.auth_type = 'custom'
            print("[+] Custom cookies configured")
        return True
    
    def get_session(self) -> requests.Session:
        """Get the authenticated session."""
        return self.session

    def ingest_browser_storage(self, storage: Dict[str, Dict[str, str]]) -> bool:
        """Promote auth artifacts from browser storage into the shared HTTP session."""
        if not apply_browser_storage_auth(self.session, storage):
            return False

        self.is_authenticated = True
        self.auth_type = "browser-storage"
        self.credentials = {"storage": storage}
        print("[+] Browser storage auth synchronized")
        return True
    
    def logout(self) -> None:
        """Clear authentication."""
        self.session = requests.Session()
        self.is_authenticated = False
        self.auth_type = None
        self.credentials = {}
        self.query_params = {}
        print("[+] Logged out")


# Global auth manager
_auth_manager = AuthManager()


def get_auth_manager() -> AuthManager:
    """Get global auth manager instance."""
    return _auth_manager
