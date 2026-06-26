import requests
import time
from datetime import datetime, timedelta

class OAuthFlowManager:
    """Manages complex OAuth2 flows (Authorization Code, Refresh Tokens)."""
    
    def __init__(self, token_url, client_id, client_secret, refresh_token):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.access_token = None
        self.expires_at = 0

    def get_valid_token(self):
        """Returns a valid access token, refreshing it if necessary."""
        if self.access_token and time.time() < self.expires_at - 60:
            return self.access_token # Token is still valid
            
        print("[*] OAuth token expired or missing. Refreshing...")
        return self._refresh_token()

    def _refresh_token(self):
        """Calls the OAuth2 /token endpoint to get a new access token."""
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        try:
            response = requests.post(self.token_url, data=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                self.expires_at = time.time() + data.get('expires_in', 3600)
                return self.access_token
            else:
                print(f"[-] Failed to refresh OAuth token: {response.text}")
                return None
        except Exception as e:
            print(f"[-] OAuth refresh error: {e}")
            return None
