from authlib.integrations.flask_client import OAuth
from flask import redirect, url_for, session, jsonify
import os

class SSOManager:
    """Handles OIDC/SAML SSO integration for enterprise authentication."""
    
    def __init__(self, app):
        self.oauth = OAuth(app)
        # Configure OIDC (e.g., Okta, Azure AD, Google Workspace)
        self.oauth.register(
            name='enterprise_oidc',
            client_id=os.getenv('OIDC_CLIENT_ID'),
            client_secret=os.getenv('OIDC_CLIENT_SECRET'),
            server_metadata_url=os.getenv('OIDC_METADATA_URL'), # e.g., https://tenant.okta.com/.well-known/openid-configuration
            client_kwargs={'scope': 'openid email profile'}
        )
        
    def login(self):
        """Redirects user to enterprise SSO provider."""
        redirect_uri = url_for('sso_callback', _external=True)
        return self.oauth.enterprise_oidc.authorize_redirect(redirect_uri)

    def callback(self):
        """Handles the callback from the SSO provider."""
        try:
            token = self.oauth.enterprise_oidc.authorize_access_token()
            user_info = token.get('userinfo')
            
            # In production, map user_info['email'] to your RBAC roles in the DB
            session['user'] = {
                'email': user_info.get('email'),
                'name': user_info.get('name'),
                'role': 'admin' if '@yourcompany.com' in user_info.get('email') else 'scanner'
            }
            return redirect('/dashboard') # Redirect to React frontend
        except Exception as e:
            return jsonify({"error": "SSO authentication failed", "details": str(e)}), 401
