"""
Proxy manager for routing traffic through tools like Burp Suite.

Allows intercepting and analyzing scanner traffic for debugging
and manual testing.
"""
from typing import Optional, Dict


class ProxyManager:
    """
    Manages HTTP/HTTPS proxy configuration for scanners.
    Commonly used to route traffic through Burp Suite.
    """
    
    def __init__(self):
        self.proxy_url: Optional[str] = None
        self.enabled: bool = False
    
    def enable(self, proxy_url: str = "http://127.0.0.1:8080") -> None:
        """
        Enable proxy routing.
        
        Args:
            proxy_url: Proxy server URL (default: Burp Suite's default)
        """
        self.proxy_url = proxy_url
        self.enabled = True
        print(f"[*] Proxy enabled: {proxy_url}")
    
    def disable(self) -> None:
        """Disable proxy routing."""
        self.enabled = False
        self.proxy_url = None
        print("[*] Proxy disabled")
    
    def get_proxies(self) -> Optional[Dict[str, str]]:
        """
        Get proxy configuration for requests library.
        
        Returns:
            Dict with http/https proxy settings, or None if disabled
        """
        if not self.enabled or not self.proxy_url:
            return None
        
        return {
            'http': self.proxy_url,
            'https': self.proxy_url,
        }


# Global proxy manager instance
_proxy_manager = ProxyManager()


def get_proxy_manager() -> ProxyManager:
    """Get the global proxy manager instance."""
    return _proxy_manager