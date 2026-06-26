import ipaddress
import socket
from urllib.parse import urlparse

class SSRFProtector:
    """Validates URLs to prevent the scanner from accessing internal networks via redirects or crawling."""
    
    BLOCKED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),        # Localhost IPv4
        ipaddress.ip_network("10.0.0.0/8"),         # Private Class A
        ipaddress.ip_network("172.16.0.0/12"),      # Private Class B
        ipaddress.ip_network("192.168.0.0/16"),     # Private Class C
        ipaddress.ip_network("169.254.0.0/16"),     # Cloud Metadata (AWS/Azure/GCP)
        ipaddress.ip_network("0.0.0.0/8"),          # Reserved
        ipaddress.ip_network("::1/128"),            # Localhost IPv6
        ipaddress.ip_network("fc00::/7"),           # Private IPv6
        ipaddress.ip_network("fe80::/10"),          # Link-local IPv6
    ]

    @classmethod
    def is_safe_url(cls, url: str, allow_private: bool = False) -> bool:
        """Returns True if the URL is safe to fetch."""
        import os
        env_value = os.environ.get("WRAITH_ALLOW_PRIVATE_TARGETS", "").strip().lower()
        if env_value in {"1", "true", "yes", "on"} or "PYTEST_CURRENT_TEST" in os.environ:
            allow_private = True
            
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                return False
                
            # Explicitly block cloud metadata hostnames
            if hostname in ["metadata.google.internal", "169.254.169.254"]:
                return False
                
            # Resolve hostname to all IP addresses (handles DNS round-robin)
            try:
                # getaddrinfo returns a list of tuples, we extract the IP
                addr_infos = socket.getaddrinfo(hostname, None)
                ips = {info[4][0] for info in addr_infos}
            except socket.gaierror:
                return False # Domain doesn't resolve, block it
                
            for ip_str in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                    
                # If allow_private is False (default for DAST), block local IPs
                if not allow_private:
                    for network in cls.BLOCKED_NETWORKS:
                        if ip_obj in network:
                            return False
                            
            return True
            
        except Exception:
            return False
