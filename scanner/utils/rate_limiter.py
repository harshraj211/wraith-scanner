"""
Rate limiter to avoid overwhelming target servers or getting blocked.

Implements smart throttling with configurable delays between requests.
"""
import time
import threading
from typing import Dict


class RateLimiter:
    """
    Thread-safe rate limiter that enforces delays between requests.
    Prevents scanner from getting blocked by WAFs or rate limits.
    """
    
    def __init__(self, requests_per_second: float = 2.0):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: How many requests allowed per second (default: 2)
        """
        self.min_interval = 1.0 / requests_per_second  # Convert to seconds between requests
        self.last_request_time: Dict[str, float] = {}
        self.lock = threading.Lock()
    
    def wait(self, domain: str) -> None:
        """
        Wait if necessary to respect rate limit for this domain.
        Call this BEFORE making a request.
        
        Args:
            domain: The target domain (e.g., "example.com")
        """
        with self.lock:
            now = time.time()
            
            if domain in self.last_request_time:
                elapsed = now - self.last_request_time[domain]
                
                if elapsed < self.min_interval:
                    # Need to wait before next request
                    sleep_time = self.min_interval - elapsed
                    time.sleep(sleep_time)
            
            # Update last request time to now
            self.last_request_time[domain] = time.time()
    
    def set_rate(self, requests_per_second: float) -> None:
        """
        Change the rate limit on the fly.
        
        Args:
            requests_per_second: New rate limit
        """
        with self.lock:
            self.min_interval = 1.0 / requests_per_second


# Global rate limiter instance that all scanners can share
_global_limiter = RateLimiter(requests_per_second=2.0)


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _global_limiter