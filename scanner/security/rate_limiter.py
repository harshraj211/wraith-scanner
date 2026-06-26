import os
import functools
from flask import request, jsonify, g
import redis

# Connect to Redis (fallback to local if env var not set)
redis_client = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/1"), decode_responses=True)

def rate_limit(limit: int = 50, window: int = 60):
    """
    Decorator to limit API requests per tenant.
    Default: 50 requests per 60 seconds per API key.
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # 1. Get tenant ID from RBAC context (set by enterprise_auth.py)
            # Fallback to IP address if no API key is used
            tenant_id = getattr(g, 'tenant_id', request.remote_addr)
            
            # 2. Create Redis key
            key = f"rate_limit:{tenant_id}:{request.path}"
            
            # 3. Get current count
            try:
                current = redis_client.incr(key)
                if current == 1:
                    # Set expiration on the first request
                    redis_client.expire(key, window)
            except Exception as e:
                # Fallback in case Redis is not reachable, do not block request
                print(f"[Limiter] Redis error: {e}")
                return f(*args, **kwargs)
                
            # 4. Check if limit exceeded
            if current > limit:
                return jsonify({
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Limit is {limit} per {window} seconds."
                }), 429
                
            # 5. Add rate limit headers to response
            response = f(*args, **kwargs)
            remaining = max(0, limit - current)
            
            # Flask response check and headers insertion
            if hasattr(response, "headers"):
                response.headers["X-RateLimit-Limit"] = str(limit)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
            elif isinstance(response, tuple) and len(response) > 0:
                # Handle Flask tuple responses (response_body, status_code, headers) or (response_body, status_code)
                # For compatibility, we return the response as is or try to modify headers if possible
                pass
            return response
        return wrapped
    return decorator
