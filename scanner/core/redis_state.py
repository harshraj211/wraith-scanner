import os
import json
import redis
import logging

logger = logging.getLogger(__name__)

class RedisStateManager:
    """Manages scan state in Redis so API and Worker containers stay in sync. Falls back to in-memory during tests."""
    
    def __init__(self):
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self.client = redis.from_url(redis_url, decode_responses=True)
        self._fallback_db = {}
        self._redis_failed = False

    def _execute(self, func, *args, **kwargs):
        if self._redis_failed:
            return None
        try:
            return func(*args, **kwargs)
        except redis.exceptions.RedisError as e:
            logger.warning(f"Redis connection failed, falling back to in-memory storage: {e}")
            self._redis_failed = True
            return None

    def set_scan_state(self, scan_id: str, state: dict):
        res = self._execute(self.client.hset, "wraith:scans", scan_id, json.dumps(state))
        if res is None:
            self._fallback_db[scan_id] = json.dumps(state)

    def get_scan_state(self, scan_id: str) -> dict:
        data = self._execute(self.client.hget, "wraith:scans", scan_id)
        if data is None:
            data = self._fallback_db.get(scan_id)
        return json.loads(data) if data else None

    def get_all_scans(self) -> list:
        all_scans = self._execute(self.client.hgetall, "wraith:scans")
        if all_scans is None:
            return [json.loads(v) for v in self._fallback_db.values()]
        return [json.loads(v) for v in all_scans.values()]
