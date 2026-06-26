import os
import json
import redis
import logging

logger = logging.getLogger(__name__)

class RedisStateManager:
    """Manages scan state in Redis so API and Worker containers stay in sync."""
    
    def __init__(self):
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self.client = redis.from_url(redis_url, decode_responses=True)

    def set_scan_state(self, scan_id: str, state: dict):
        self.client.hset("wraith:scans", scan_id, json.dumps(state))

    def get_scan_state(self, scan_id: str) -> dict:
        data = self.client.hget("wraith:scans", scan_id)
        return json.loads(data) if data else None

    def get_all_scans(self) -> list:
        all_scans = self.client.hgetall("wraith:scans")
        return [json.loads(v) for v in all_scans.values()]
