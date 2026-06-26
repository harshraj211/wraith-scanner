import os
import asyncio
from celery import Celery
from scanner.core.redis_state import RedisStateManager
from scanner.storage.pg_database import PostgresManager

# Initialize Celery
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
app = Celery('wraith_worker', broker=redis_url, backend=redis_url)

# Import the heavy scanning logic
from api_server import run_scan

@app.task(bind=True)
def run_dast_scan_task(self, scan_id, target_url, depth, timeout, auth_config, scan_mode, import_config, sequence_config):
    """Celery task for distributed DAST scanning."""
    state_mgr = RedisStateManager()
    
    try:
        # Postgres connection is established inside the worker process
        PostgresManager.initialize_pool()
        
        state_mgr.set_scan_state(scan_id, {"status": "running", "target": target_url})
        
        # Execute the actual scan
        asyncio.run(run_scan(scan_id, target_url, depth, timeout, auth_config, scan_mode, import_config, sequence_config))
        
        return {"status": "SUCCESS", "scan_id": scan_id}
    except Exception as e:
        state_mgr.set_scan_state(scan_id, {"status": "failed", "error": str(e)})
        return {"status": "FAILED", "error": str(e)}
