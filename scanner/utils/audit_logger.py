import functools
from datetime import datetime
from flask import request, g
import sqlite3

DB_PATH = "wraith_audit.db"

def init_audit_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                     (id INTEGER PRIMARY KEY, timestamp TEXT, user_role TEXT, action TEXT, target TEXT, ip_address TEXT)''')
    conn.commit()
    conn.close()

def audit_log(action: str):
    """Decorator to log administrative actions."""
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # Extract user from RBAC context (set by enterprise_auth.py)
            user = getattr(g, 'user', {}).get('role', 'anonymous')
            ip_addr = request.remote_addr
            target = request.path
            
            # Log to DB
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT INTO audit_logs (timestamp, user_role, action, target, ip_address) VALUES (?, ?, ?, ?, ?)",
                         (datetime.utcnow().isoformat(), user, action, target, ip_addr))
            conn.commit()
            conn.close()
            
            return f(*args, **kwargs)
        return wrapped
    return decorator
