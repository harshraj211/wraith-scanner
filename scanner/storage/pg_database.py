import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import DictCursor
from urllib.parse import urlparse
import logging
from typing import Any

logger = logging.getLogger(__name__)

class PostgresRowWrapper:
    """Wraps a psycopg2 DictRow to behave like sqlite3.Row."""
    def __init__(self, row):
        self._row = row

    def __getitem__(self, key):
        return self._row[key]

    def keys(self):
        return self._row.keys()

class PostgresCursorWrapper:
    """Wraps a psycopg2 cursor to mimic sqlite3.Cursor."""
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query: str, params: Any = None):
        # Translate SQLite ? placeholders to PostgreSQL %s
        if params is not None:
            query = query.replace('?', '%s')
        
        # Translate INSERT OR REPLACE INTO <table> (col1, col2) VALUES (%s, %s)
        # to INSERT INTO <table> (col1, col2) VALUES (%s, %s) ON CONFLICT (<primary_key>) DO UPDATE SET ...
        # Let's handle the known tables in the repository:
        query_upper = query.upper()
        if "INSERT OR REPLACE INTO" in query_upper:
            # We can translate common ones
            table = query_upper.split("INSERT OR REPLACE INTO")[1].strip().split()[0].split("(")[0].strip().lower()
            
            # Extract fields and map them to DO UPDATE SET
            # For simplicity, we can map ON CONFLICT for key tables:
            pk = "id"
            if table == "scans":
                pk = "scan_id"
            elif table == "scan_states":
                pk = "scan_id"
            elif table == "requests":
                pk = "request_id"
            elif table == "responses":
                pk = "response_id"
            elif table == "findings":
                pk = "finding_id"
            elif table == "evidence_artifacts":
                pk = "artifact_id"
            elif table == "auth_profiles":
                pk = "profile_id"
            elif table == "proof_tasks":
                pk = "task_id"
            elif table == "oob_events":
                pk = "event_id"

            # Parse columns and generate the ON CONFLICT clause
            # Simple translation: replace "INSERT OR REPLACE INTO" with "INSERT INTO"
            # and append " ON CONFLICT (<pk>) DO UPDATE SET <col1> = EXCLUDED.<col1>, ..."
            query = query.replace("INSERT OR REPLACE INTO", "INSERT INTO")
            
            # Try to parse the columns list to construct the update clause
            try:
                col_start = query.find("(")
                col_end = query.find(")")
                if col_start != -1 and col_end != -1:
                    cols = [c.strip() for c in query[col_start+1:col_end].split(",")]
                    update_clause = ", ".join([f"{c} = EXCLUDED.{c}" for c in cols if c != pk])
                    query += f" ON CONFLICT ({pk}) DO UPDATE SET {update_clause}"
            except Exception:
                pass

        # Execute
        self._cursor.execute(query, params)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        return PostgresRowWrapper(row) if row else None

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [PostgresRowWrapper(r) for r in rows]

    def __getattr__(self, name):
        return getattr(self._cursor, name)

class PostgresConnectionWrapper:
    """Wraps a psycopg2 connection to mimic sqlite3.Connection."""
    def __init__(self, conn):
        self._conn = conn

    def execute(self, query: str, params: Any = None):
        cursor = self.cursor()
        cursor.execute(query, params)
        return cursor

    def executescript(self, script: str):
        with self._conn.cursor() as cur:
            cur.execute(script)
        self.commit()

    def cursor(self):
        return PostgresCursorWrapper(self._conn.cursor(cursor_factory=DictCursor))

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        # We don't close, we return to pool via return_conn
        PostgresManager.return_conn(self._conn)

    def __getattr__(self, name):
        return getattr(self._conn, name)

class PostgresManager:
    """Manages a thread-safe PostgreSQL connection pool."""
    _pool = None

    @classmethod
    def initialize_pool(cls):
        if cls._pool:
            return
            
        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            raise RuntimeError("DATABASE_URL environment variable is not set. Cannot start enterprise backend.")
            
        try:
            url = urlparse(database_url)
            cls._pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=10,
                database=url.path[1:],
                user=url.username,
                password=url.password,
                host=url.hostname,
                port=url.port
            )
            logger.info("[DB] PostgreSQL connection pool initialized.")
        except Exception as e:
            logger.critical(f"[DB] Failed to initialize PostgreSQL pool: {e}")
            raise

    @classmethod
    def get_conn(cls):
        if not cls._pool:
            cls.initialize_pool()
        return PostgresConnectionWrapper(cls._pool.getconn())

    @classmethod
    def return_conn(cls, conn):
        if cls._pool:
            cls._pool.putconn(conn._conn if isinstance(conn, PostgresConnectionWrapper) else conn)
