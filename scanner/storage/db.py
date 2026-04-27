"""SQLite database bootstrap for the local Wraith corpus."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Optional


DEFAULT_DB_PATH = os.environ.get("WRAITH_DB_PATH", os.path.join("reports", "wraith.sqlite3"))


def init_db(path: Optional[str] = None) -> sqlite3.Connection:
    """Open and migrate a local SQLite database."""
    db_path = path or DEFAULT_DB_PATH
    parent = Path(db_path).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    _create_schema(conn)
    return conn


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target_base_url TEXT NOT NULL,
            scope_json TEXT NOT NULL DEFAULT '[]',
            excluded_hosts_json TEXT NOT NULL DEFAULT '[]',
            safety_mode TEXT NOT NULL DEFAULT 'safe',
            max_depth INTEGER NOT NULL DEFAULT 0,
            max_requests INTEGER NOT NULL DEFAULT 0,
            rate_limit REAL NOT NULL DEFAULT 0,
            auth_profiles_json TEXT NOT NULL DEFAULT '[]',
            enabled_modules_json TEXT NOT NULL DEFAULT '[]',
            output_dir TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS requests (
            request_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            source TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            normalized_endpoint TEXT NOT NULL DEFAULT '',
            headers_json TEXT NOT NULL DEFAULT '{}',
            body TEXT,
            auth_profile_id TEXT NOT NULL DEFAULT '',
            auth_role TEXT NOT NULL DEFAULT 'anonymous',
            timestamp TEXT NOT NULL,
            hash TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS responses (
            response_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            headers_json TEXT NOT NULL DEFAULT '{}',
            body_excerpt TEXT,
            body_hash TEXT NOT NULL DEFAULT '',
            content_type TEXT NOT NULL DEFAULT '',
            content_length INTEGER NOT NULL DEFAULT 0,
            response_time_ms INTEGER NOT NULL DEFAULT 0,
            title TEXT NOT NULL DEFAULT '',
            json_shape_hash TEXT NOT NULL DEFAULT '',
            dom_hash TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(request_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            target_url TEXT NOT NULL DEFAULT '',
            normalized_endpoint TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT 'GET',
            parameter_name TEXT NOT NULL DEFAULT '',
            parameter_location TEXT NOT NULL DEFAULT 'unknown',
            auth_role TEXT NOT NULL DEFAULT 'anonymous',
            discovery_method TEXT NOT NULL DEFAULT '',
            discovery_evidence TEXT,
            proof_status TEXT NOT NULL DEFAULT 'not_attempted',
            cwe TEXT NOT NULL DEFAULT '',
            owasp_category TEXT NOT NULL DEFAULT '',
            cvss_score REAL NOT NULL DEFAULT 0,
            cvss_vector TEXT NOT NULL DEFAULT '',
            remediation TEXT,
            references_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS evidence_artifacts (
            artifact_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            task_id TEXT NOT NULL DEFAULT '',
            artifact_type TEXT NOT NULL,
            path TEXT NOT NULL DEFAULT '',
            inline_excerpt TEXT,
            redactions_applied_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_profiles (
            profile_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            base_url TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'anonymous',
            auth_type TEXT NOT NULL DEFAULT 'anonymous',
            storage_state_path TEXT NOT NULL DEFAULT '',
            headers_json TEXT NOT NULL DEFAULT '{}',
            cookies_json TEXT NOT NULL DEFAULT '{}',
            session_health_check_json TEXT NOT NULL DEFAULT '{}',
            refresh_strategy_json TEXT NOT NULL DEFAULT '{}',
            redaction_rules_json TEXT NOT NULL DEFAULT '{}',
            raw_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oob_events (
            event_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL DEFAULT '',
            finding_id TEXT NOT NULL DEFAULT '',
            task_id TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT '',
            callback_host TEXT NOT NULL DEFAULT '',
            remote_address TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '',
            parameter_name TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proof_tasks (
            task_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            safety_mode TEXT NOT NULL DEFAULT 'safe',
            allowed_techniques_json TEXT NOT NULL DEFAULT '[]',
            max_attempts INTEGER NOT NULL DEFAULT 1,
            requires_human_approval INTEGER NOT NULL DEFAULT 0,
            approved_by TEXT,
            approved_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            result TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_requests_scan ON requests(scan_id);
        CREATE INDEX IF NOT EXISTS idx_requests_method ON requests(method);
        CREATE INDEX IF NOT EXISTS idx_requests_host ON requests(host);
        CREATE INDEX IF NOT EXISTS idx_requests_path ON requests(path);
        CREATE INDEX IF NOT EXISTS idx_requests_source ON requests(source);
        CREATE INDEX IF NOT EXISTS idx_requests_auth_role ON requests(auth_role);
        CREATE INDEX IF NOT EXISTS idx_responses_request ON responses(request_id);
        CREATE INDEX IF NOT EXISTS idx_responses_status ON responses(status_code);
        CREATE INDEX IF NOT EXISTS idx_responses_content_type ON responses(content_type);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(normalized_endpoint);
        CREATE INDEX IF NOT EXISTS idx_findings_param ON findings(parameter_name);
        CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_artifacts(finding_id);
        CREATE INDEX IF NOT EXISTS idx_oob_scan ON oob_events(scan_id);
        """
    )
    conn.commit()
