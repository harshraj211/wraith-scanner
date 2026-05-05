"""Repository API for the local Wraith request/response corpus."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scanner.core.models import (
    AuthProfile,
    EvidenceArtifact,
    Finding,
    ProofTask,
    RequestRecord,
    ResponseRecord,
    ScanConfig,
    utc_now,
)
from scanner.storage.db import DEFAULT_DB_PATH, init_db as open_db
from scanner.utils.redaction import redact, redact_headers


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


class StorageRepository:
    """SQLite-backed repository for scans, traffic, findings, and evidence."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or DEFAULT_DB_PATH
        self.conn = open_db(self.path)
        self._lock = threading.RLock()

    def close(self) -> None:
        """Close the SQLite connection and release Windows file handles promptly."""
        with self._lock:
            conn = getattr(self, "conn", None)
            if conn is None:
                return
            try:
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            finally:
                conn.close()
                self.conn = None

    def __enter__(self) -> "StorageRepository":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def create_scan(self, scan_config: ScanConfig) -> None:
        data = scan_config.to_dict()
        with self._lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, target_base_url, scope_json, excluded_hosts_json,
                    safety_mode, max_depth, max_requests, rate_limit,
                    auth_profiles_json, enabled_modules_json, output_dir,
                    created_at, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_config.scan_id,
                    scan_config.target_base_url,
                    _json(scan_config.scope),
                    _json(scan_config.excluded_hosts),
                    scan_config.safety_mode,
                    scan_config.max_depth,
                    scan_config.max_requests,
                    scan_config.rate_limit,
                    _json(redact(scan_config.auth_profiles)),
                    _json(scan_config.enabled_modules),
                    scan_config.output_dir,
                    scan_config.created_at,
                    _json(data),
                ),
            )
            self.conn.commit()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT raw_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return _loads(row["raw_json"], {}) if row else None

    def save_request(self, request_record: RequestRecord) -> str:
        data = request_record.to_dict()
        parsed = urlparse(request_record.url)
        stored_url = data.get("url") or request_record.url
        with self._lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO requests (
                    request_id, scan_id, source, method, url, host, path,
                    normalized_endpoint, headers_json, body, auth_profile_id,
                    auth_role, timestamp, hash, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_record.request_id,
                    request_record.scan_id,
                    request_record.source,
                    request_record.method,
                    stored_url,
                    parsed.netloc,
                    parsed.path or "/",
                    request_record.normalized_endpoint,
                    _json(redact_headers(request_record.headers)),
                    _json(redact(request_record.body)),
                    request_record.auth_profile_id,
                    request_record.auth_role,
                    request_record.timestamp,
                    request_record.hash,
                    _json(data),
                ),
            )
            self.conn.commit()
        return request_record.request_id

    def save_response(self, response_record: ResponseRecord) -> str:
        data = response_record.to_dict()
        with self._lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO responses (
                    response_id, request_id, status_code, headers_json, body_excerpt,
                    body_hash, content_type, content_length, response_time_ms,
                    title, json_shape_hash, dom_hash, timestamp, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response_record.response_id,
                    response_record.request_id,
                    response_record.status_code,
                    _json(redact_headers(response_record.headers)),
                    response_record.body_excerpt,
                    response_record.body_hash,
                    response_record.content_type,
                    response_record.content_length,
                    response_record.response_time_ms,
                    response_record.title,
                    response_record.json_shape_hash,
                    response_record.dom_hash,
                    response_record.timestamp,
                    _json(data),
                ),
            )
            self.conn.commit()
        return response_record.response_id

    def save_finding(self, finding: Finding) -> str:
        data = finding.to_dict()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO findings (
                finding_id, scan_id, title, vuln_type, severity, confidence,
                target_url, normalized_endpoint, method, parameter_name,
                parameter_location, auth_role, discovery_method,
                discovery_evidence, proof_status, cwe, owasp_category,
                cvss_score, cvss_vector, remediation, references_json,
                created_at, updated_at, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_id,
                finding.scan_id,
                finding.title,
                finding.vuln_type,
                finding.severity,
                finding.confidence,
                finding.target_url,
                finding.normalized_endpoint,
                finding.method,
                finding.parameter_name,
                finding.parameter_location,
                finding.auth_role,
                finding.discovery_method,
                finding.discovery_evidence,
                finding.proof_status,
                finding.cwe,
                finding.owasp_category,
                finding.cvss_score,
                finding.cvss_vector,
                finding.remediation,
                _json(finding.references),
                finding.created_at,
                finding.updated_at,
                _json(data),
            ),
        )
        self.conn.commit()
        return finding.finding_id

    def update_finding(self, finding: Finding) -> str:
        finding.updated_at = utc_now()
        return self.save_finding(finding)

    def save_evidence_artifact(self, artifact: EvidenceArtifact) -> str:
        data = artifact.to_dict()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO evidence_artifacts (
                artifact_id, finding_id, task_id, artifact_type, path,
                inline_excerpt, redactions_applied_json, created_at, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.artifact_id,
                artifact.finding_id,
                artifact.task_id,
                artifact.artifact_type,
                artifact.path,
                artifact.inline_excerpt,
                _json(artifact.redactions_applied),
                artifact.created_at,
                _json(data),
            ),
        )
        self.conn.commit()
        return artifact.artifact_id

    def save_auth_profile(self, profile: AuthProfile) -> str:
        data = profile.to_dict()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO auth_profiles (
                profile_id, name, base_url, role, auth_type, storage_state_path,
                headers_json, cookies_json, session_health_check_json,
                refresh_strategy_json, redaction_rules_json, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile.profile_id,
                profile.name,
                profile.base_url,
                profile.role,
                profile.auth_type,
                profile.storage_state_path,
                _json(redact_headers(profile.headers)),
                _json(redact(profile.cookies)),
                _json(profile.session_health_check),
                _json(redact(profile.refresh_strategy)),
                _json(profile.redaction_rules),
                _json(data),
            ),
        )
        self.conn.commit()
        return profile.profile_id

    def save_proof_task(self, task: ProofTask) -> str:
        data = task.to_dict()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO proof_tasks (
                task_id, finding_id, safety_mode, allowed_techniques_json,
                max_attempts, requires_human_approval, approved_by, approved_at,
                status, result, created_at, updated_at, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.task_id,
                task.finding_id,
                task.safety_mode,
                _json(task.allowed_techniques),
                task.max_attempts,
                1 if task.requires_human_approval else 0,
                task.approved_by,
                task.approved_at,
                task.status,
                task.result,
                task.created_at,
                task.updated_at,
                _json(data),
            ),
        )
        self.conn.commit()
        return task.task_id

    def get_proof_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT raw_json FROM proof_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        return _loads(row["raw_json"], {}) if row else None

    def list_proof_tasks(self, finding_id: str = "") -> List[Dict[str, Any]]:
        where: List[str] = []
        params: List[Any] = []
        if finding_id:
            where.append("finding_id = ?")
            params.append(finding_id)
        query = "SELECT raw_json FROM proof_tasks"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY created_at ASC"
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [_loads(row["raw_json"], {}) for row in rows]

    def list_evidence_artifacts(self, finding_id: str = "", task_id: str = "") -> List[Dict[str, Any]]:
        where: List[str] = []
        params: List[Any] = []
        if finding_id:
            where.append("finding_id = ?")
            params.append(finding_id)
        if task_id:
            where.append("task_id = ?")
            params.append(task_id)
        query = "SELECT raw_json FROM evidence_artifacts"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY created_at ASC"
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [_loads(row["raw_json"], {}) for row in rows]

    def save_oob_event(self, event: Dict[str, Any]) -> str:
        event = redact(event or {})
        event_id = str(event.get("event_id") or "oob_" + uuid.uuid4().hex[:16])
        self.conn.execute(
            """
            INSERT OR REPLACE INTO oob_events (
                event_id, scan_id, finding_id, task_id, protocol, callback_host,
                remote_address, url, parameter_name, evidence_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                str(event.get("scan_id") or ""),
                str(event.get("finding_id") or ""),
                str(event.get("task_id") or ""),
                str(event.get("protocol") or ""),
                str(event.get("callback_host") or event.get("host") or ""),
                str(event.get("remote_address") or event.get("remote") or ""),
                str(event.get("url") or ""),
                str(event.get("parameter_name") or event.get("param") or ""),
                _json(event),
                str(event.get("created_at") or utc_now()),
            ),
        )
        self.conn.commit()
        return event_id

    def list_requests(self, scan_id: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        filters = filters or {}
        where = ["r.scan_id = ?"]
        params: List[Any] = [scan_id]

        if filters.get("method"):
            where.append("r.method = ?")
            params.append(str(filters["method"]).upper())
        if filters.get("host"):
            where.append("r.host = ?")
            params.append(str(filters["host"]))
        if filters.get("path_contains"):
            where.append("r.path LIKE ?")
            params.append(f"%{filters['path_contains']}%")
        if filters.get("status_code") is not None:
            where.append(
                "EXISTS (SELECT 1 FROM responses rsp WHERE rsp.request_id = r.request_id AND rsp.status_code = ?)"
            )
            params.append(int(filters["status_code"]))
        if filters.get("content_type"):
            where.append(
                "EXISTS (SELECT 1 FROM responses rsp WHERE rsp.request_id = r.request_id AND rsp.content_type LIKE ?)"
            )
            params.append(f"%{filters['content_type']}%")
        if filters.get("source"):
            where.append("r.source = ?")
            params.append(str(filters["source"]))
        if filters.get("auth_role"):
            where.append("r.auth_role = ?")
            params.append(str(filters["auth_role"]))
        if filters.get("has_finding") is not None:
            exists = (
                "EXISTS (SELECT 1 FROM findings f WHERE f.scan_id = r.scan_id "
                "AND f.normalized_endpoint = r.normalized_endpoint)"
            )
            where.append(exists if filters.get("has_finding") else f"NOT {exists}")
        if filters.get("parameter_name"):
            needle = f"%{filters['parameter_name']}%"
            where.append("(r.url LIKE ? OR r.body LIKE ?)")
            params.extend([needle, needle])

        with self._lock:
            rows = self.conn.execute(
                f"""
                SELECT
                    r.raw_json,
                    rsp.status_code,
                    rsp.content_type,
                    rsp.content_length,
                    rsp.response_time_ms,
                    rsp.timestamp AS response_timestamp
                FROM requests r
                LEFT JOIN responses rsp ON rsp.response_id = (
                    SELECT response_id
                    FROM responses latest_rsp
                    WHERE latest_rsp.request_id = r.request_id
                    ORDER BY latest_rsp.timestamp DESC
                    LIMIT 1
                )
                WHERE {' AND '.join(where)}
                ORDER BY r.timestamp ASC
                """,
                params,
            ).fetchall()
        enriched = []
        for row in rows:
            item = _loads(row["raw_json"], {})
            item["response"] = {
                "status_code": row["status_code"],
                "content_type": row["content_type"] or "",
                "content_length": row["content_length"] or 0,
                "response_time_ms": row["response_time_ms"] or 0,
                "timestamp": row["response_timestamp"] or "",
            } if row["status_code"] is not None else None
            enriched.append(item)
        return enriched

    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT raw_json FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        return _loads(row["raw_json"], {}) if row else None

    def get_response_for_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT raw_json FROM responses WHERE request_id = ? ORDER BY timestamp DESC LIMIT 1",
                (request_id,),
            ).fetchone()
        return _loads(row["raw_json"], {}) if row else None

    def list_findings(self, scan_id: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        filters = filters or {}
        where = ["scan_id = ?"]
        params: List[Any] = [scan_id]
        if filters.get("severity"):
            where.append("severity = ?")
            params.append(str(filters["severity"]).lower())
        if filters.get("vuln_type"):
            where.append("vuln_type = ?")
            params.append(str(filters["vuln_type"]).lower())
        if filters.get("auth_role"):
            where.append("auth_role = ?")
            params.append(str(filters["auth_role"]))
        with self._lock:
            rows = self.conn.execute(
                f"SELECT raw_json FROM findings WHERE {' AND '.join(where)} ORDER BY severity, title",
                params,
            ).fetchall()
        return [_loads(row["raw_json"], {}) for row in rows]

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT raw_json FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
        return _loads(row["raw_json"], {}) if row else None


_default_repo: Optional[StorageRepository] = None


def init_db(path: Optional[str] = None) -> StorageRepository:
    global _default_repo
    _default_repo = StorageRepository(path)
    return _default_repo


def get_repository(path: Optional[str] = None) -> StorageRepository:
    global _default_repo
    if path is not None:
        return StorageRepository(path)
    if _default_repo is None:
        _default_repo = StorageRepository()
    return _default_repo


def create_scan(scan_config: ScanConfig) -> None:
    get_repository().create_scan(scan_config)


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    return get_repository().get_scan(scan_id)


def save_request(request_record: RequestRecord) -> str:
    return get_repository().save_request(request_record)


def save_response(response_record: ResponseRecord) -> str:
    return get_repository().save_response(response_record)


def save_finding(finding: Finding) -> str:
    return get_repository().save_finding(finding)


def update_finding(finding: Finding) -> str:
    return get_repository().update_finding(finding)


def save_evidence_artifact(artifact: EvidenceArtifact) -> str:
    return get_repository().save_evidence_artifact(artifact)


def save_proof_task(task: ProofTask) -> str:
    return get_repository().save_proof_task(task)


def list_requests(scan_id: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return get_repository().list_requests(scan_id, filters)


def get_request(request_id: str) -> Optional[Dict[str, Any]]:
    return get_repository().get_request(request_id)


def get_response_for_request(request_id: str) -> Optional[Dict[str, Any]]:
    return get_repository().get_response_for_request(request_id)


def list_findings(scan_id: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return get_repository().list_findings(scan_id, filters)


def get_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    return get_repository().get_finding(finding_id)


def get_proof_task(task_id: str) -> Optional[Dict[str, Any]]:
    return get_repository().get_proof_task(task_id)


def list_proof_tasks(finding_id: str = "") -> List[Dict[str, Any]]:
    return get_repository().list_proof_tasks(finding_id)


def list_evidence_artifacts(finding_id: str = "", task_id: str = "") -> List[Dict[str, Any]]:
    return get_repository().list_evidence_artifacts(finding_id, task_id)
