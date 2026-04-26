import json
import tempfile
import unittest
from pathlib import Path

from scanner.core.models import (
    EvidenceArtifact,
    Finding,
    RequestRecord,
    ResponseRecord,
    ScanConfig,
    findings_from_legacy,
)
from scanner.reporting.json_export import build_scan_json
from scanner.storage.repository import StorageRepository
from scanner.utils.redaction import MASK, redact, redact_headers, redact_text


class CanonicalModelTests(unittest.TestCase):
    def test_finding_id_is_stable_across_equivalent_object_paths(self):
        first = Finding.from_legacy(
            {
                "type": "idor",
                "url": "https://app.example.test/users/123?view=full",
                "param": "id",
                "evidence": "object visible",
                "confidence": 90,
            },
            target_url="https://app.example.test",
            scan_id="scan-a",
        )
        second = Finding.from_legacy(
            {
                "type": "idor",
                "url": "https://app.example.test/users/456?view=full",
                "param": "id",
                "evidence": "object visible",
                "confidence": 90,
            },
            target_url="https://app.example.test",
            scan_id="scan-b",
        )

        self.assertEqual(first.normalized_endpoint, "/users/{int}")
        self.assertEqual(first.finding_id, second.finding_id)

    def test_legacy_finding_conversion_populates_cvss_and_proof_defaults(self):
        finding = findings_from_legacy(
            [
                {
                    "type": "sqli-error",
                    "url": "https://app.example.test/search?q=abc",
                    "param": "q",
                    "evidence": "SQL syntax error near token",
                    "confidence": 95,
                }
            ],
            target_url="https://app.example.test",
            scan_id="scan-1",
        )[0]

        self.assertEqual(finding.parameter_location, "query")
        self.assertEqual(finding.proof_status, "not_attempted")
        self.assertGreaterEqual(finding.cvss_score, 9.0)
        self.assertIn("CWE-89", finding.cwe)


class RedactionTests(unittest.TestCase):
    def test_redacts_auth_headers_tokens_and_sensitive_keys(self):
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop.qrstuvwxyz123456",
            "Cookie": "sessionid=abc12345; theme=dark",
            "X-Trace": "safe",
        }
        body = {
            "username": "alice",
            "password": "correct horse battery staple",
            "nested": {"api_key": "super-secret-api-key"},
        }

        redacted_headers = redact_headers(headers)
        redacted_body = redact(body)

        self.assertEqual(redacted_headers["Authorization"], MASK)
        self.assertEqual(redacted_headers["Cookie"], MASK)
        self.assertEqual(redacted_headers["X-Trace"], "safe")
        self.assertEqual(redacted_body["password"], MASK)
        self.assertEqual(redacted_body["nested"]["api_key"], MASK)

    def test_email_redaction_is_configurable(self):
        text = "Contact admin@example.test with token=abc123456789"

        self.assertIn("admin@example.test", redact_text(text))
        self.assertNotIn("admin@example.test", redact_text(text, redact_emails=True))
        self.assertIn(MASK, redact_text(text, redact_emails=True))


class StorageRepositoryTests(unittest.TestCase):
    def test_save_list_get_flow_persists_redacted_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "wraith.sqlite3")
            repo = StorageRepository(db_path)
            scan = ScanConfig(
                scan_id="scan-1",
                target_base_url="https://app.example.test",
                max_depth=2,
            )
            repo.create_scan(scan)

            request = RequestRecord.create(
                scan_id=scan.scan_id,
                source="crawler",
                method="GET",
                url="https://app.example.test/users/123?token=abc123456789",
                headers={"Authorization": "Bearer abc123456789"},
                auth_role="user_a",
            )
            repo.save_request(request)
            repo.save_response(
                ResponseRecord.create(
                    request_id=request.request_id,
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"id": 123, "email": "person@example.test"}),
                    response_time_ms=42,
                )
            )
            finding = Finding.from_legacy(
                {
                    "type": "idor",
                    "url": request.url,
                    "param": "id",
                    "evidence": "role diff showed unauthorized access",
                    "confidence": 90,
                },
                target_url=scan.target_base_url,
                scan_id=scan.scan_id,
                auth_role="user_a",
            )
            repo.save_finding(finding)
            repo.save_evidence_artifact(
                EvidenceArtifact(
                    artifact_id="",
                    finding_id=finding.finding_id,
                    task_id="",
                    artifact_type="response",
                    inline_excerpt="Authorization: Bearer abc123456789",
                )
            )
            repo.close()

            reopened = StorageRepository(db_path)
            requests = reopened.list_requests(
                scan.scan_id,
                {"method": "GET", "status_code": 200, "auth_role": "user_a", "has_finding": True},
            )
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0]["headers"]["Authorization"], MASK)
            self.assertIn("token=" + MASK, requests[0]["url"])

            response = reopened.get_response_for_request(request.request_id)
            self.assertEqual(response["status_code"], 200)
            self.assertEqual(response["content_type"], "application/json")

            findings = reopened.list_findings(scan.scan_id, {"vuln_type": "idor"})
            self.assertEqual(len(findings), 1)
            self.assertEqual(reopened.get_finding(finding.finding_id)["finding_id"], finding.finding_id)
            reopened.close()

    def test_canonical_json_export_contains_schema_and_redacted_findings(self):
        scan = ScanConfig(scan_id="scan-json", target_base_url="https://app.example.test")
        finding = Finding.from_legacy(
            {
                "type": "xss-reflected",
                "url": "https://app.example.test/search?q=x",
                "param": "q",
                "evidence": "Authorization: Bearer abc123456789 was reflected",
                "confidence": 90,
            },
            target_url=scan.target_base_url,
            scan_id=scan.scan_id,
        )

        payload = build_scan_json(
            scan_config=scan,
            urls=["https://app.example.test/search?q=x"],
            forms=[],
            findings=[finding],
        )

        self.assertEqual(payload["schema_version"], "wraith.scan.v1")
        self.assertEqual(payload["findings"][0]["finding_id"], finding.finding_id)
        self.assertNotIn("abc123456789", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()

