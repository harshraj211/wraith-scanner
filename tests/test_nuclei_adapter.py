import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_server import app
from scanner.core.models import RequestRecord, ScanConfig
from scanner.integrations.nuclei_adapter import NucleiAdapter, NucleiRunConfig, parse_jsonl
from scanner.storage.repository import StorageRepository


NUCLEI_JSONL = json.dumps({
    "template-id": "cve-2024-demo",
    "template-path": "http/cves/2024/cve-2024-demo.yaml",
    "host": "https://app.example.test",
    "matched-at": "https://app.example.test/admin",
    "type": "http",
    "matcher-name": "status",
    "extracted-results": ["Demo banner"],
    "info": {
        "name": "Demo CVE Exposure",
        "severity": "high",
        "description": "demo",
        "classification": {
            "cve-id": "CVE-2024-0001",
            "cwe-id": "CWE-200",
            "cvss-score": 8.1,
            "cvss-vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        "reference": ["https://example.test/advisory"],
        "remediation": "Upgrade the affected component."
    }
})


class NucleiAdapterTests(unittest.TestCase):
    def test_jsonl_parser_skips_non_json_lines(self):
        parsed, skipped = parse_jsonl(f"{NUCLEI_JSONL}\nnot-json\n")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(skipped, 1)

    @patch("scanner.integrations.nuclei_adapter.find_nuclei_binary", return_value="nuclei")
    @patch("scanner.integrations.nuclei_adapter.subprocess.run")
    def test_adapter_runs_safe_command_and_maps_findings(self, run_mock, _which):
        run_mock.return_value = subprocess.CompletedProcess(
            args=["nuclei"],
            returncode=0,
            stdout=NUCLEI_JSONL + "\n",
            stderr="",
        )
        adapter = NucleiAdapter()
        result = adapter.run(NucleiRunConfig(
            scan_id="scan-nuclei",
            target_base_url="https://app.example.test",
            targets=["https://app.example.test"],
            templates=["templates/cves"],
            severity=["high"],
        ))

        self.assertTrue(result.available)
        self.assertEqual(result.raw_count, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Demo CVE Exposure")
        self.assertEqual(result.findings[0].vuln_type, "vulnerable-component")
        command = run_mock.call_args.args[0]
        self.assertIn("-jsonl", command)
        self.assertIn("-duc", command)
        self.assertIn("-exclude-tags", command)
        self.assertIn("destructive", ",".join(command))

    @patch("api_server.NucleiAdapter")
    def test_nuclei_api_persists_findings_and_evidence(self, adapter_cls):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = StorageRepository(str(Path(tmpdir) / "wraith.sqlite3"))
            scan = ScanConfig(scan_id="scan-api-nuclei", target_base_url="https://app.example.test")
            repo.create_scan(scan)
            repo.save_request(RequestRecord.create(
                scan_id=scan.scan_id,
                source="crawler",
                method="GET",
                url="https://app.example.test/admin",
            ))
            # Rebuild the result with mocked stdout rather than requiring nuclei.
            with patch("scanner.integrations.nuclei_adapter.subprocess.run") as run_mock:
                run_mock.return_value = subprocess.CompletedProcess(["nuclei"], 0, NUCLEI_JSONL + "\n", "")
                with patch("scanner.integrations.nuclei_adapter.find_nuclei_binary", return_value="nuclei"):
                    real_result = NucleiAdapter().run(NucleiRunConfig(
                        scan_id=scan.scan_id,
                        target_base_url=scan.target_base_url,
                        targets=[scan.target_base_url],
                    ))

            adapter_cls.return_value.run.return_value = real_result
            adapter_cls.return_value.available = True
            with patch("api_server._storage_repo", return_value=repo):
                client = app.test_client()
                response = client.post("/api/integrations/nuclei/run", json={
                    "scan_id": scan.scan_id,
                    "targets": ["https://app.example.test/admin"],
                    "severity": ["high"],
                })

            self.assertEqual(response.status_code, 200, response.get_json())
            payload = response.get_json()
            self.assertEqual(payload["raw_count"], 1)
            findings = repo.list_findings(scan.scan_id, {})
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["discovery_method"], "nuclei")
            artifacts = repo.list_evidence_artifacts(finding_id=findings[0]["finding_id"])
            self.assertEqual(len(artifacts), 1)
            repo.close()


if __name__ == "__main__":
    unittest.main()
