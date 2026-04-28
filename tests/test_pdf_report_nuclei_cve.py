import os
import tempfile
import unittest

from scanner.reporting.pdf_generator import (
    _cve_records,
    _finding_cvss_data,
    _is_nuclei_finding,
    _normalize_report_finding,
    generate_pdf_report,
)


def canonical_nuclei_finding():
    return {
        "finding_id": "fnd_demo",
        "title": "CVE-2024-9999 Demo Component Exposure",
        "vuln_type": "vulnerable-component",
        "severity": "critical",
        "confidence": 95,
        "target_url": "https://example.test/login",
        "normalized_endpoint": "/login",
        "method": "GET",
        "parameter_name": "cves/demo-template",
        "parameter_location": "unknown",
        "auth_role": "nuclei",
        "discovery_method": "nuclei",
        "discovery_evidence": "Nuclei template cves/demo-template matched CVE-2024-9999.",
        "proof_status": "not_attempted",
        "cwe": "CWE-1035",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Upgrade the affected component.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-9999"],
        "metadata": {
            "cve_intelligence": [
                {
                    "cve_id": "CVE-2024-9999",
                    "nvd_severity": "critical",
                    "cvss_score": 9.8,
                    "epss_score": 0.72,
                    "cisa_kev": True,
                    "priority_score": 99,
                    "description": "Demo public vulnerability description.",
                }
            ]
        },
    }


class PdfReportNucleiCveTests(unittest.TestCase):
    def test_normalizes_canonical_nuclei_finding(self):
        normalized = _normalize_report_finding(canonical_nuclei_finding())

        self.assertEqual(normalized["type"], "vulnerable-component")
        self.assertEqual(normalized["url"], "https://example.test/login")
        self.assertEqual(normalized["param"], "cves/demo-template")
        self.assertTrue(_is_nuclei_finding(normalized))
        self.assertEqual(_finding_cvss_data(normalized)["score"], 9.8)
        self.assertEqual(_cve_records(normalized)[0]["cve_id"], "CVE-2024-9999")

    def test_generate_pdf_report_accepts_cve_enriched_nuclei_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "wraith-nuclei-cve.pdf")
            generate_pdf_report(
                "https://example.test",
                ["https://example.test/login"],
                [],
                [canonical_nuclei_finding()],
                output_path,
            )

            self.assertTrue(os.path.exists(output_path))
            self.assertGreater(os.path.getsize(output_path), 1000)


if __name__ == "__main__":
    unittest.main()
