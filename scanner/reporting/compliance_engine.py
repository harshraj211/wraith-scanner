from __future__ import annotations

from collections import defaultdict
from typing import Dict, List


class ComplianceEngine:
    """Maps vulnerabilities to compliance frameworks and generates attestations."""

    FRAMEWORK_MAPPINGS = {
        "SQLi": {
            "OWASP_Top_10_2021": "A03:2021 - Injection",
            "PCI_DSS_v4.0": "6.2.4 (Cover all application software vulnerabilities)",
            "SOC2_Type_II": "CC7.1 (Detection of vulnerabilities)",
        },
        "XSS": {
            "OWASP_Top_10_2021": "A03:2021 - Injection",
            "PCI_DSS_v4.0": "6.2.4 (Cover all application software vulnerabilities)",
            "SOC2_Type_II": "CC7.1 (Detection of vulnerabilities)",
        },
        "Hardcoded_Secret": {
            "OWASP_Top_10_2021": "A07:2021 - Identification and Authentication Failures",
            "PCI_DSS_v4.0": "8.3.2 (Strong cryptography for authentication factors)",
            "SOC2_Type_II": "CC6.1 (Logical and physical access controls)",
        },
        "Broken_Access_Control": {
            "OWASP_Top_10_2021": "A01:2021 - Broken Access Control",
            "PCI_DSS_v4.0": "7.2.1 (Access control model)",
            "SOC2_Type_II": "CC6.3 (Authorization controls)",
        },
    }

    def generate_compliance_report(self, findings: list):
        report = {
            "OWASP_Top_10_2021": {},
            "PCI_DSS_v4.0": {},
            "SOC2_Type_II": {},
        }

        for finding in findings:
            vuln_type = finding.get("type")
            mappings = self.FRAMEWORK_MAPPINGS.get(vuln_type, {})
            evidence_id = finding.get("finding_id") or finding.get("id")

            for framework, control in mappings.items():
                if control not in report[framework]:
                    report[framework][control] = {
                        "status": "FAIL",
                        "findings_count": 0,
                        "severity": finding.get("severity", "MEDIUM"),
                        "evidence_ids": [],
                    }

                report[framework][control]["findings_count"] += 1
                if finding.get("severity") == "CRITICAL":
                    report[framework][control]["severity"] = "CRITICAL"
                if evidence_id:
                    report[framework][control]["evidence_ids"].append(evidence_id)

        for framework, controls in report.items():
            report[framework]["_overall_status"] = "PASS"
            for control_data in controls.values():
                if isinstance(control_data, dict) and control_data.get("severity") in ["CRITICAL", "HIGH"]:
                    report[framework]["_overall_status"] = "FAIL"
                    break

        return report
