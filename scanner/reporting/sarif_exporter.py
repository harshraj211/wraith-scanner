from __future__ import annotations

import json


class SARIFExporter:
    """Generates SARIF reports for GitHub Advanced Security integration."""

    def generate_sarif(self, findings: list):
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Wraith Scanner",
                            "version": "4.0.0",
                            "informationUri": "https://github.com/yourrepo/wraith",
                        }
                    },
                    "results": [],
                }
            ],
        }

        for finding in findings:
            sarif_severity = "error" if finding.get("severity") in ["CRITICAL", "HIGH"] else "warning"
            result = {
                "ruleId": finding.get("type", "VULN"),
                "level": sarif_severity,
                "message": {"text": finding.get("description", "Vulnerability found")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("file", "unknown")},
                            "region": {"startLine": finding.get("line", 1)},
                        }
                    }
                ],
            }
            sarif_report["runs"][0]["results"].append(result)

        return sarif_report

    def export_to_file(self, findings: list, filepath: str):
        sarif_data = self.generate_sarif(findings)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=4)
