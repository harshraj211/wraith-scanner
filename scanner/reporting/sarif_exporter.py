import json

class SARIFExporter:
    """Generates SARIF v2.1.0 reports for GitHub Advanced Security integration."""
    
    SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none"
    }

    def generate_sarif(self, findings: list) -> dict:
        rules = {}
        results = []
        
        for finding in findings:
            rule_id = finding.get("type", "VULN")
            
            # 1. Build Rules dictionary (deduplicated by rule_id)
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.replace("_", " ").title(),
                    "shortDescription": {"text": finding.get("title", rule_id)},
                    "fullDescription": {"text": finding.get("description", "Vulnerability found")},
                    "helpUri": "https://owasp.org/www-community/vulnerabilities/",
                    "defaultConfiguration": {
                        "level": self.SEVERITY_MAP.get(finding.get("severity", "MEDIUM").upper(), "warning")
                    }
                }

            # 2. Build Results array
            location_uri = finding.get("url", finding.get("file", "unknown"))
            line_num = finding.get("line", 1)
            
            results.append({
                "ruleId": rule_id,
                "level": self.SEVERITY_MAP.get(finding.get("severity", "MEDIUM").upper(), "warning"),
                "message": {"text": finding.get("evidence", finding.get("description", ""))},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": location_uri},
                        "region": {"startLine": line_num}
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": f"{location_uri}:{line_num}:{rule_id}"
                }
            })

        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Wraith Scanner",
                        "version": "4.0.0",
                        "informationUri": "https://github.com/yourrepo/wraith",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }]
        }
        return sarif_report

    def export_to_file(self, findings: list, filepath: str):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.generate_sarif(findings), f, indent=4)
