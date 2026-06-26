import subprocess
import json
import os

class SCAScanner:
    """Checks Python and Node.js dependencies for known CVEs."""
    
    def scan_python(self, repo_path: str):
        findings = []
        try:
            # Requires pip-audit installed in the environment
            result = subprocess.run(['pip-audit', '-r', os.path.join(repo_path, 'requirements.txt'), '-f', 'json'], 
                                   capture_output=True, text=True, timeout=60)
            if result.stdout:
                data = json.loads(result.stdout)
                for dep in data.get('dependencies', []):
                    for vuln in dep.get('vulns', []):
                        findings.append({
                            "type": "SCA_Python_CVE",
                            "severity": "HIGH",
                            "confidence": 100,
                            "package": dep.get('name'),
                            "version": dep.get('version'),
                            "cve": vuln.get('id'),
                            "description": vuln.get('description', '')[:200]
                        })
        except Exception as e:
            print(f"SCA Python scan failed: {e}")
        return findings

    def scan_nodejs(self, repo_path: str):
        findings = []
        try:
            # Run npm audit
            result = subprocess.run(['npm', 'audit', '--json'], cwd=repo_path, capture_output=True, text=True, timeout=60)
            if result.stdout:
                data = json.loads(result.stdout)
                for advisory in data.get('vulnerabilities', {}).values():
                    findings.append({
                        "type": "SCA_Nodejs_CVE",
                        "severity": advisory.get('severity', 'MEDIUM').upper(),
                        "confidence": 100,
                        "package": advisory.get('name'),
                        "description": f"Vulnerable via {advisory.get('via', 'unknown')}"
                    })
        except Exception as e:
            print(f"SCA Node.js scan failed: {e}")
        return findings
