import subprocess
import json

class ContainerImageScanner:
    """Scans Docker images using Trivy for OS-level vulnerabilities."""
    
    def scan_image(self, image_name: str):
        findings = []
        try:
            # Requires Trivy installed: https://aquasecurity.github.io/trivy/
            cmd = ['trivy', 'image', '--format', 'json', image_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                data = json.loads(result.stdout)
                for target in data.get('Results', []):
                    for vuln in target.get('Vulnerabilities', []):
                        findings.append({
                            "type": "Container_CVE",
                            "severity": vuln.get('Severity', 'UNKNOWN'),
                            "confidence": 100,
                            "package": vuln.get('PkgName'),
                            "installed_version": vuln.get('InstalledVersion'),
                            "fixed_version": vuln.get('FixedVersion'),
                            "cve": vuln.get('VulnerabilityID'),
                            "description": vuln.get('Title', 'Container OS vulnerability')
                        })
        except FileNotFoundError:
            print("[-] Trivy not installed. Skipping container scan.")
        except Exception as e:
            print(f"Container scan failed: {e}")
            
        return findings
