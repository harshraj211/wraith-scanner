from __future__ import annotations

from typing import Dict, List


class IaCScanner:
    """Scans IaC manifests for common misconfigurations."""

    MISCONFIG_RULES = {
        "aws_s3_bucket": {"check": "acl", "fail_value": "public-read"},
        "aws_security_group": {"check": "ingress.cidr_blocks", "fail_value": ["0.0.0.0/0"]},
        "k8s_deployment": {"check": "spec.template.spec.containers.securityContext.privileged", "fail_value": True},
    }

    def scan_terraform(self, file_path: str) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if 'acl = "public-read"' in content:
            findings.append(
                {
                    "type": "SAST_IAC",
                    "severity": "HIGH",
                    "file": file_path,
                    "message": "S3 Bucket is publicly readable",
                }
            )
        return findings
