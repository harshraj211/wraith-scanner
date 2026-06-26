from __future__ import annotations

import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)


class CloudSecretScanner:
    """SAST module to scan source code for hardcoded cloud credentials and API keys."""

    SECRET_PATTERNS = {
        "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Secret Access Key": re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])"),
        "Google Cloud API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
        "Private Key Block": re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    }

    def scan_file(self, file_path: str, content: str) -> List[Dict[str, object]]:
        findings = []
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                secret_value = match.group()
                masked_secret = secret_value[:4] + "..." + secret_value[-4:]
                line_num = content[:match.start()].count("\n") + 1
                findings.append(
                    {
                        "type": "Hardcoded_Secret",
                        "subtype": secret_type,
                        "severity": "CRITICAL",
                        "confidence": 90,
                        "file": file_path,
                        "line": line_num,
                        "evidence": f"Found {secret_type}: {masked_secret}",
                        "remediation": "Move secrets to environment variables or a secret manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
                        "source": "cloud-secret-scanner",
                    }
                )
        return findings

    def verify_aws_key(self, access_key: str, secret_key: str):
        try:
            import boto3
            client = boto3.client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            identity = client.get_caller_identity()
            return True, identity.get("Account")
        except Exception:
            return False, None
