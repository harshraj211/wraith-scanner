import re
import math
from collections import Counter
from typing import Dict, List, Any

class CloudSecretScanner:
    """SAST module to scan for hardcoded credentials using Regex AND Entropy analysis."""
    
    # Known patterns (High confidence)
    SECRET_PATTERNS = {
        "AWS Access Key ID": re.compile(r'AKIA[0-9A-Z]{16}'),
        "Google Cloud API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "Slack Token": re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,48}'),
        "Private Key Block": re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')
    }

    # Heuristic patterns for generic secrets (e.g., password = "...")
    GENERIC_SECRET_PATTERNS = [
        re.compile(r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[:=]\s*["\']([^"\']{12,})["\']', re.IGNORECASE)
    ]

    # Min entropy threshold (typically 3.5 to 4.5 for base64/hex strings)
    ENTROPY_THRESHOLD = 3.5
    MIN_SECRET_LENGTH = 20

    @staticmethod
    def _calculate_entropy(string: str) -> float:
        """Calculates Shannon entropy for a given string."""
        if not string:
            return 0.0
        counts = Counter(string)
        length = len(string)
        entropy = 0.0
        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def scan_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Check known regex patterns
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(file_path, line_num, secret_type, match.group()))

        # 2. Check generic assignments with Entropy Analysis
        for pattern in self.GENERIC_SECRET_PATTERNS:
            for match in pattern.finditer(content):
                secret_value = match.group(1)
                entropy = self._calculate_entropy(secret_value)
                
                # If the extracted value has high entropy, it's likely a real secret, not "test123"
                if entropy >= self.ENTROPY_THRESHOLD and len(secret_value) >= self.MIN_SECRET_LENGTH:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(file_path, line_num, "High-Entropy Secret", secret_value, entropy))

        return findings

    def _create_finding(self, file_path, line_num, secret_type, secret_value, entropy=0.0):
        masked = secret_value[:4] + "..." + secret_value[-4:] if len(secret_value) > 8 else "****"
        return {
            "type": "Hardcoded_Secret",
            "subtype": secret_type,
            "severity": "CRITICAL",
            "confidence": 95 if entropy == 0.0 else 80, # Regex is 95%, Entropy is 80%
            "file": file_path,
            "line": line_num,
            "evidence": f"Found {secret_type}: {masked} (Entropy: {entropy:.2f})",
            "remediation": "Move secrets to environment variables or a secret manager.",
            "source": "cloud-secret-scanner"
        }

    def verify_aws_key(self, access_key: str, secret_key: str):
        try:
            import boto3
            client = boto3.client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            identity = client.get_caller_identity()
            return True, identity.get("Account")
        except Exception:
            return False, None
