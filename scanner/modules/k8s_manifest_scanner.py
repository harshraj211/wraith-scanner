from __future__ import annotations

import logging
from typing import Dict, List

import yaml

logger = logging.getLogger(__name__)


class K8sManifestScanner:
    """SAST module to scan Kubernetes YAML files for insecure configurations."""

    def scan_yaml(self, file_path: str) -> List[Dict[str, object]]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                docs = list(yaml.safe_load_all(f))
        except Exception:
            return findings

        for doc in docs:
            if not doc or "kind" not in doc:
                continue

            kind = doc.get("kind")
            spec = doc.get("spec", {})

            if kind in {"Deployment", "Pod"}:
                containers = spec.get("template", {}).get("spec", {}).get("containers", spec.get("containers", []))
                for container in containers or []:
                    security_context = container.get("securityContext", {}) or {}
                    if security_context.get("privileged") is True:
                        findings.append(
                            {
                                "type": "K8s_Privileged_Container",
                                "severity": "HIGH",
                                "confidence": 100,
                                "file": file_path,
                                "description": f"Container '{container.get('name')}' is running in privileged mode. This gives it root access to the host node.",
                                "source": "k8s-manifest-scanner",
                            }
                        )

                    if security_context.get("runAsNonRoot") is not True:
                        findings.append(
                            {
                                "type": "K8s_Running_As_Root",
                                "severity": "MEDIUM",
                                "confidence": 100,
                                "file": file_path,
                                "description": f"Container '{container.get('name')}' is not explicitly configured to run as a non-root user.",
                                "source": "k8s-manifest-scanner",
                            }
                        )
        return findings
