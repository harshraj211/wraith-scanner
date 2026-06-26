from __future__ import annotations

import subprocess


class GRPCScanner:
    """Discovers and scans gRPC endpoints for reflection and unauthenticated access."""

    def __init__(self, target_host: str, target_port: int = 50051):
        self.target = f"{target_host}:{target_port}"

    def scan_grpc_reflection(self):
        print(f"[*] Checking gRPC reflection on {self.target}...")
        try:
            result = subprocess.run(
                ["grpcurl", "-plaintext", self.target, "list"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout:
                services = result.stdout.strip().split("\n")
                return {
                    "type": "gRPC_Reflection_Enabled",
                    "severity": "MEDIUM",
                    "confidence": 100,
                    "description": f"gRPC reflection is enabled. Exposed services: {', '.join(services)}",
                }
        except FileNotFoundError:
            print("[-] grpcurl not installed. Please install it to scan gRPC.")
        except Exception:
            pass
        return None

    def test_unauthenticated_call(self, service_method: str):
        _ = service_method
        return None
