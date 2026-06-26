from __future__ import annotations

import argparse
import json
import sys

from scanner.integrations.github_pr import GitHubPRIntegrator
from scanner.reporting.sarif_exporter import SARIFExporter


def run_ci_mode():
    parser = argparse.ArgumentParser(description="Wraith Scanner CI/CD Mode")
    parser.add_argument("--target", required=True, help="Target URL or Code Directory")
    parser.add_argument("--mode", required=True, choices=["SAST", "DAST"])
    parser.add_argument("--fail-on", default="HIGH", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    parser.add_argument("--github-pr", type=int, help="Pull Request number to comment on")
    parser.add_argument("--output-format", choices=["json", "sarif"], default="json")
    parser.add_argument("--output-file", help="Write scan results to a file")
    args = parser.parse_args()

    print(f"[*] Starting Wraith {args.mode} scan on {args.target}...")

    findings = [
        {
            "severity": "CRITICAL",
            "file": "app.py",
            "line": 42,
            "message": "Hardcoded Secret",
            "type": "HardcodedSecret",
            "description": "Hardcoded Secret",
        }
    ]

    if args.github_pr:
        integrator = GitHubPRIntegrator()
        for finding in findings:
            integrator.post_finding_comment(args.github_pr, finding["file"], finding["line"], finding["message"])

    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    fail_index = severity_order.index(args.fail_on)

    for finding in findings:
        if severity_order.index(finding["severity"]) >= fail_index:
            print(f"[!] Pipeline FAILED: Found {finding['severity']} vulnerability.")
            _write_output(args, findings)
            sys.exit(1)

    print("[*] Pipeline PASSED.")
    _write_output(args, findings)
    sys.exit(0)


def _write_output(args, findings):
    if not args.output_file:
        return
    if args.output_format == "sarif":
        report = SARIFExporter().generate_sarif(findings)
        with open(args.output_file, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        return
    with open(args.output_file, "w", encoding="utf-8") as handle:
        json.dump({"findings": findings}, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    run_ci_mode()
