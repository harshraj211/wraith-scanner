import argparse
import sys
import os
import asyncio
import json

# Adjust path to import scanner modules if running from root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.core.async_engine import AsyncHTTPSession, AsyncResponse
from scanner.modules.sqli_scanner import SQLiScanner
from scanner.modules.xss_scanner import XSSScanner
from scanner.modules.cmdi_scanner import CMDIScanner
from scanner.modules.path_traversal_scanner import PathTraversalScanner
from scanner.reporting.sarif_exporter import SARIFExporter
from scanner.reporting.junit_exporter import JUnitExporter

def run_ci_mode():
    parser = argparse.ArgumentParser(description="Wraith Scanner CI/CD Mode")
    parser.add_argument("--target", required=True, help="Target URL or Code Directory")
    parser.add_argument("--mode", required=True, choices=["SAST", "DAST"])
    parser.add_argument("--output-format", default="sarif", choices=["sarif", "junit", "json"])
    parser.add_argument("--output-file", default="wraith-results.sarif")
    parser.add_argument("--fail-on", default="HIGH", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    args = parser.parse_args()

    print(f"[*] Starting Wraith {args.mode} scan on {args.target}...")
    
    findings = []
    
    if args.mode == "DAST":
        # Real DAST Engine invocation
        async def execute_dast():
            # For CI/CD, we scan the exact target URL provided
            # Initialize connection session and run scan
            async with AsyncHTTPSession(max_concurrent=5, timeout=10) as session:
                sqli = SQLiScanner()
                xss = XSSScanner()
                cmdi = CMDIScanner()
                path = PathTraversalScanner()
                
                # Check target base scan
                # Collect findings across modules
                url_findings = []
                # Running scans on direct input URL
                for scanner in [sqli, xss, cmdi, path]:
                    try:
                        res = await scanner.scan_url_async(args.target, {"q": "test"}, session)
                        url_findings.extend(res)
                    except Exception as e:
                        print(f"[{type(scanner).__name__}] failed: {e}")
                return url_findings
            
        findings = asyncio.run(execute_dast())
        
    elif args.mode == "SAST":
        # Real SAST Engine invocation
        from scanner.modules.sast_scanner import SASTScanner
        from scanner.utils.github_manager import get_github_manager
        github_mgr = get_github_manager()
        target_path = os.path.abspath(args.target)
        if os.path.isdir(target_path):
            # CI jobs commonly scan the checkout they already have. Avoid
            # treating a local path as a Git hosting URL and cloning it.
            repo_path = target_path
        else:
            repo_path = github_mgr.clone_repo(args.target)
            if not repo_path:
                print("[-] Clone failed. Exiting.")
                sys.exit(1)
        file_tree = github_mgr.get_file_tree(repo_path)

        scanner = SASTScanner()
        findings = scanner.scan_repo(repo_path, file_tree)
        if repo_path != target_path:
            github_mgr.cleanup()

    print(f"[*] Scan complete. Found {len(findings)} vulnerabilities.")
    
    # Export Results
    if args.output_format == "sarif":
        SARIFExporter().export_to_file(findings, args.output_file)
    elif args.output_format == "junit":
        JUnitExporter().export_to_file(findings, args.output_file)
    else:
        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=4)
            
    print(f"[*] Results saved to {args.output_file}")

    # CI/CD Gate Logic
    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    fail_index = severity_order.index(args.fail_on)
    
    for finding in findings:
        sev = finding.get("severity", "LOW").upper()
        if sev in severity_order and severity_order.index(sev) >= fail_index:
            print(f"[!] Pipeline FAILED: Found {sev} vulnerability.")
            sys.exit(1) # Exit 1 fails the GitHub Action/Jenkins job
            
    print("[*] Pipeline PASSED.")
    sys.exit(0)

if __name__ == "__main__":
    run_ci_mode()
