"""Main CLI for the vulnerability scanner.

Provides a simple command-line entry point that runs the crawler and
multiple vulnerability scanners (SQLi, XSS, IDOR, Open Redirect), aggregates
results, and emits a human-readable or machine-readable report.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse
import requests # Added for cookie handling

# Optional colored output
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
except Exception:
    class Fore:
        RESET = ""
        RED = ""
        GREEN = ""
        YELLOW = ""
        CYAN = ""
        MAGENTA = ""
    
    class Style:
        RESET_ALL = ""
from urllib.parse import urlparse, parse_qs
from scanner.core.live_scan import LiveDiscoveryScanner
from scanner.core.workflows import load_workflows
from scanner.core.crawler import WebCrawler
from scanner.modules.sqli_scanner import SQLiScanner
from scanner.modules.xss_scanner import XSSScanner
from scanner.modules.idor_scanner import IDORScanner
from scanner.modules.redirect_scanner import RedirectScanner
from scanner.modules.cmdi_scanner import CMDIScanner
from scanner.modules.path_traversal_scanner import PathTraversalScanner
from scanner.modules.csrf_scanner import CSRFScanner
from scanner.modules.crypto_scanner import CryptoScanner
from scanner.modules.ssrf_scanner import SSRFScanner
from scanner.modules.xxe_scanner import XXEScanner
from scanner.modules.ssti_scanner import SSTIScanner
from scanner.modules.header_scanner import HeaderScanner
from scanner.modules.component_scanner import ComponentScanner
from scanner.modules.graphql_scanner import GraphQLScanner
from scanner.modules.race_scanner import RaceConditionScanner
from scanner.modules.websocket_scanner import WebSocketScanner
from scanner.reporting.pdf_generator import generate_pdf_report
from scanner.reporting.json_export import build_scan_json
from scanner.core.models import RequestRecord, ScanConfig, findings_from_legacy
from scanner.storage.repository import StorageRepository
from scanner.utils.mode_manager import get_mode_manager
from scanner.modules.flag_hunter import FlagHunter
from scanner.utils.auth_manager import get_auth_manager # <--- Added Import
from scanner.utils.auth_profiles import (
    build_auth_profile_from_config,
    check_session,
    record_playwright_login_state,
)


SEVERITY_ORDER = {"sqli": 0, "xss": 1, "idor": 2, "open-redirect": 3}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Professional Vulnerability Scanner with Multiple Modes"
    )
    p.add_argument("--url", required=True, help="Target base URL to scan")
    p.add_argument("--mode", choices=['scan', 'lab', 'ctf', 'ctf-auth'], 
                   default='scan', help='Scanning mode (default: scan)')
    p.add_argument("--username", help="Username for authenticated modes")
    p.add_argument("--password", help="Password for authenticated modes")
    p.add_argument("--bearer-token", help="Bearer token for API scans")
    p.add_argument("--auth-header", action="append", default=[], help="Static auth header as Name=Value; can be repeated")
    p.add_argument("--auth-cookie", action="append", default=[], help="Static auth cookie as Name=Value; can be repeated")
    p.add_argument("--storage-state", help="Playwright storage_state JSON to reuse for auth")
    p.add_argument("--auth-role", default="anonymous", help="Auth role label for corpus/reporting")
    p.add_argument("--auth-health-url", help="URL used to check whether the auth profile is healthy")
    p.add_argument("--auth-health-text", help="Text expected in the auth health-check response")
    p.add_argument("--record-login", help="Open a browser at this login URL and save Playwright storage state")
    p.add_argument("--record-login-output", help="Output path for --record-login storage state JSON")
    p.add_argument("--depth", type=int, help="Crawl depth (overrides mode default)")
    p.add_argument("--timeout", type=int, help="Request timeout seconds (overrides mode default)")
    p.add_argument("--workflow", help="Path to a JSON workflow macro file")
    p.add_argument("--output", help="Output file path (.pdf, .html, .json, .txt)")
    p.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return p.parse_args()


def banner() -> None:
    print(Fore.CYAN + "===============================================" + Style.RESET_ALL)
    print(Fore.CYAN + "      MULTI-MODE VULNERABILITY SCANNER" + Style.RESET_ALL)
    print(Fore.CYAN + "===============================================" + Style.RESET_ALL)


def normalize_params_from_url(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    raw = parse_qs(parsed.query)
    # take first value for each param
    return {k: v[0] for k, v in raw.items() if v}


def strip_query_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(query="", fragment="").geturl()


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[Tuple[str, str, str]] = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        raw_url = f.get("url", f.get("action", ""))
        
        # NEW FIX: Parse the URL and remove the query string for the dedupe key
        parsed = urlparse(raw_url)
        base_path = parsed.path 
        
        key = (f.get("type", ""), f.get("param", ""), base_path)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def severity_sort_key(item: Dict[str, Any]) -> int:
    t = item.get("type", "").lower()
    if "xss" in t:
        key = "xss"
    elif "sqli" in t:
        key = "sqli"
    elif "idor" in t:
        key = "idor"
    elif "redirect" in t:
        key = "open-redirect"
    else:
        key = t
    return SEVERITY_ORDER.get(key, 99)


def generate_console_report(target: str, urls: List[str], forms: List[Dict[str, Any]], findings: List[Dict[str, Any]], flags: Optional[List[Dict[str, str]]] = None) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("VULNERABILITY SCAN REPORT")
    lines.append(f"Target: {target}")
    lines.append(f"Scan Date: {now}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("SUMMARY:")
    lines.append(f"- Total URLs crawled: {len(urls)}")
    lines.append(f"- Total forms found: {len(forms)}")
    lines.append(f"- Total vulnerabilities: {len([f for f in findings if f.get('type') != 'flag'])}")
    
    if flags:
        lines.append(f"- Flags captured: {len(flags)}")
    
    lines.append("")
    
    if flags:
        lines.append("🏁 FLAGS CAPTURED:")
        for flag in flags:
            lines.append(f"  {flag['flag']}")
        lines.append("")
    
    vuln_findings = [f for f in findings if f.get('type') != 'flag']
    if vuln_findings:
        lines.append("VULNERABILITIES FOUND:")
        for f in vuln_findings:
            sev = f.get("type", "").upper()
            confidence = f.get("confidence", 0)
            lines.append("")
            lines.append(f"[{sev}] {f.get('type')} ({f.get('payload', '')})")
            lines.append(f"  Parameter: {f.get('param')}")
            lines.append(f"  URL: {f.get('url', f.get('action', ''))}")
            lines.append(f"  Payload: {f.get('payload')}")
            lines.append(f"  Evidence: {f.get('evidence')}")
            lines.append(f"  Confidence: {confidence}%")
    else:
        lines.append("No vulnerabilities found.")
    
    report = "\n".join(lines)
    print(report)
    return report


def generate_json_report(target: str, urls: List[str], forms: List[Dict[str, Any]], findings: List[Dict[str, Any]], flags: Optional[List[Dict[str, str]]] = None) -> str:
    scan_config = ScanConfig(scan_id="cli", target_base_url=target, output_dir="reports")
    canonical = findings_from_legacy(
        [f for f in findings if f.get('type') != 'flag'],
        target_url=target,
        scan_id=scan_config.scan_id,
    )
    out = build_scan_json(
        scan_config=scan_config,
        urls=urls,
        forms=forms,
        findings=canonical,
        legacy_findings=[f for f in findings if f.get('type') != 'flag'],
    )
    if flags:
        out["metadata"]["flags"] = flags
    return json.dumps(out, indent=2)


def generate_txt_report(*args, **kwargs) -> str:
    return generate_console_report(*args, **kwargs)


def generate_html_report(target: str, urls: List[str], forms: List[Dict[str, Any]], findings: List[Dict[str, Any]], flags: Optional[List[Dict[str, str]]] = None) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    css = """
    body { font-family: Arial, sans-serif; padding: 20px; }
    .header { background:#222;color:#fff;padding:10px }
    .vuln { border:1px solid #ddd;padding:10px;margin:10px 0 }
    .critical { background: #ffeeee }
    .high { background: #fff6e6 }
    .flag { background: #e6ffe6; border: 2px solid #00aa00; padding: 10px; margin: 10px 0; }
    """
    parts: List[str] = []
    parts.append(f"<html><head><style>{css}</style><title>Scan Report</title></head><body>")
    parts.append(f"<div class='header'><h1>Vulnerability Scan Report</h1><div>Target: {target}</div><div>{now}</div></div>")
    parts.append(f"<h2>Summary</h2><ul><li>Total URLs: {len(urls)}</li><li>Total forms: {len(forms)}</li><li>Total vulnerabilities: {len([f for f in findings if f.get('type') != 'flag'])}</li>")
    
    if flags:
        parts.append(f"<li>Flags captured: {len(flags)}</li>")
    
    parts.append("</ul>")
    
    if flags:
        parts.append("<h2>🏁 Flags Captured</h2>")
        for flag in flags:
            parts.append(f"<div class='flag'><strong>{flag['flag']}</strong></div>")
    
    parts.append("<h2>Vulnerabilities</h2>")
    for f in findings:
        if f.get('type') == 'flag':
            continue
        typ = f.get("type", "").upper()
        parts.append(f"<div class='vuln'><strong>{typ}</strong><div>Param: {f.get('param')}</div><div>URL: {f.get('url', f.get('action',''))}</div><div>Payload: {f.get('payload')}</div><div>Evidence: {f.get('evidence')}</div><div>Confidence: {f.get('confidence')}%</div></div>")
    parts.append("</body></html>")
    return "\n".join(parts)


def save_output(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _parse_pairs(items: List[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        if key:
            parsed[key] = value
    return parsed


def _auth_config_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    headers = _parse_pairs(args.auth_header)
    cookies = _parse_pairs(args.auth_cookie)
    health_check = {}
    if args.auth_health_url:
        health_check["health_check_url"] = args.auth_health_url
    if args.auth_health_text:
        health_check["expected_text"] = args.auth_health_text

    if args.storage_state:
        auth_type = "playwright_storage"
    elif args.bearer_token:
        auth_type = "bearer"
    elif headers:
        auth_type = "header"
    elif cookies:
        auth_type = "cookie"
    elif args.username and args.password:
        auth_type = "basic"
    else:
        auth_type = "anonymous"
    role = args.auth_role or "anonymous"
    if role == "anonymous" and auth_type != "anonymous":
        role = "authenticated"

    return {
        "type": auth_type,
        "role": role,
        "token": args.bearer_token,
        "headers": headers,
        "cookies": cookies,
        "storage_state_path": args.storage_state,
        "session_health_check": health_check,
    }


def _safe_storage_repo():
    try:
        return StorageRepository()
    except Exception as exc:
        print(Fore.YELLOW + f"[!] Corpus storage disabled: {exc}" + Style.RESET_ALL)
        return None


def _persist_discovered_requests(repo, scan_id: str, urls: List[str], forms: List[Dict[str, Any]]) -> None:
    if repo is None:
        return
    for url in urls:
        try:
            repo.save_request(
                RequestRecord.create(
                    scan_id=scan_id,
                    source="crawler",
                    method="GET",
                    url=url,
                )
            )
        except Exception:
            pass
    for form in forms:
        try:
            body = {
                inp.get("name", ""): inp.get("value", "")
                for inp in form.get("inputs", [])
                if inp.get("name")
            }
            repo.save_request(
                RequestRecord.create(
                    scan_id=scan_id,
                    source="crawler",
                    method=form.get("method", "GET"),
                    url=form.get("action", ""),
                    headers=form.get("extra_headers", {}),
                    body=body,
                )
            )
        except Exception:
            pass


def main() -> int:
    args = parse_args()
    scan_id = str(uuid.uuid4())[:8]

    if args.record_login:
        output_path = args.record_login_output or os.path.join(
            "reports",
            f"auth_{args.auth_role or 'authenticated'}_storage_state.json",
        )
        profile = record_playwright_login_state(
            login_url=args.record_login,
            output_path=output_path,
            base_url=args.url,
            role=args.auth_role or "authenticated",
        )
        args.storage_state = profile.storage_state_path
        print(Fore.GREEN + f"Saved Playwright storage state to {profile.storage_state_path}" + Style.RESET_ALL)

    # Initialize managers
    mode_mgr = get_mode_manager()
    auth_mgr = get_auth_manager() # <--- Initialize AuthManager
    auth_mgr.logout()
    
    # Set mode
    if not mode_mgr.set_mode(args.mode):
        print(Fore.RED + f"Invalid mode: {args.mode}" + Style.RESET_ALL)
        return 1
    
    # --- UNIFIED SESSION SETUP ---
    # Get the single shared session
    session = auth_mgr.get_session()
    session.headers.update({"User-Agent": "vuln-scanner/1.0"})
    auth_config = _auth_config_from_args(args)
    auth_profile = build_auth_profile_from_config(
        auth_config,
        base_url=args.url,
        default_name="cli-auth",
    )
    profile_result = auth_mgr.apply_auth_profile(auth_profile)
    if args.verbose and profile_result.applied:
        print(Fore.GREEN + f"Auth profile applied: {auth_profile.name} ({auth_profile.role})" + Style.RESET_ALL)

    # Set credentials if provided
    if args.username and args.password:
        mode_mgr.set_credentials(args.username, args.password)
        # Automatically attempt basic auth if credentials are provided
        auth_mgr.login_basic_auth(args.username, args.password)
    elif args.mode == 'ctf-auth':
        print(Fore.RED + "[!] ctf-auth mode requires --username and --password" + Style.RESET_ALL)
        return 1
    
    # Get mode configuration
    config = mode_mgr.get_mode_config()
    
    # Override with command-line args
    if args.depth:
        config['max_depth'] = args.depth
    if args.timeout:
        config['timeout'] = args.timeout

    if args.verbose:
        print(Fore.GREEN + "Starting scan..." + Style.RESET_ALL)

    output_dir = os.path.dirname(args.output) if args.output else "reports"
    if not output_dir:
        output_dir = "reports"
    scan_config = ScanConfig(
        scan_id=scan_id,
        target_base_url=args.url,
        safety_mode="safe",
        max_depth=config['max_depth'],
        auth_profiles=[auth_profile.to_dict()],
        enabled_modules=[
            "sqli", "xss", "idor", "open-redirect", "cmdi", "path-traversal",
            "csrf", "crypto", "ssrf", "xxe", "ssti", "headers", "components",
            "graphql", "race", "websocket",
        ],
        output_dir=output_dir,
    )
    storage_repo = _safe_storage_repo()
    if storage_repo is not None:
        storage_repo.create_scan(scan_config)
        storage_repo.save_auth_profile(auth_profile)
    auth_health = {"status": "skipped", "reason": "no health check configured"}
    if auth_profile.session_health_check:
        auth_health_result = check_session(auth_profile, session=auth_mgr.get_session(), timeout=config["timeout"])
        auth_health = auth_health_result.to_dict()
        if args.verbose:
            color = Fore.GREEN if auth_health_result.healthy else Fore.YELLOW
            print(color + f"Auth health: {auth_health_result.status} ({auth_health_result.reason})" + Style.RESET_ALL)

    banner()
    
    print(f"\n{Fore.YELLOW}[*] Mode: {args.mode.upper()}{Style.RESET_ALL}")
    print(f"    Target: {args.url}")
    print(f"    Exploit: {'YES' if config['exploit'] else 'NO'}")
    print(f"    Auth: {'YES' if config['auth'] else 'NO'}")
    print(f"    Auth Role: {auth_profile.role}")
    print(f"    Flags: {'YES' if config.get('flags', False) else 'NO'}")
    print(f"    Depth: {config['max_depth']}")
    print(f"    Timeout: {config['timeout']}s\n")

    workflows = load_workflows(args.workflow) if args.workflow else []
    sqli = SQLiScanner(timeout=config['timeout'], session=session)
    xss = XSSScanner(timeout=config['timeout'], session=session)
    idor = IDORScanner(timeout=config['timeout'], session=session)
    redir = RedirectScanner(timeout=config['timeout'], session=session)
    cmdi = CMDIScanner(timeout=config['timeout'], session=session)
    path = PathTraversalScanner(timeout=config['timeout'], session=session)
    crypto = CryptoScanner(timeout=config['timeout'], session=session)
    ssrf = SSRFScanner(timeout=config['timeout'], session=session)
    xxe = XXEScanner(timeout=config['timeout'], session=session)
    ssti = SSTIScanner(timeout=config['timeout'], session=session)
    header_scan = HeaderScanner(timeout=config['timeout'], session=session)
    component_scan = ComponentScanner(timeout=config['timeout'], session=session)
    graphql = GraphQLScanner(timeout=config['timeout'], session=session)
    race = RaceConditionScanner(timeout=config['timeout'], session=session)
    websocket = WebSocketScanner(timeout=config['timeout'], session=session)
    live_scanner = LiveDiscoveryScanner(
        form_scanners=[
            sqli, xss, cmdi, path,
            CSRFScanner(timeout=config['timeout'], session=session),
            crypto, ssrf, xxe, ssti, graphql, race,
        ],
        websocket_scanner=websocket,
    )

    print(Fore.MAGENTA + "CRAWLING" + Style.RESET_ALL)
    
    # --- PASS SESSION TO CRAWLER ---
    # Crawler now uses the authenticated session
    crawler = WebCrawler(args.url, max_depth=config['max_depth'], 
                         timeout=config['timeout'], session=session,
                         workflows=workflows,
                         discovery_callback=live_scanner.handle_discovery,
                         auth_profile=auth_profile)
    results = crawler.crawl()

    urls = results.get("urls", [])
    forms = results.get("forms", [])
    websockets = results.get("websockets", [])
    _persist_discovered_requests(storage_repo, scan_id, urls, forms)

    print(Fore.MAGENTA + "SCANNING" + Style.RESET_ALL)
    all_findings: List[Dict[str, Any]] = list(live_scanner.findings)
    errors: List[str] = []

    # One-time base URL checks
    for finding in header_scan.scan_url(args.url):
        finding['url'] = args.url
        all_findings.append(finding)

    for finding in component_scan.scan_url(args.url):
        finding['url'] = args.url
        all_findings.append(finding)

    for finding in component_scan.scan_base_url(args.url):
        finding['url'] = args.url
        all_findings.append(finding)

    for finding in crypto.scan_url(args.url):
        finding['url'] = args.url
        all_findings.append(finding)

    # Initialize flag hunter only when mode manager exposes CTF hooks.
    flag_hunter = None
    can_hunt_flags = (
        hasattr(mode_mgr, 'should_hunt_flags')
        and hasattr(mode_mgr, 'get_flag_patterns')
        and mode_mgr.should_hunt_flags()
    )
    if can_hunt_flags:
        flag_hunter = FlagHunter(mode_mgr.get_flag_patterns())
        print(Fore.CYAN + "[*] Flag hunting enabled!" + Style.RESET_ALL)

    # Scan URLs
    for u in urls:
        params = normalize_params_from_url(u)
        scan_url = strip_query_from_url(u)
        
        # --- HUNT FLAGS WITH SHARED SESSION ---
        if flag_hunter:
            try:
                # Use SESSION instead of requests.get
                # This sends the cookies found during crawling!
                resp = session.get(u, timeout=config['timeout'])
                
                flags = flag_hunter.scan_response(u, resp.text)
                all_findings.extend(flags)
                
                # Check headers
                flags_headers = flag_hunter.scan_headers(u, dict(resp.headers))
                all_findings.extend(flags_headers)
                
                # Check cookies from the SHARED session
                current_cookies = requests.utils.dict_from_cookiejar(session.cookies)
                flags_cookies = flag_hunter.scan_cookies(u, current_cookies)
                all_findings.extend(flags_cookies)
                
            except Exception as exc:
                if args.verbose:
                    print(f"[!] Flag hunting failed on {u}: {exc}")
        
        if params:
            # SQLi
            try:
                f = sqli.scan_url(scan_url, params)
                for item in f: item["url"] = scan_url
                all_findings.extend(f)
            except Exception as exc:
                errors.append(f"SQLi scanner failed on {u}: {exc}")

            # XSS
            try:
                f = xss.scan_url(scan_url, params)
                for item in f: item["url"] = scan_url
                all_findings.extend(f)
            except Exception as exc:
                errors.append(f"XSS scanner failed on {u}: {exc}")

            # SSRF
            try:
                f = ssrf.scan_url(scan_url, params)
                for item in f: item["url"] = scan_url
                all_findings.extend(f)
            except Exception as exc:
                errors.append(f"SSRF scanner failed on {u}: {exc}")

            # SSTI
            try:
                f = ssti.scan_url(scan_url, params)
                for item in f: item["url"] = scan_url
                all_findings.extend(f)
            except Exception as exc:
                errors.append(f"SSTI scanner failed on {u}: {exc}")

            # XXE
            try:
                f = xxe.scan_url(scan_url, params)
                for item in f: item["url"] = scan_url
                all_findings.extend(f)
            except Exception as exc:
                errors.append(f"XXE scanner failed on {u}: {exc}")

            # CMDI
            try:
                f = cmdi.scan_url(scan_url, params)
                for item in f: item["url"] = scan_url
                all_findings.extend(f)
            except Exception as exc:
                errors.append(f"CMDI scanner failed on {u}: {exc}")

            # Path traversal
            try:
                f = path.scan_url(scan_url, params)
                for item in f: item["url"] = scan_url
                all_findings.extend(f)
            except Exception as exc:
                errors.append(f"Path traversal scanner failed on {u}: {exc}")

        try:
            f = idor.scan_url(scan_url, params)
            for item in f: item["url"] = scan_url
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"IDOR scanner failed on {u}: {exc}")

        # Redirect check
        try:
            f = redir.scan_url(scan_url, params)
            for item in f: item["url"] = scan_url
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"Redirect scanner failed on {u}: {exc}")

    errors.extend(live_scanner.errors)

    # After the scanning loops complete, run stored XSS check
    stored_xss = xss.check_stored(urls, session=session)
    all_findings.extend(stored_xss)

    # After all scan_url / scan_form calls — collect blind SSRF callbacks
    blind_ssrf = ssrf.collect_oob_findings()
    all_findings.extend(blind_ssrf)
    all_findings.extend(websocket.collect_oob_findings())

    # Deduplicate and sort
    unique = dedupe_findings(all_findings)
    unique.sort(key=severity_sort_key)
    canonical_findings = findings_from_legacy(
        [finding for finding in unique if finding.get("type") != "flag"],
        target_url=args.url,
        scan_id=scan_id,
    )
    if storage_repo is not None:
        for finding in canonical_findings:
            try:
                storage_repo.save_finding(finding)
            except Exception:
                pass

    # Extract flags
    flags_found = None
    if flag_hunter:
        flags_found = flag_hunter.get_all_flags()

    print(Fore.MAGENTA + "REPORTING" + Style.RESET_ALL)
    
    if flags_found:
        print(Fore.GREEN + f"\n🏁 FLAGS FOUND: {len(flags_found)}" + Style.RESET_ALL)
        for flag in flags_found:
            print(Fore.GREEN + f"  {flag['flag']}" + Style.RESET_ALL)
    
    console = generate_console_report(args.url, urls, forms, unique, flags_found)

    if args.output:
        out = args.output
        try:
            if out.endswith(".pdf"):
                vuln_only = [f for f in unique if f.get('type') != 'flag']
                generate_pdf_report(args.url, urls, forms, vuln_only, out)
                print(Fore.GREEN + f"Saved PDF report to {out}" + Style.RESET_ALL)
            elif out.endswith(".json"):
                payload = build_scan_json(
                    scan_config=scan_config,
                    urls=urls,
                    forms=forms,
                    findings=canonical_findings,
                    legacy_findings=[f for f in unique if f.get('type') != 'flag'],
                    metadata={"flags": flags_found or [], "websockets": websockets, "auth_health": auth_health},
                )
                content = json.dumps(payload, indent=2)
                save_output(out, content)
                print(Fore.GREEN + f"Saved report to {out}" + Style.RESET_ALL)
            elif out.endswith(".html"):
                content = generate_html_report(args.url, urls, forms, unique, flags_found)
                save_output(out, content)
                print(Fore.GREEN + f"Saved report to {out}" + Style.RESET_ALL)
            else:
                content = generate_txt_report(args.url, urls, forms, unique, flags_found)
                save_output(out, content)
                print(Fore.GREEN + f"Saved report to {out}" + Style.RESET_ALL)
        except Exception as exc:
            print(Fore.RED + f"Failed to save report: {exc}" + Style.RESET_ALL)

    if errors:
        print(Fore.YELLOW + "Errors encountered during scan:" + Style.RESET_ALL)
        for e in errors:
            print(" - " + e)

    return 0


if __name__ == "__main__":
    sys.exit(main())
