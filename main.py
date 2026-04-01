"""Main CLI for the vulnerability scanner.

Provides a simple command-line entry point that runs the crawler and
multiple vulnerability scanners (SQLi, XSS, IDOR, Open Redirect), aggregates
results, and emits a human-readable or machine-readable report.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
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
from scanner.core.crawler import WebCrawler
from scanner.modules.sqli_scanner import SQLiScanner
from scanner.modules.xss_scanner import XSSScanner
from scanner.modules.idor_scanner import IDORScanner
from scanner.modules.redirect_scanner import RedirectScanner
from scanner.modules.csrf_scanner import CSRFScanner
from scanner.modules.crypto_scanner import CryptoScanner
from scanner.modules.ssrf_scanner import SSRFScanner
from scanner.modules.xxe_scanner import XXEScanner
from scanner.modules.ssti_scanner import SSTIScanner
from scanner.modules.header_scanner import HeaderScanner
from scanner.modules.component_scanner import ComponentScanner
from scanner.reporting.pdf_generator import generate_pdf_report
from scanner.utils.mode_manager import get_mode_manager
from scanner.modules.flag_hunter import FlagHunter
from scanner.utils.auth_manager import get_auth_manager # <--- Added Import


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
    p.add_argument("--depth", type=int, help="Crawl depth (overrides mode default)")
    p.add_argument("--timeout", type=int, help="Request timeout seconds (overrides mode default)")
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
    out = {
        "target": target,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "urls": urls,
        "forms": forms,
        "vulnerabilities": [f for f in findings if f.get('type') != 'flag'],
    }
    if flags:
        out["flags"] = flags
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


def main() -> int:
    args = parse_args()

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

    banner()
    
    print(f"\n{Fore.YELLOW}[*] Mode: {args.mode.upper()}{Style.RESET_ALL}")
    print(f"    Target: {args.url}")
    print(f"    Exploit: {'YES' if config['exploit'] else 'NO'}")
    print(f"    Auth: {'YES' if config['auth'] else 'NO'}")
    print(f"    Flags: {'YES' if config['flags'] else 'NO'}")
    print(f"    Depth: {config['max_depth']}")
    print(f"    Timeout: {config['timeout']}s\n")

    print(Fore.MAGENTA + "CRAWLING" + Style.RESET_ALL)
    
    # --- PASS SESSION TO CRAWLER ---
    # Crawler now uses the authenticated session
    crawler = WebCrawler(args.url, max_depth=config['max_depth'], 
                         timeout=config['timeout'], session=session)
    results = crawler.crawl()

    urls = results.get("urls", [])
    forms = results.get("forms", [])

    print(Fore.MAGENTA + "SCANNING" + Style.RESET_ALL)
    all_findings: List[Dict[str, Any]] = []
    errors: List[str] = []

    sqli = SQLiScanner(timeout=config['timeout'], session=session)
    xss = XSSScanner(timeout=config['timeout'], session=session)
    idor = IDORScanner(timeout=config['timeout'], session=session)
    redir = RedirectScanner(timeout=config['timeout'], session=session)
    crypto = CryptoScanner(timeout=config['timeout'], session=session)
    ssrf = SSRFScanner(timeout=config['timeout'], session=session)
    xxe = XXEScanner(timeout=config['timeout'], session=session)
    ssti = SSTIScanner(timeout=config['timeout'], session=session)
    header_scan = HeaderScanner(timeout=config['timeout'], session=session)
    component_scan = ComponentScanner(timeout=config['timeout'], session=session)

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

    # Initialize flag hunter if in CTF mode
    flag_hunter = None
    if mode_mgr.should_hunt_flags():
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

    # Scan forms
    for form in forms:
        action = form.get("action")
        try:
            f = sqli.scan_form(form)
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"SQLi scanner failed on form {action}: {exc}")

        try:
            f = xss.scan_form(form)
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"XSS scanner failed on form {action}: {exc}")

        try:
            f = redir.scan_url(action, normalize_params_from_url(action))
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"Redirect scanner failed on form {action}: {exc}")

        try:
            csrf_scanner = CSRFScanner()
            f = csrf_scanner.scan_form(form)
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"CSRF scanner failed on form {action}: {exc}")

        try:
            f = crypto.scan_form(form)
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"Crypto scanner failed on form {action}: {exc}")

        try:
            f = ssrf.scan_form(form)
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"SSRF scanner failed on form {action}: {exc}")

        try:
            f = ssti.scan_form(form)
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"SSTI scanner failed on form {action}: {exc}")

        try:
            f = xxe.scan_form(form)
            for item in f: item["url"] = action
            all_findings.extend(f)
        except Exception as exc:
            errors.append(f"XXE scanner failed on form {action}: {exc}")

    # After the scanning loops complete, run stored XSS check
    stored_xss = xss.check_stored(urls, session=session)
    all_findings.extend(stored_xss)

    # After all scan_url / scan_form calls — collect blind SSRF callbacks
    blind_ssrf = ssrf.collect_oob_findings()
    all_findings.extend(blind_ssrf)

    # Deduplicate and sort
    unique = dedupe_findings(all_findings)
    unique.sort(key=severity_sort_key)

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
                content = generate_json_report(args.url, urls, forms, unique, flags_found)
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
