"""Flask API server with WordPress scanner, authentication support, and multi-mode scanning."""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import os
import uuid
import shutil
import subprocess
import json as _json
from datetime import datetime
import concurrent.futures
from urllib.parse import urlparse, parse_qs

from scanner.core.crawler import WebCrawler
from scanner.modules.sqli_scanner import SQLiScanner
from scanner.modules.xss_scanner import XSSScanner
from scanner.modules.idor_scanner import IDORScanner
from scanner.modules.redirect_scanner import RedirectScanner
from scanner.modules.cmdi_scanner import CMDIScanner
from scanner.modules.path_traversal_scanner import PathTraversalScanner
from scanner.modules.csrf_scanner import CSRFScanner
from scanner.modules.wordpress_scanner import WordPressScanner
from scanner.modules.flag_hunter import FlagHunter
from scanner.utils.deduplication import deduplicate_and_group
from scanner.utils.rate_limiter import get_rate_limiter
from scanner.utils.auth_manager import get_auth_manager
from scanner.utils.mode_manager import get_mode_manager
from scanner.reporting.pdf_generator import generate_pdf_report
from scanner.modules.crypto_scanner import CryptoScanner
from scanner.modules.ssrf_scanner import SSRFScanner
from scanner.modules.xxe_scanner import XXEScanner
from scanner.modules.ssti_scanner import SSTIScanner
from scanner.modules.header_scanner import HeaderScanner
from scanner.modules.component_scanner import ComponentScanner
# NOTE: SemgrepScanner import removed — Semgrep now runs via subprocess directly.
#       If you need to call SemgrepScanner class elsewhere, re-add the import there.
from scanner.modules.sast_scanner import SASTScanner
from scanner.utils.github_manager import get_github_manager, detect_tech_stack
from scanner.reporting.pdf_generator_sast_patch import (
    _render_sast_finding, _render_sast_summary,
    SAST_VULN_DESCRIPTIONS, SAST_OWASP_MAPPING, SAST_CWE_MAPPING
)


def _check_semgrep():
    if shutil.which("semgrep"):
        print("[✓] Semgrep found — SAST engine ready")
    else:
        print("[!] Semgrep not installed — SAST code analysis will be skipped")
        print("    Install with: pip install semgrep")


_check_semgrep()

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

active_scans = {}
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def emit_progress(scan_id, message, type="info"):
    """Send real-time progress updates."""
    socketio.emit('scan_progress', {
        'scan_id': scan_id,
        'message': message,
        'type': type,
        'timestamp': datetime.now().isoformat()
    })


def deduplicate_findings(findings):
    """Remove duplicate vulnerabilities - keep only unique (URL, param, type) combinations."""
    seen = set()
    unique = []
    for finding in findings:
        key = (finding.get('url'), finding.get('param'), finding.get('type'))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def run_scan(scan_id, target_url, depth, timeout, auth_config=None, scan_mode='scan'):
    """Main scanning function with WordPress, auth, and mode support."""
    try:
        emit_progress(scan_id, f"Starting scan of {target_url}", "info")

        mode_mgr = get_mode_manager()
        mode_mgr.set_mode(scan_mode)
        mode_config = mode_mgr.get_mode_config()

        if depth is None:
            depth = mode_config['max_depth']
        if timeout is None:
            timeout = mode_config['timeout']

        emit_progress(scan_id, f"Mode: {scan_mode.upper()} | Depth: {depth} | Timeout: {timeout}s", "info")

        auth_manager = get_auth_manager()
        authenticated_session = None

        if auth_config or mode_config['auth']:
            if auth_config:
                auth_type = auth_config.get('type')
                if auth_type == 'form':
                    success = auth_manager.login_form(
                        auth_config.get('login_url'),
                        auth_config.get('username'),
                        auth_config.get('password'),
                        auth_config.get('username_field', 'username'),
                        auth_config.get('password_field', 'password')
                    )
                    if success:
                        authenticated_session = auth_manager.get_session()
                        emit_progress(scan_id, "Authentication successful", "success")
                    else:
                        emit_progress(scan_id, "Authentication failed, continuing without auth", "warning")

        flag_hunter = None
        if mode_mgr.should_hunt_flags():
            flag_hunter = FlagHunter(mode_mgr.get_flag_patterns())
            emit_progress(scan_id, "🏁 Flag hunting enabled!", "success")

        emit_progress(scan_id, "Checking for WordPress/CMS...", "phase")
        wp_scanner = WordPressScanner(timeout=timeout)
        wp_findings = wp_scanner.scan_url(target_url)

        if wp_findings:
            emit_progress(scan_id, f"WordPress detected! Found {len(wp_findings)} WP-specific issues", "warning")

        emit_progress(scan_id, "Phase 1: Crawling target...", "phase")
        crawler = WebCrawler(target_url, max_depth=depth, timeout=timeout)
        results = crawler.crawl()
        urls = results.get("urls", [])
        forms = results.get("forms", [])

        emit_progress(scan_id, f"Found {len(urls)} URLs and {len(forms)} forms", "success")

        sqli = SQLiScanner(timeout=timeout, session=authenticated_session)
        xss = XSSScanner(timeout=timeout, session=authenticated_session)
        idor = IDORScanner(timeout=timeout, session=authenticated_session)
        redir = RedirectScanner(timeout=timeout, session=authenticated_session)
        cmdi = CMDIScanner(timeout=timeout, session=authenticated_session)
        path = PathTraversalScanner(timeout=timeout, session=authenticated_session)
        csrf = CSRFScanner(timeout=timeout, session=authenticated_session)
        rate_limiter = get_rate_limiter()
        crypto = CryptoScanner(timeout=timeout, session=authenticated_session)
        ssrf = SSRFScanner(timeout=timeout, session=authenticated_session)
        xxe = XXEScanner(timeout=timeout, session=authenticated_session)
        ssti = SSTIScanner(timeout=timeout, session=authenticated_session)
        header_scan = HeaderScanner(timeout=timeout, session=authenticated_session)
        component_scan = ComponentScanner(timeout=timeout, session=authenticated_session)

        all_findings = wp_findings.copy()
        all_findings.extend(header_scan.scan_url(target_url))
        all_findings.extend(component_scan.scan_url(target_url))
        all_findings.extend(component_scan.scan_base_url(target_url))
        all_findings.extend(crypto.scan_url(target_url))

        emit_progress(scan_id, "Phase 2: Testing for vulnerabilities (multi-threaded)...", "phase")

        def scan_single_url(url_data):
            url, idx, total = url_data
            findings = []
            try:
                emit_progress(scan_id, f"[{idx}/{total}] Scanning: {url}", "info")

                if flag_hunter:
                    try:
                        import requests
                        resp = requests.get(url, timeout=timeout)
                        flags = flag_hunter.scan_response(url, resp.text)
                        if flags:
                            for flag in flags:
                                emit_progress(scan_id, f"🏁 FLAG FOUND: {flag['flag']}", "success")
                        findings.extend(flags)
                    except Exception:
                        pass

                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params = {k: v[0] for k, v in params.items() if v}

                if params:
                    for scanner, name in [(sqli, 'SQL Injection'), (xss, 'XSS'),
                                          (idor, 'IDOR'), (cmdi, 'Command Injection'),
                                          (path, 'Path Traversal'), (ssrf, 'SSRF'),
                                          (ssti, 'SSTI'), (xxe, 'XXE')]:
                        vuln = scanner.scan_url(url, params)
                        for f in vuln:
                            f['url'] = url
                            emit_progress(scan_id, f"✓ Found {f['type']} in '{f['param']}'", "warning")
                        findings.extend(vuln)

                vuln = redir.scan_url(url, params or {})
                for f in vuln:
                    f['url'] = url
                    emit_progress(scan_id, f"✓ Found {f['type']}", "warning")
                findings.extend(vuln)

                domain = urlparse(url).netloc
                rate_limiter.wait(domain)

            except Exception as e:
                emit_progress(scan_id, f"Error scanning {url}: {str(e)}", "error")

            return findings

        max_workers = 10 if mode_config['aggressive'] else 5

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            url_data = [(url, idx+1, len(urls)) for idx, url in enumerate(urls)]
            results_iter = executor.map(scan_single_url, url_data)
            for findings in results_iter:
                all_findings.extend(findings)

        def scan_single_form(form_data):
            form, idx, total = form_data
            findings = []
            action = form.get('action', '')
            try:
                emit_progress(scan_id, f"[{idx}/{total}] Scanning form: {action}", "info")
                for scanner in [sqli, xss, cmdi, path, csrf, crypto, ssrf, ssti, xxe]:
                    vuln = scanner.scan_form(form)
                    for f in vuln:
                        f['url'] = action
                        emit_progress(scan_id, f"✓ Found {f['type']}", "warning")
                    findings.extend(vuln)
            except Exception as e:
                emit_progress(scan_id, f"Error scanning form: {str(e)}", "error")
            return findings

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            form_data = [(form, idx+1, len(forms)) for idx, form in enumerate(forms)]
            results_iter = executor.map(scan_single_form, form_data)
            for findings in results_iter:
                all_findings.extend(findings)

        # Stored XSS sweep (checks all URLs for markers injected during scan)
        stored_xss = xss.check_stored(urls, session=authenticated_session)
        all_findings.extend(stored_xss)

        # Blind SSRF OOB callback collection
        blind_ssrf = ssrf.collect_oob_findings()
        all_findings.extend(blind_ssrf)

        emit_progress(scan_id, "Phase 3: Generating report...", "phase")

        report_filename = f"scan_{scan_id}.pdf"
        report_path = os.path.join(REPORTS_DIR, report_filename)
        unique_findings = deduplicate_and_group(all_findings)

        flags_found = [f for f in unique_findings if f.get('type') == 'flag']
        vuln_findings = [f for f in unique_findings if f.get('type') != 'flag']

        generate_pdf_report(target_url, urls, forms, vuln_findings, report_path)

        active_scans[scan_id] = {
            'status': 'completed',
            'target': target_url,
            'mode': scan_mode,
            'urls': urls,
            'forms': forms,
            'findings': vuln_findings,
            'flags': flags_found,
            'report_path': report_path,
            'total_vulnerabilities': len(vuln_findings),
            'total_flags': len(flags_found)
        }

        if flags_found:
            emit_progress(scan_id, f"🏁 Captured {len(flags_found)} flags!", "success")

        emit_progress(scan_id, f"Scan complete! Found {len(vuln_findings)} vulnerabilities", "success")
        emit_progress(scan_id, f"Report saved: {report_filename}", "success")

    except Exception as e:
        emit_progress(scan_id, f"Error: {str(e)}", "error")
        active_scans[scan_id] = {'status': 'failed', 'error': str(e)}


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start scan with optional authentication and mode."""
    data = request.json
    target_url = data.get('url')
    depth = data.get('depth')
    timeout = data.get('timeout')
    auth_config = data.get('auth')
    scan_mode = data.get('mode', 'scan')

    if not target_url:
        return jsonify({'error': 'URL is required'}), 400

    valid_modes = ['scan', 'lab', 'ctf', 'ctf-auth']
    if scan_mode not in valid_modes:
        return jsonify({'error': f'Invalid mode. Must be one of: {valid_modes}'}), 400

    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {'status': 'running', 'target': target_url, 'mode': scan_mode}

    thread = threading.Thread(target=run_scan, args=(scan_id, target_url, depth, timeout, auth_config, scan_mode))
    thread.daemon = True
    thread.start()

    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'mode': scan_mode,
        'message': 'Scan started successfully'
    })


@app.route('/api/scan/repo', methods=['POST'])
def scan_repo():
    """SAST scan of a GitHub repository."""
    data = request.json
    repo_url = data.get('url')
    token = data.get('token')
    branch = data.get('branch')

    if not repo_url:
        return jsonify({'error': 'url is required'}), 400

    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {'status': 'running', 'target': repo_url, 'mode': 'sast'}

    def run_sast(scan_id, repo_url, token, branch):
        """
        SAST scan — Semgrep is MANDATORY for code analysis (runs via subprocess).
        SASTScanner handles secrets + deps only (TaintAnalyzer removed).
        Semgrep JSON output parsed directly — no legacy format mapping.
        """
        try:
            emit_progress(scan_id, f"Starting SAST scan: {repo_url}", "phase")

            github_mgr = get_github_manager()
            if token:
                github_mgr.set_token(token)
                emit_progress(scan_id, "GitHub token configured", "success")

            # ── Clone ──────────────────────────────────────────────────────
            emit_progress(scan_id, "Cloning repository...", "phase")
            repo_path = github_mgr.clone_repo(repo_url, branch=branch)
            if not repo_path:
                emit_progress(scan_id, "Failed to clone repository", "error")
                active_scans[scan_id] = {"status": "failed", "error": "Clone failed"}
                return

            # ── Tech stack ─────────────────────────────────────────────────
            emit_progress(scan_id, "Detecting tech stack...", "info")
            stack = detect_tech_stack(repo_path)
            lang  = stack.get("primary_language", "unknown")
            fws   = ", ".join(stack.get("frameworks", [])) or "none"
            emit_progress(scan_id, f"Stack: {lang} | frameworks: {fws}", "success")

            # ── File tree (for SASTScanner secrets/deps) ───────────────────
            emit_progress(scan_id, "Indexing repository files...", "info")
            file_tree   = github_mgr.get_file_tree(repo_path)
            total_files = len(file_tree.get("all", []))
            emit_progress(scan_id, f"Indexed {total_files} files", "success")

            if total_files == 0:
                emit_progress(scan_id, "No scannable files found", "error")
                active_scans[scan_id] = {"status": "failed", "error": "No files"}
                return

            findings = []
            semgrep_count = 0

            # ── PHASE 1: Semgrep via subprocess — MANDATORY ────────────────
            if not shutil.which("semgrep"):
                emit_progress(
                    scan_id,
                    "Semgrep NOT installed — code vulnerability analysis SKIPPED. "
                    "Run: pip install semgrep",
                    "error"
                )
                # Honest failure — do NOT fall back to TaintAnalyzer
            else:
                emit_progress(scan_id, "Running Semgrep AST analysis...", "phase")

                # Language-specific rulesets
                lang_rulesets = {
                    "javascript": ["p/javascript", "p/nodejs"],
                    "typescript": ["p/typescript", "p/nodejs"],
                    "python":     ["p/python", "p/django", "p/flask"],
                    "java":       ["p/java", "p/spring"],
                    "php":        ["p/php"],
                    "go":         ["p/golang"],
                    "ruby":       ["p/ruby"],
                }
                base_rulesets  = ["p/default", "p/owasp-top-ten", "p/secrets"]
                extra_rulesets = lang_rulesets.get(lang.lower(), [])
                all_rulesets   = base_rulesets + extra_rulesets

                semgrep_cmd = (
                    ["semgrep", "--json", "--quiet", "--timeout=30"]
                    + [arg for r in all_rulesets for arg in ["--config", r]]
                    + [repo_path]
                )

                emit_progress(scan_id,
                    f"Rulesets: {' + '.join(all_rulesets)}", "info")

                try:
                    result = subprocess.run(
                        semgrep_cmd,
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )

                    raw_output = result.stdout.strip()

                    if not raw_output:
                        emit_progress(scan_id,
                            "Semgrep produced no output — check installation or network",
                            "error")
                    else:
                        semgrep_data    = _json.loads(raw_output)
                        semgrep_results = semgrep_data.get("results", [])
                        semgrep_errors  = semgrep_data.get("errors",  [])

                        for err in semgrep_errors[:3]:
                            emit_progress(scan_id,
                                f"Semgrep error: {err.get('message', '?')}", "warning")

                        emit_progress(scan_id,
                            f"Semgrep: {len(semgrep_results)} raw findings", "info")

                        sev_map = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}

                        for r in semgrep_results:
                            meta = r.get("extra", {})
                            severity = meta.get("severity", "WARNING").upper()
                            findings.append({
                                "type":       r.get("check_id", "semgrep-finding"),
                                "category":   "code",
                                "file":       r.get("path", ""),
                                "line":       r.get("start", {}).get("line", 0),
                                "code":       meta.get("lines", "").strip()[:200],
                                "message":    meta.get("message", ""),
                                "severity":   sev_map.get(severity, "Medium"),
                                "confidence": 85,
                                "cwe":        meta.get("metadata", {}).get("cwe", ""),
                                "owasp":      meta.get("metadata", {}).get("owasp", ""),
                                "source":     "semgrep",
                            })

                        semgrep_count = len(findings)
                        emit_progress(scan_id,
                            f"Semgrep parsed: {semgrep_count} findings", "success")

                except subprocess.TimeoutExpired:
                    emit_progress(scan_id, "Semgrep timed out (>5 min)", "error")
                except _json.JSONDecodeError as e:
                    emit_progress(scan_id,
                        f"Failed to parse Semgrep JSON: {e}", "error")
                except Exception as e:
                    emit_progress(scan_id, f"Semgrep subprocess error: {e}", "error")

            # ── PHASE 2: SASTScanner — secrets + deps ONLY ─────────────────
            emit_progress(scan_id, "Running secrets/dependency scanner...", "phase")
            regex_scanner  = SASTScanner()
            regex_findings = regex_scanner.scan_repo(repo_path, file_tree)
            emit_progress(scan_id,
                f"Secrets/deps: {len(regex_findings)} findings", "info")

            # Merge + deduplicate on (file, line, type)
            existing_keys = {
                (f.get("file"), f.get("line"), f.get("type")) for f in findings
            }
            added = 0
            for rf in regex_findings:
                key = (rf.get("file"), rf.get("line"), rf.get("type"))
                if key not in existing_keys:
                    findings.append(rf)
                    existing_keys.add(key)
                    added += 1

            emit_progress(scan_id,
                f"Combined: {len(findings)} total "
                f"({semgrep_count} semgrep + {added} secrets/deps)",
                "success")

            # ── Category summary ───────────────────────────────────────────
            cats = {
                "secret":     len([f for f in findings if f.get("category") == "secret"]),
                "code":       len([f for f in findings if f.get("category") == "code"]),
                "dependency": len([f for f in findings if f.get("category") == "dependency"]),
                "config":     len([f for f in findings if f.get("category") == "config"]),
            }
            emit_progress(scan_id,
                f"Breakdown — code: {cats['code']} | secrets: {cats['secret']} | "
                f"deps: {cats['dependency']} | config: {cats['config']}",
                "warning" if findings else "success")

            # ── PDF ────────────────────────────────────────────────────────
            emit_progress(scan_id, "Generating PDF report...", "phase")
            report_filename = f"sast_{scan_id}.pdf"
            report_path     = os.path.join(REPORTS_DIR, report_filename)
            _generate_sast_pdf(repo_url, findings, stack, report_path)

            github_mgr.cleanup()

            active_scans[scan_id] = {
                "status":                "completed",
                "target":                repo_url,
                "mode":                  "sast",
                "scan_type":             "SAST (Semgrep AST + Secrets/Deps)",
                "findings":              findings,
                "report_path":           report_path,
                "total_vulnerabilities": len(findings),
                "total_flags":           0,
                "tech_stack":            stack,
                "summary":               cats,
            }

            emit_progress(scan_id,
                f"SAST complete — {len(findings)} findings", "success")

        except Exception as e:
            import traceback
            emit_progress(scan_id, f"SAST error: {str(e)}", "error")
            emit_progress(scan_id, traceback.format_exc()[:400], "error")
            active_scans[scan_id] = {"status": "failed", "error": str(e)}

    thread = threading.Thread(target=run_sast, args=(scan_id, repo_url, token, branch))
    thread.daemon = True
    thread.start()

    return jsonify({'scan_id': scan_id, 'status': 'started', 'mode': 'sast'})


def _generate_sast_pdf(repo_url: str, findings: list, stack: dict, output_path: str):
    """Generate SAST-specific PDF report using the sast patch renderer."""
    from reportlab.platypus import SimpleDocTemplate
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch

    # Warn in PDF if Semgrep wasn't available and produced zero code findings
    code_findings = [f for f in findings if f.get("category") == "code"]
    if not code_findings and not shutil.which("semgrep"):
        findings.insert(0, {
            "type":       "scanner-error",
            "category":   "config",
            "file":       "N/A",
            "line":       0,
            "code":       "",
            "severity":   "Critical",
            "confidence": 100,
            "message": (
                "Semgrep is NOT installed — code vulnerability analysis was completely skipped. "
                "Install with: pip install semgrep  then re-run this scan."
            ),
        })

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=0.75*inch, leftMargin=0.75*inch,
        topMargin=0.75*inch,   bottomMargin=0.75*inch,
    )

    from reportlab.lib.styles import getSampleStyleSheet
    styles  = getSampleStyleSheet()
    normal  = styles['Normal']
    heading = styles['Heading2']

    story = []
    story += _render_sast_summary(findings, repo_url, stack, styles, normal, heading)
    for f in findings:
        story += _render_sast_finding(f, styles, normal, heading, None)

    doc.build(story)


@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = active_scans[scan_id]
    return jsonify({
        'scan_id':              scan_id,
        'status':               scan.get('status'),
        'target':               scan.get('target'),
        'mode':                 scan.get('mode', 'scan'),
        'total_vulnerabilities': scan.get('total_vulnerabilities', 0),
        'total_flags':          scan.get('total_flags', 0)
    })


@app.route('/api/download/<scan_id>', methods=['GET'])
def download_report(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = active_scans[scan_id]
    if scan.get('status') != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400
    report_path = scan.get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Report file not found'}), 404
    return send_file(report_path, as_attachment=True,
                     download_name=f'vulnerability_report_{scan_id}.pdf')


@app.route('/api/mode', methods=['POST'])
def set_mode():
    data = request.json
    mode = data.get('mode', 'scan')
    mode_mgr = get_mode_manager()
    success = mode_mgr.set_mode(mode)
    if success:
        return jsonify({'status': 'success', 'mode': mode, 'config': mode_mgr.get_mode_config()})
    return jsonify({'error': 'Invalid mode'}), 400


@app.route('/api/mode', methods=['GET'])
def get_mode():
    mode_mgr = get_mode_manager()
    return jsonify({'current_mode': mode_mgr.current_mode, 'config': mode_mgr.get_mode_config()})


@app.route('/api/modes', methods=['GET'])
def get_available_modes():
    return jsonify({
        'modes': [
            {'name': 'scan',     'description': 'Normal vulnerability scanning (safe, non-exploiting)',
             'features': ['Conservative depth', 'No exploitation', 'Production-safe']},
            {'name': 'lab',      'description': 'Lab/practice environment mode (more aggressive)',
             'features': ['Deeper crawl', 'Can exploit', 'For DVWA, bWAPP, etc.']},
            {'name': 'ctf',      'description': 'CTF mode with flag hunting',
             'features': ['Flag detection', 'Very aggressive', 'Deep crawl']},
            {'name': 'ctf-auth', 'description': 'Authenticated CTF mode',
             'features': ['Requires credentials', 'Flag hunting', 'Post-auth testing']},
        ]
    })


@socketio.on('connect')
def handle_connect():
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


if __name__ == '__main__':
    print("=" * 60)
    print("Vulnerability Scanner API Server v3.1")
    print("=" * 60)
    print("Server:   http://localhost:5001")
    print("SAST:     Semgrep (subprocess) + Secrets/Deps scanner")
    print("Modes:    scan, lab, ctf, ctf-auth")
    print("Scanners: SQLi, XSS (reflected+stored+DOM), IDOR, CSRF,")
    print("          CMDi, Path Traversal, Open Redirect, SSRF (OOB),")
    print("          XXE, SSTI, Headers, Components, WordPress")
    print("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)