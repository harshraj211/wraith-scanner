"""Flask API server with WordPress scanner, authentication support, and multi-mode scanning."""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import os
import uuid
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
        # Create unique key
        key = (finding.get('url'), finding.get('param'), finding.get('type'))
        
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    
    return unique


def run_scan(scan_id, target_url, depth, timeout, auth_config=None, scan_mode='scan'):
    """Main scanning function with WordPress, auth, and mode support."""
    try:
        emit_progress(scan_id, f"Starting scan of {target_url}", "info")
        
        # Get mode manager and apply mode settings
        mode_mgr = get_mode_manager()
        mode_mgr.set_mode(scan_mode)
        mode_config = mode_mgr.get_mode_config()
        
        # Override timeout and depth from mode if not provided
        if depth is None:
            depth = mode_config['max_depth']
        if timeout is None:
            timeout = mode_config['timeout']
        
        emit_progress(scan_id, f"Mode: {scan_mode.upper()} | Depth: {depth} | Timeout: {timeout}s", "info")
        
        # Setup authentication if provided
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
        
        # Initialize flag hunter if in CTF mode
        flag_hunter = None
        if mode_mgr.should_hunt_flags():
            flag_hunter = FlagHunter(mode_mgr.get_flag_patterns())
            emit_progress(scan_id, "🏁 Flag hunting enabled!", "success")
        
        # Check for WordPress
        emit_progress(scan_id, "Checking for WordPress/CMS...", "phase")
        wp_scanner = WordPressScanner(timeout=timeout)
        wp_findings = wp_scanner.scan_url(target_url)
        
        if wp_findings:
            emit_progress(scan_id, f"WordPress detected! Found {len(wp_findings)} WP-specific issues", "warning")
        
        # Phase 1: Crawl
        emit_progress(scan_id, "Phase 1: Crawling target...", "phase")
        crawler = WebCrawler(target_url, max_depth=depth, timeout=timeout)
        results = crawler.crawl()
        urls = results.get("urls", [])
        forms = results.get("forms", [])
        
        emit_progress(scan_id, f"Found {len(urls)} URLs and {len(forms)} forms", "success")
        
        # Initialize scanners (with auth session if available)
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
                
                # Flag hunting if enabled
                if flag_hunter:
                    try:
                        import requests
                        resp = requests.get(url, timeout=timeout)
                        flags = flag_hunter.scan_response(url, resp.text)
                        if flags:
                            for flag in flags:
                                emit_progress(scan_id, f"🏁 FLAG FOUND: {flag['flag']}", "success")
                        findings.extend(flags)
                        
                        # # Check headers and cookies too
                        # flags_headers = flag_hunter.scan_headers(url, dict(resp.headers))
                        # findings.extend(flags_headers)
                        
                        # flags_cookies = flag_hunter.scan_cookies(url, requests.utils.dict_from_cookiejar(resp.cookies))
                        # findings.extend(flags_cookies)
                    except:
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
        
        # Use more workers if in aggressive mode
        max_workers = 10 if mode_config['aggressive'] else 5
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            url_data = [(url, idx+1, len(urls)) for idx, url in enumerate(urls)]
            results = executor.map(scan_single_url, url_data)
            for findings in results:
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
            results = executor.map(scan_single_form, form_data)
            for findings in results:
                all_findings.extend(findings)
        
        emit_progress(scan_id, "Phase 3: Generating report...", "phase")
        
        report_filename = f"scan_{scan_id}.pdf"
        report_path = os.path.join(REPORTS_DIR, report_filename)
        unique_findings = deduplicate_and_group(all_findings)
        
        # Separate flags from vulnerabilities
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
    scan_mode = data.get('mode', 'scan')  # Default to 'scan' mode
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate mode
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


@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    return jsonify({
        'scan_id': scan_id,
        'status': scan.get('status'),
        'target': scan.get('target'),
        'mode': scan.get('mode', 'scan'),
        'total_vulnerabilities': scan.get('total_vulnerabilities', 0),
        'total_flags': scan.get('total_flags', 0)
    })


@app.route('/api/download/<scan_id>', methods=['GET'])
def download_report(scan_id):
    """Download PDF report."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    
    if scan.get('status') != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400
    
    report_path = scan.get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Report file not found'}), 404
    
    return send_file(report_path, as_attachment=True, download_name=f'vulnerability_report_{scan_id}.pdf')


@app.route('/api/mode', methods=['POST'])
def set_mode():
    """Set scanner mode globally."""
    data = request.json
    mode = data.get('mode', 'scan')
    
    mode_mgr = get_mode_manager()
    success = mode_mgr.set_mode(mode)
    
    if success:
        return jsonify({
            'status': 'success',
            'mode': mode,
            'config': mode_mgr.get_mode_config()
        })
    else:
        return jsonify({'error': 'Invalid mode'}), 400


@app.route('/api/mode', methods=['GET'])
def get_mode():
    """Get current mode."""
    mode_mgr = get_mode_manager()
    return jsonify({
        'current_mode': mode_mgr.current_mode,
        'config': mode_mgr.get_mode_config()
    })


@app.route('/api/modes', methods=['GET'])
def get_available_modes():
    """Get list of available modes with descriptions."""
    return jsonify({
        'modes': [
            {
                'name': 'scan',
                'description': 'Normal vulnerability scanning (safe, non-exploiting)',
                'features': ['Conservative depth', 'No exploitation', 'Production-safe']
            },
            {
                'name': 'lab',
                'description': 'Lab/practice environment mode (more aggressive)',
                'features': ['Deeper crawl', 'Can exploit', 'For DVWA, bWAPP, etc.']
            },
            {
                'name': 'ctf',
                'description': 'CTF mode with flag hunting',
                'features': ['Flag detection', 'Very aggressive', 'Deep crawl']
            },
            {
                'name': 'ctf-auth',
                'description': 'Authenticated CTF mode',
                'features': ['Requires credentials', 'Flag hunting', 'Post-auth testing']
            }
        ]
    })


@socketio.on('connect')
def handle_connect():
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


if __name__ == '__main__':
    print("="*60)
    print("Vulnerability Scanner API Server v3.0")
    print("="*60)
    print("Server: http://localhost:5001")
    print("Features: Multi-Mode, WordPress Detection, Authenticated Scanning, Flag Hunting")
    print("Modes: scan, lab, ctf, ctf-auth")
    print("Scanners: SQLi, XSS, IDOR, CSRF, CMDi, Path Traversal, Open Redirect")
    print("="*60)
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
