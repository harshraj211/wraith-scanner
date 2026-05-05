"""Flask API server with WordPress scanner, authentication support, and multi-mode scanning."""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
from concurrent.futures import ThreadPoolExecutor
import os
import uuid
import shutil
import subprocess
import json as _json
import time
from datetime import datetime
from urllib.parse import urlparse
import requests

from scanner.core.async_engine import AsyncScanEngine, build_url_param_pairs
from scanner.core.authorization_matrix import run_authorization_matrix
from scanner.core.crawler import WebCrawler
from scanner.core.live_scan import LiveDiscoveryScanner
from scanner.core.sequence_runner import run_sequence_workflows
from scanner.core.workflows import load_workflows
from scanner.modules.sqli_scanner import SQLiScanner
from scanner.modules.xss_scanner import XSSScanner
from scanner.modules.idor_scanner import IDORScanner
from scanner.modules.redirect_scanner import RedirectScanner
from scanner.modules.cmdi_scanner import CMDIScanner
from scanner.modules.path_traversal_scanner import PathTraversalScanner
from scanner.modules.csrf_scanner import CSRFScanner
from scanner.modules.wordpress_scanner import WordPressScanner
from scanner.utils.deduplication import deduplicate_and_group
from scanner.utils.auth_manager import get_auth_manager
from scanner.utils.mode_manager import get_mode_manager
from scanner.reporting.pdf_generator import generate_pdf_report
from scanner.reporting.json_export import write_scan_json
from scanner.core.models import Finding, ProofTask, RequestRecord, ScanConfig, findings_from_legacy
from scanner.core.models import ResponseRecord
from scanner.exploitation.evidence import persist_proof_result
from scanner.exploitation.models import ProofContext
from scanner.exploitation.planner import create_proof_task
from scanner.exploitation.registry import default_registry
from scanner.exploitation.runner import run_proof_coroutine
from scanner.importers.common import (
    candidates_to_scan_targets,
    load_candidates_from_imports,
    merge_scan_targets,
    save_candidates_to_corpus,
)
from scanner.integrations.nuclei_adapter import NucleiAdapter, NucleiRunConfig, normalize_targets
from scanner.integrations.cve_intel import enrich_findings, finding_from_dict
from scanner.integrations.nuclei_manager import NucleiAssetManager
from scanner.integrations.nuclei_policy import policy_options, validate_policy_acknowledgement
from scanner.integrations.template_trust import (
    apply_template_trust,
    load_template_trust,
    save_template_trust,
    trust_config_path,
)
from scanner.manual.browser_launcher import WraithBrowserController
from scanner.manual.passive import run_passive_checks
from scanner.manual.proxy import ProxyConfig, WraithProxyController
from scanner.storage.repository import StorageRepository
from scanner.utils.auth_profiles import build_auth_profile_from_config, check_session
from scanner.modules.crypto_scanner import CryptoScanner
from scanner.modules.ssrf_scanner import SSRFScanner
from scanner.modules.xxe_scanner import XXEScanner
from scanner.modules.ssti_scanner import SSTIScanner
from scanner.modules.header_scanner import HeaderScanner
from scanner.modules.component_scanner import ComponentScanner
from scanner.modules.graphql_scanner import GraphQLScanner
from scanner.modules.race_scanner import RaceConditionScanner
from scanner.modules.websocket_scanner import WebSocketScanner
from scanner.modules.semgrep_scanner import SemgrepScanner, _find_semgrep
# NOTE: SemgrepScanner import removed — Semgrep now runs via subprocess directly.
#       If you need to call SemgrepScanner class elsewhere, re-add the import there.
from scanner.modules.sast_scanner import SASTScanner
from scanner.modules.taint_analyzer import TaintAnalyzer
from scanner.utils.github_manager import get_github_manager, detect_tech_stack
from scanner.reporting.pdf_generator_sast_patch import (
    _render_sast_finding, _render_sast_summary,
    SAST_VULN_DESCRIPTIONS, SAST_OWASP_MAPPING, SAST_CWE_MAPPING
)


def _check_semgrep():
    if _find_semgrep():
        print("[OK] Semgrep found - SAST engine ready")
    else:
        print("[!] Semgrep not installed - SAST code analysis will be skipped")
        print("    Install with: pip install semgrep")


_check_semgrep()

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

active_scans = {}
manual_proxy = WraithProxyController()
wraith_browser = WraithBrowserController()
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


DAST_MODULES = [
    "wordpress",
    "sqli",
    "xss",
    "idor",
    "open-redirect",
    "cmdi",
    "path-traversal",
    "csrf",
    "crypto",
    "ssrf",
    "xxe",
    "ssti",
    "headers",
    "components",
    "graphql",
    "race",
    "websocket",
]


def _storage_repo():
    try:
        return StorageRepository()
    except Exception as exc:
        print(f"[storage] disabled: {exc}")
        return None


def _scan_config(scan_id, target_url, depth, auth_config, enabled_modules, auth_profile=None):
    auth_profiles = [auth_profile.to_dict() if hasattr(auth_profile, "to_dict") else auth_profile] if auth_profile else []
    if not auth_profiles and auth_config:
        auth_profiles.append({
            "profile_id": auth_config.get("profile_id", ""),
            "name": auth_config.get("name", "api-auth"),
            "role": auth_config.get("role", "authenticated"),
            "auth_type": auth_config.get("type", "custom"),
            "headers": auth_config.get("headers", {}),
            "cookies": auth_config.get("cookies", {}),
        })
    return ScanConfig(
        scan_id=scan_id,
        target_base_url=target_url,
        safety_mode=(auth_config or {}).get("safety_mode", "safe"),
        max_depth=depth or 0,
        auth_profiles=auth_profiles,
        enabled_modules=enabled_modules,
        output_dir=REPORTS_DIR,
    )


def _auth_role(auth_config):
    if not auth_config:
        return "anonymous"
    return auth_config.get("role") or ("authenticated" if auth_config else "anonymous")


def _persist_discovered_requests(repo, scan_id, urls, forms, auth_role):
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
                    auth_role=auth_role,
                )
            )
        except Exception:
            pass
    for form in forms:
        try:
            body = {
                item.get("name", ""): item.get("value", "")
                for item in form.get("inputs", [])
                if item.get("name")
            }
            repo.save_request(
                RequestRecord.create(
                    scan_id=scan_id,
                    source="crawler",
                    method=form.get("method", "GET"),
                    url=form.get("action", ""),
                    headers=form.get("extra_headers", {}),
                    body=body,
                    auth_role=auth_role,
                )
            )
        except Exception:
            pass


def _persist_findings(repo, canonical_findings):
    if repo is None:
        return
    for finding in canonical_findings:
        try:
            repo.save_finding(finding)
        except Exception:
            pass


def _refresh_scan_artifacts(scan_id):
    """Regenerate downloadable artifacts after post-scan enrichment."""
    scan = active_scans.get(scan_id) or {}
    if scan.get("status") != "completed":
        return

    findings = scan.get("canonical_findings") or []
    target = scan.get("target") or scan.get("target_base_url") or ""
    urls = scan.get("urls") or []
    forms = scan.get("forms") or []

    report_path = scan.get("report_path")
    if report_path:
        try:
            generate_pdf_report(target, urls, forms, findings, report_path)
        except Exception as exc:
            print(f"[report] PDF refresh failed for {scan_id}: {exc}")

    json_report_path = scan.get("json_report_path")
    if json_report_path and os.path.exists(json_report_path):
        try:
            with open(json_report_path, "r", encoding="utf-8") as handle:
                payload = _json.load(handle)
            payload["findings"] = findings
            metadata = dict(payload.get("metadata") or {})
            metadata.update({
                "nuclei_summary": scan.get("nuclei_summary", {}),
                "nuclei_runs": scan.get("nuclei_runs", []),
                "cve_intel_summary": scan.get("cve_intel_summary", {}),
            })
            payload["metadata"] = metadata
            with open(json_report_path, "w", encoding="utf-8") as handle:
                _json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
        except Exception as exc:
            print(f"[report] JSON refresh failed for {scan_id}: {exc}")


def _parse_list_value(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).replace("\n", ",").split(",") if item.strip()]


def _targets_for_nuclei(repo, scan_id, payload, scan_payload):
    explicit_targets = _parse_list_value(payload.get("targets"))
    if explicit_targets:
        return normalize_targets(explicit_targets)

    candidates = [scan_payload.get("target_base_url", "")]
    try:
        for request_record in repo.list_requests(scan_id, {}):
            url = request_record.get("url")
            if url:
                candidates.append(url)
    except Exception:
        pass
    return normalize_targets(candidates)[: int(payload.get("max_targets") or 200)]


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


def run_scan(
    scan_id,
    target_url,
    depth,
    timeout,
    auth_config=None,
    scan_mode='scan',
    import_config=None,
    sequence_config=None,
):
    """Main scanning function with WordPress, auth, and mode support."""
    try:
        emit_progress(scan_id, f"Starting scan of {target_url}", "info")
        auth_role = _auth_role(auth_config)
        auth_profile = build_auth_profile_from_config(
            auth_config,
            base_url=target_url,
            default_name="api-auth",
        )
        auth_role = auth_profile.role or auth_role
        auth_health = {"status": "skipped", "reason": "no health check configured"}
        import_summary = {}
        sequence_results = []

        mode_mgr = get_mode_manager()
        mode_mgr.set_mode(scan_mode)
        mode_config = mode_mgr.get_mode_config()

        if depth is None:
            depth = mode_config['max_depth']
        if timeout is None:
            timeout = mode_config['timeout']

        emit_progress(scan_id, f"Mode: {scan_mode.upper()} | Depth: {depth} | Timeout: {timeout}s", "info")
        storage_repo = _storage_repo()
        scan_config = _scan_config(scan_id, target_url, depth, auth_config, DAST_MODULES, auth_profile)
        if storage_repo is not None:
            storage_repo.create_scan(scan_config)
            storage_repo.save_auth_profile(auth_profile)

        auth_manager = get_auth_manager()
        auth_manager.logout()
        authenticated_session = None
        profile_result = auth_manager.apply_auth_profile(auth_profile)
        if profile_result.applied:
            authenticated_session = auth_manager.get_session()
            emit_progress(
                scan_id,
                f"Auth profile applied: {auth_profile.name} ({auth_profile.role})",
                "success",
            )
        for profile_error in profile_result.errors:
            emit_progress(scan_id, f"Auth profile warning: {profile_error}", "warning")

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
                elif auth_type == 'basic':
                    username = auth_config.get('username')
                    password = auth_config.get('password')
                    if username and password:
                        auth_manager.login_basic_auth(username, password)
                        authenticated_session = auth_manager.get_session()
                        emit_progress(scan_id, f"Basic auth configured for {username}", "success")
                elif auth_type == 'bearer':
                    token = auth_config.get('token')
                    if token:
                        auth_manager.set_bearer_token(token)
                        authenticated_session = auth_manager.get_session()
                        emit_progress(scan_id, "Bearer token configured", "success")
                elif auth_type == 'api_key':
                    key_name = auth_config.get('name')
                    key_value = auth_config.get('value') or auth_config.get('token')
                    key_location = auth_config.get('location', 'header')
                    if key_name and key_value:
                        auth_manager.set_api_key(key_name, key_value, key_location)
                        authenticated_session = auth_manager.get_session()
                        emit_progress(
                            scan_id,
                            f"API key configured in {key_location}: {key_name}",
                            "success",
                        )
                elif auth_type in ('custom', 'headers'):
                    headers = auth_config.get('headers') or {}
                    if headers:
                        auth_manager.set_custom_headers(headers)
                        authenticated_session = auth_manager.get_session()
                        emit_progress(scan_id, "Custom auth headers configured", "success")

                bearer_token = auth_config.get('bearer_token')
                if bearer_token and auth_type != 'bearer':
                    auth_manager.set_bearer_token(bearer_token)
                    authenticated_session = auth_manager.get_session()
                    emit_progress(scan_id, "Bearer token configured", "success")

                api_keys = auth_config.get('api_keys') or []
                for api_key in api_keys:
                    key_name = api_key.get('name')
                    key_value = api_key.get('value') or api_key.get('token')
                    key_location = api_key.get('location', 'header')
                    if not key_name or key_value is None:
                        continue
                    auth_manager.set_api_key(key_name, key_value, key_location)
                    authenticated_session = auth_manager.get_session()
                    emit_progress(
                        scan_id,
                        f"API key configured in {key_location}: {key_name}",
                        "success",
                    )

                headers = auth_config.get('headers') or {}
                if headers and auth_type not in ('custom', 'headers'):
                    auth_manager.set_custom_headers(headers)
                    authenticated_session = auth_manager.get_session()
                    emit_progress(scan_id, "Custom auth headers configured", "success")

                cookies = auth_config.get('cookies') or {}
                if cookies:
                    auth_manager.set_cookies(cookies)
                    authenticated_session = auth_manager.get_session()
                    emit_progress(scan_id, "Custom auth cookies configured", "success")

        if auth_profile.session_health_check:
            auth_health_result = check_session(
                auth_profile,
                session=auth_manager.get_session(),
                timeout=timeout,
            )
            auth_health = auth_health_result.to_dict()
            if auth_health_result.healthy:
                emit_progress(scan_id, f"Auth health check passed for role {auth_profile.role}", "success")
            else:
                emit_progress(
                    scan_id,
                    f"Auth health check {auth_health_result.status}: {auth_health_result.reason}",
                    "warning",
                )

        emit_progress(scan_id, "Checking for WordPress/CMS...", "phase")
        wp_scanner = WordPressScanner(timeout=timeout)
        wp_findings = wp_scanner.scan_url(target_url)

        if wp_findings:
            emit_progress(scan_id, f"WordPress detected! Found {len(wp_findings)} WP-specific issues", "warning")

        scan_start_time = time.time()
        workflows = load_workflows(
            (auth_config or {}).get("workflows") or (auth_config or {}).get("workflow")
        )
        sqli = SQLiScanner(timeout=timeout, session=authenticated_session)
        xss = XSSScanner(timeout=timeout, session=authenticated_session)
        idor = IDORScanner(timeout=timeout, session=authenticated_session)
        redir = RedirectScanner(timeout=timeout, session=authenticated_session)
        cmdi = CMDIScanner(timeout=timeout, session=authenticated_session)
        path = PathTraversalScanner(timeout=timeout, session=authenticated_session)
        csrf = CSRFScanner(timeout=timeout, session=authenticated_session)
        crypto = CryptoScanner(timeout=timeout, session=authenticated_session)
        ssrf = SSRFScanner(timeout=timeout, session=authenticated_session)
        xxe = XXEScanner(timeout=timeout, session=authenticated_session)
        ssti = SSTIScanner(timeout=timeout, session=authenticated_session)
        header_scan = HeaderScanner(timeout=timeout, session=authenticated_session)
        component_scan = ComponentScanner(timeout=timeout, session=authenticated_session)
        graphql = GraphQLScanner(timeout=timeout, session=authenticated_session)
        race = RaceConditionScanner(timeout=timeout, session=authenticated_session)
        websocket = WebSocketScanner(timeout=timeout, session=authenticated_session)
        live_scanner = LiveDiscoveryScanner(
            form_scanners=[sqli, xss, cmdi, path, csrf, crypto, ssrf, ssti, xxe, graphql, race],
            websocket_scanner=websocket,
            progress_cb=lambda msg: emit_progress(scan_id, msg, "info"),
        )

        emit_progress(scan_id, "Phase 1: Crawling target...", "phase")
        crawler = WebCrawler(
            target_url,
            max_depth=depth,
            timeout=timeout,
            session=authenticated_session,
            workflows=workflows,
            discovery_callback=live_scanner.handle_discovery,
            auth_profile=auth_profile,
        )
        results = crawler.crawl()
        urls = results.get("urls", [])
        forms = results.get("forms", [])
        websockets = results.get("websockets", [])
        deep_state = results.get("deep_state", [])
        crawled_urls = list(urls)
        crawled_forms = list(forms)

        try:
            imported_candidates, import_summary = load_candidates_from_imports(
                import_config or {},
                base_url=target_url,
            )
            if imported_candidates:
                imported_urls, imported_forms = candidates_to_scan_targets(imported_candidates)
                save_candidates_to_corpus(
                    storage_repo,
                    scan_id,
                    imported_candidates,
                    auth_profile_id=auth_profile.profile_id,
                    auth_role=auth_role,
                )
                for form in imported_forms:
                    live_scanner.handle_discovery("form", form)
                urls, forms = merge_scan_targets(urls, forms, imported_urls, imported_forms)
                emit_progress(
                    scan_id,
                    f"Imported {len(imported_candidates)} API request candidates: {import_summary}",
                    "success",
                )
        except Exception as exc:
            emit_progress(scan_id, f"API import failed: {exc}", "warning")

        deep_state_mutations = sum(len(item.get("mutations", [])) for item in deep_state)
        deep_state_revealed = sum((item.get("revealed", {}) or {}).get("count", 0) for item in deep_state)
        deep_state_wizard_steps = sum(len((item.get("wizard", {}) or {}).get("clicked_steps", [])) for item in deep_state)

        crawl_duration = round(time.time() - scan_start_time, 1)
        emit_progress(
            scan_id,
            f"Crawl complete in {crawl_duration}s: {len(urls)} URLs, {len(forms)} forms, {len(websockets)} websockets",
            "success",
        )
        if deep_state_mutations or deep_state_wizard_steps:
            emit_progress(
                scan_id,
                f"Deep-state mutator flipped {deep_state_mutations} client-side flags, stepped through {deep_state_wizard_steps} wizard actions, and exposed {deep_state_revealed} privileged UI hints",
                "info",
            )
        _persist_discovered_requests(storage_repo, scan_id, crawled_urls, crawled_forms, auth_role)

        if sequence_config:
            try:
                sequence_results = run_sequence_workflows(
                    sequence_config,
                    base_url=target_url,
                    session=authenticated_session or auth_manager.get_session(),
                    storage_repo=storage_repo,
                    scan_id=scan_id,
                    auth_profile_id=auth_profile.profile_id,
                    auth_role=auth_role,
                    safety_mode=scan_config.safety_mode,
                    timeout=timeout,
                )
                executed = sum(
                    1 for workflow in sequence_results for step in workflow.steps if step.status == "executed"
                )
                skipped = sum(workflow.skipped for workflow in sequence_results)
                emit_progress(
                    scan_id,
                    f"Sequence workflows executed {executed} step(s), skipped {skipped}",
                    "success",
                )
            except Exception as exc:
                emit_progress(scan_id, f"Sequence workflow failed: {exc}", "warning")

        # Run passive checks in parallel (headers, components, crypto)
        all_findings = wp_findings.copy()
        all_findings.extend(live_scanner.findings)
        emit_progress(scan_id, "Running passive checks (headers, components, crypto)...", "info")
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_header    = pool.submit(header_scan.scan_url, target_url)
            f_comp_url  = pool.submit(component_scan.scan_url, target_url)
            f_comp_base = pool.submit(component_scan.scan_base_url, target_url)
            f_crypto    = pool.submit(crypto.scan_url, target_url)
        for fut in [f_header, f_comp_url, f_comp_base, f_crypto]:
            try:
                all_findings.extend(fut.result(timeout=30))
            except Exception:
                pass

        emit_progress(scan_id, "Phase 2: Testing URL targets while forms are scanned during crawl...", "phase")
        engine = AsyncScanEngine(
            max_concurrent=20 if mode_config['aggressive'] else 10,
            timeout=timeout,
            auth_session=authenticated_session,
            storage_repo=storage_repo,
            scan_id=scan_id,
            traffic_source="fuzzer",
            auth_profile_id=auth_profile.profile_id,
            auth_role=auth_role,
        )
        url_param_pairs = build_url_param_pairs(urls)
        dast_scanners = [sqli, xss, idor, cmdi, path, ssrf, ssti, xxe, redir]

        # Single event loop — URLs + forms scan concurrently (full I/O overlap)
        all_findings.extend(
            engine.scan_urls_sync(
                url_param_pairs,
                dast_scanners,
                progress_cb=lambda msg: emit_progress(scan_id, msg, "info"),
            )
        )

        # Stored XSS sweep (checks all URLs for markers injected during scan)
        stored_xss = xss.check_stored(urls, session=authenticated_session)
        all_findings.extend(stored_xss)

        blind_sqli = sqli.collect_oob_findings()
        all_findings.extend(blind_sqli)

        # Blind SSRF OOB callback collection
        blind_ssrf = ssrf.collect_oob_findings()
        all_findings.extend(blind_ssrf)
        all_findings.extend(websocket.collect_oob_findings())

        xss_intel = dict(xss.intelligence_stats)
        ssrf_network_map = ssrf.get_network_map()
        if xss_intel.get("mutation_attempts"):
            emit_progress(
                scan_id,
                f"Adaptive mutation engine ran {xss_intel.get('mutation_attempts', 0)} retries and confirmed {xss_intel.get('confirmed', 0)} exploit paths",
                "info",
            )
        if ssrf.mapping_stats.get("tracked_injections"):
            emit_progress(
                scan_id,
                f"OOB mapper tracked {ssrf.mapping_stats.get('tracked_injections', 0)} probes across {len(ssrf_network_map)} callback groups",
                "info",
            )

        for live_error in live_scanner.errors:
            emit_progress(scan_id, live_error, "warning")

        emit_progress(scan_id, "Phase 3: Generating report...", "phase")

        scan_duration = round(time.time() - scan_start_time, 1)

        report_filename = f"scan_{scan_id}.pdf"
        report_path = os.path.join(REPORTS_DIR, report_filename)
        unique_findings = deduplicate_and_group(all_findings)
        canonical_findings = findings_from_legacy(
            unique_findings,
            target_url=target_url,
            scan_id=scan_id,
            auth_role=auth_role,
            discovery_method="dast",
        )
        _persist_findings(storage_repo, canonical_findings)

        generate_pdf_report(target_url, urls, forms, unique_findings, report_path,
                            scan_duration=scan_duration)
        json_report_filename = f"scan_{scan_id}.json"
        json_report_path = os.path.join(REPORTS_DIR, json_report_filename)
        write_scan_json(
            json_report_path,
            scan_config=scan_config,
            urls=urls,
            forms=forms,
            findings=canonical_findings,
            legacy_findings=unique_findings,
            metadata={
                "scan_duration_seconds": scan_duration,
                "deep_state_summary": {
                    "mutations": deep_state_mutations,
                    "wizard_steps": deep_state_wizard_steps,
                    "revealed_hints": deep_state_revealed,
                },
                "oob_mapping_summary": dict(ssrf.mapping_stats),
                "auth_health": auth_health,
                "api_imports": import_summary,
                "sequence_workflows": [workflow.to_dict() for workflow in sequence_results],
            },
        )

        active_scans[scan_id] = {
            'status': 'completed',
            'target': target_url,
            'mode': 'dast',
            'urls': urls,
            'forms': forms,
            'websockets': websockets,
            'findings': unique_findings,
            'report_path': report_path,
            'json_report_path': json_report_path,
            'total_vulnerabilities': len(unique_findings),
            'deep_state': deep_state,
            'deep_state_summary': {
                'mutations': deep_state_mutations,
                'wizard_steps': deep_state_wizard_steps,
                'revealed_hints': deep_state_revealed,
            },
            'intelligent_mutation': xss_intel,
            'oob_mapping': ssrf_network_map,
            'api_imports': import_summary,
            'sequence_workflows': [workflow.to_dict() for workflow in sequence_results],
            'oob_mapping_summary': dict(ssrf.mapping_stats),
            'auth_health': auth_health,
            'scan_type': 'DAST',
            'canonical_findings': [finding.to_dict() for finding in canonical_findings],
        }

        emit_progress(scan_id, f"Scan complete! Found {len(unique_findings)} vulnerabilities", "success")
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
    import_config = data.get('imports') or data.get('api_imports') or {}
    sequence_config = (
        data.get('sequence_workflows')
        or data.get('sequence_workflow')
        or data.get('api_workflows')
        or []
    )
    scan_mode = 'scan'

    if not target_url:
        return jsonify({'error': 'URL is required'}), 400

    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {'status': 'running', 'target': target_url, 'mode': 'dast', 'scan_type': 'DAST'}

    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target_url, depth, timeout, auth_config, scan_mode, import_config, sequence_config),
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
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
    active_scans[scan_id] = {'status': 'running', 'target': repo_url, 'mode': 'sast', 'scan_type': 'SAST'}

    def run_sast(scan_id, repo_url, token, branch):
        """
        SAST scan — Semgrep is MANDATORY for code analysis (runs via subprocess).
        SASTScanner handles secrets + deps only (TaintAnalyzer removed).
        Semgrep JSON output parsed directly — no legacy format mapping.
        """
        try:
            emit_progress(scan_id, f"Starting SAST scan: {repo_url}", "phase")
            storage_repo = _storage_repo()
            scan_config = ScanConfig(
                scan_id=scan_id,
                target_base_url=repo_url,
                safety_mode="safe",
                max_depth=0,
                auth_profiles=[],
                enabled_modules=["semgrep", "taint-analyzer", "secrets", "dependencies"],
                output_dir=REPORTS_DIR,
            )
            if storage_repo is not None:
                storage_repo.create_scan(scan_config)

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
            semgrep_bin = _find_semgrep()

            # ── PHASE 1: Semgrep via subprocess — MANDATORY ────────────────
            if not semgrep_bin:
                emit_progress(
                    scan_id,
                    "Semgrep NOT installed — code vulnerability analysis SKIPPED. "
                    "Run: pip install semgrep",
                    "error"
                )
                # Honest failure — do NOT fall back to TaintAnalyzer
            else:
                emit_progress(scan_id, "Running Semgrep AST analysis...", "phase")

                # Check login status — p/ requires semgrep login, r/ does not
                import subprocess as _sp
                _utf8_env = {**os.environ, "PYTHONUTF8": "1"}

                def _semgrep_logged_in():
                    try:
                        r = _sp.run(
                            [semgrep_bin, "show", "identity"],
                            capture_output=True, text=True, timeout=15,
                            env=_utf8_env,
                        )
                        # identity info is printed to stderr
                        output = (r.stdout + r.stderr).lower()
                        return r.returncode == 0 and "logged in" in output
                    except Exception:
                        return False

                open_rulesets = {
                    "javascript": ["r/javascript", "r/nodejs"],
                    "typescript": ["r/typescript", "r/nodejs"],
                    "python":     ["r/python"],
                    "php":        ["r/php"],
                    "java":       ["r/java"],
                    "go":         ["r/go"],
                    "ruby":       ["r/ruby"],
                }

                if _semgrep_logged_in():
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
                    emit_progress(scan_id, "Semgrep authenticated — using p/ registry", "info")
                else:
                    base_rulesets  = ["r/generic.secrets"]
                    extra_rulesets = open_rulesets.get(lang.lower(), [])
                    emit_progress(scan_id,
                        "Semgrep not logged in — using r/ open registry (no login needed). "
                        "For full coverage run: semgrep login", "warning")

                all_rulesets = base_rulesets + extra_rulesets

                # Write custom rules to temp file (always works, no login)
                import os as _os
                custom_rules_path = _os.path.join(repo_path, ".vulnscan_rules.yaml")
                with open(custom_rules_path, "w") as _f:
                    from scanner.modules.semgrep_scanner import CUSTOM_RULES
                    _f.write(CUSTOM_RULES)
                all_rulesets.insert(0, custom_rules_path)  # custom rules first

                semgrep_cmd = (
                    [semgrep_bin, "--json", "--quiet", "--timeout=30"]
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
                        env=_utf8_env,
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

                        # Only show non-Pro-engine errors to the user
                        shown_errors = 0
                        for err in semgrep_errors:
                            msg = err.get('message', '')
                            # Suppress noisy "Pro engine" warnings — user can't fix these
                            if 'pro engine' in msg.lower() or 'pro only' in msg.lower():
                                continue
                            if shown_errors < 3:
                                emit_progress(scan_id,
                                    f"Semgrep error: {msg}", "warning")
                                shown_errors += 1

                        emit_progress(scan_id,
                            f"Semgrep: {len(semgrep_results)} raw findings", "info")

                        sev_map = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}

                        # Confidence mapping from Semgrep metadata
                        _conf_map = {"HIGH": 90, "MEDIUM": 70, "LOW": 40}
                        skipped_low = 0

                        for r in semgrep_results:
                            meta     = r.get("extra", {})
                            metadata = meta.get("metadata", {})
                            severity = meta.get("severity", "WARNING").upper()

                            # Use Semgrep's own confidence if available
                            raw_conf = metadata.get("confidence", "MEDIUM").upper()
                            confidence = _conf_map.get(raw_conf, 70)

                            # Filter out INFO/LOW severity with LOW confidence
                            # (format-string noise, console.log concatenations, etc.)
                            if severity == "INFO" and confidence < 60:
                                skipped_low += 1
                                continue

                            findings.append({
                                "type":       r.get("check_id", "semgrep-finding"),
                                "category":   "code",
                                "file":       r.get("path", ""),
                                "line":       r.get("start", {}).get("line", 0),
                                "code":       meta.get("lines", "").strip()[:200],
                                "message":    meta.get("message", ""),
                                "severity":   sev_map.get(severity, "Medium"),
                                "confidence": confidence,
                                "cwe":        metadata.get("cwe", ""),
                                "owasp":      metadata.get("owasp", ""),
                                "source":     "semgrep",
                            })

                        if skipped_low:
                            emit_progress(scan_id,
                                f"Filtered {skipped_low} low-confidence noise findings",
                                "info")

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

                # Clean up custom rules file
                try:
                    _os.remove(custom_rules_path)
                except Exception:
                    pass

            # ── PHASE 2: SASTScanner — secrets + deps ONLY ─────────────────
            emit_progress(scan_id, "Running cross-file taint analysis...", "phase")
            taint_scanner = TaintAnalyzer()
            taint_findings = taint_scanner.scan_repo(repo_path, file_tree, stack)
            emit_progress(scan_id, f"Taint analysis: {len(taint_findings)} findings", "info")

            emit_progress(scan_id, "Running secrets/dependency scanner...", "phase")
            regex_scanner  = SASTScanner()
            regex_findings = regex_scanner.scan_repo(repo_path, file_tree)
            emit_progress(scan_id,
                f"Secrets/deps: {len(regex_findings)} findings", "info")

            # Merge + deduplicate on (file, line, type)
            existing_keys = {
                (f.get("file"), f.get("line"), f.get("type"), f.get("source")) for f in findings
            }
            taint_added = 0
            for tf in taint_findings:
                key = (tf.get("file"), tf.get("line"), tf.get("type"), tf.get("source"))
                if key in existing_keys:
                    continue
                findings.append(tf)
                existing_keys.add(key)
                taint_added += 1
            added = 0
            for rf in regex_findings:
                key = (rf.get("file"), rf.get("line"), rf.get("type"), rf.get("source"))
                if key not in existing_keys:
                    findings.append(rf)
                    existing_keys.add(key)
                    added += 1

            emit_progress(scan_id,
                f"Combined: {len(findings)} total "
                f"({semgrep_count} semgrep + {taint_added} taint + {added} secrets/deps)",
                "success")

            # ── Category summary ───────────────────────────────────────────
            cats = {
                "secret":     len([f for f in findings if f.get("category") == "secret"]),
                "code":       len([f for f in findings if f.get("category") == "code"]),
                "dependency": len([f for f in findings if f.get("category") == "dependency"]),
                "config":     len([f for f in findings if f.get("category") == "config"]),
                "taint":      len([f for f in findings if f.get("source") == "taint-analyzer"]),
            }
            emit_progress(scan_id,
                f"Breakdown — code: {cats['code']} | secrets: {cats['secret']} | "
                f"deps: {cats['dependency']} | config: {cats['config']} | taint: {cats['taint']}",
                "warning" if findings else "success")

            # ── PDF ────────────────────────────────────────────────────────
            emit_progress(scan_id, "Generating PDF report...", "phase")
            report_filename = f"sast_{scan_id}.pdf"
            report_path     = os.path.join(REPORTS_DIR, report_filename)
            _generate_sast_pdf(repo_url, findings, stack, report_path)
            canonical_findings = findings_from_legacy(
                findings,
                target_url=repo_url,
                scan_id=scan_id,
                auth_role="source",
                discovery_method="sast",
            )
            _persist_findings(storage_repo, canonical_findings)
            json_report_path = os.path.join(REPORTS_DIR, f"sast_{scan_id}.json")
            write_scan_json(
                json_report_path,
                scan_config=scan_config,
                urls=[],
                forms=[],
                findings=canonical_findings,
                legacy_findings=findings,
                metadata={"tech_stack": stack, "summary": cats},
            )

            github_mgr.cleanup()

            active_scans[scan_id] = {
                "status":                "completed",
                "target":                repo_url,
                "mode":                  "sast",
                "scan_type":             "SAST (Semgrep AST + Cross-File Taint + Secrets/Deps)",
                "findings":              findings,
                "report_path":           report_path,
                "json_report_path":      json_report_path,
                "total_vulnerabilities": len(findings),
                "tech_stack":            stack,
                "summary":               cats,
                "canonical_findings":    [finding.to_dict() for finding in canonical_findings],
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
    if not code_findings and not _find_semgrep():
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
        'total_vulnerabilities': scan.get('total_vulnerabilities', 0),
        'mode':                 scan.get('mode', 'dast'),
        'scan_type':            scan.get('scan_type', 'DAST'),
        'summary':              scan.get('summary', {}),
        'deep_state_summary':   scan.get('deep_state_summary', {}),
        'intelligent_mutation': scan.get('intelligent_mutation', {}),
        'oob_mapping_summary':  scan.get('oob_mapping_summary', {}),
        'auth_health':          scan.get('auth_health', {}),
        'api_imports':          scan.get('api_imports', {}),
        'sequence_workflows':   scan.get('sequence_workflows', []),
        'nuclei_summary':       scan.get('nuclei_summary', {}),
        'nuclei_runs':          scan.get('nuclei_runs', []),
        'cve_intel_summary':    scan.get('cve_intel_summary', {}),
        'tech_stack':           scan.get('tech_stack', {}),
        'findings':             scan.get('findings', []),
        'canonical_findings':   scan.get('canonical_findings', []),
        'report_path':          scan.get('report_path'),
        'json_report_path':     scan.get('json_report_path'),
        'error':                scan.get('error'),
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


@app.route('/api/download-json/<scan_id>', methods=['GET'])
def download_json_report(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = active_scans[scan_id]
    if scan.get('status') != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400
    report_path = scan.get('json_report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'JSON report file not found'}), 404
    return send_file(
        report_path,
        as_attachment=True,
        download_name=f'wraith_scan_{scan_id}.json',
        mimetype='application/json',
    )


@app.route('/api/corpus/<scan_id>/requests', methods=['GET'])
def list_corpus_requests(scan_id):
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503

    filters = {}
    for key in ('method', 'host', 'content_type', 'source', 'auth_role', 'parameter_name'):
        value = request.args.get(key)
        if value:
            filters[key] = value
    path_contains = request.args.get('path_contains') or request.args.get('path')
    if path_contains:
        filters['path_contains'] = path_contains
    status_code = request.args.get('status_code')
    if status_code:
        try:
            filters['status_code'] = int(status_code)
        except ValueError:
            return jsonify({'error': 'status_code must be an integer'}), 400
    has_finding = request.args.get('has_finding')
    if has_finding is not None and has_finding != '':
        filters['has_finding'] = str(has_finding).lower() in {'1', 'true', 'yes', 'on'}

    requests_list = repo.list_requests(scan_id, filters)
    return jsonify({
        'scan_id': scan_id,
        'count': len(requests_list),
        'requests': requests_list,
    })


@app.route('/api/corpus/request/<request_id>', methods=['GET'])
def get_corpus_request(request_id):
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    request_record = repo.get_request(request_id)
    if not request_record:
        return jsonify({'error': 'Request not found'}), 404
    return jsonify({
        'request': request_record,
        'response': repo.get_response_for_request(request_id),
    })


@app.route('/api/corpus/<scan_id>/findings/manual', methods=['POST'])
def create_manual_finding(scan_id):
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    if not repo.get_scan(scan_id):
        return jsonify({'error': 'Scan not found'}), 404

    payload = request.get_json(silent=True) or {}
    title = str(payload.get('title') or '').strip()
    vuln_type = str(payload.get('vuln_type') or payload.get('type') or 'manual').strip().lower()
    severity = str(payload.get('severity') or 'medium').strip().lower()
    if not title:
        return jsonify({'error': 'title is required'}), 400
    if severity not in {'critical', 'high', 'medium', 'low', 'info'}:
        return jsonify({'error': 'severity must be critical, high, medium, low, or info'}), 400

    request_id = str(payload.get('request_id') or '').strip()
    request_record = repo.get_request(request_id) if request_id else None
    response_record = repo.get_response_for_request(request_id) if request_id else None
    target_url = str(payload.get('url') or (request_record or {}).get('url') or '')
    method = str(payload.get('method') or (request_record or {}).get('method') or 'GET').upper()
    parameter = str(payload.get('parameter_name') or payload.get('parameter') or '').strip()
    evidence_parts = [str(payload.get('evidence') or '').strip()]
    if request_record:
        evidence_parts.append(f"Request evidence: {request_record.get('method')} {request_record.get('url')}")
    if response_record:
        evidence_parts.append(f"Response evidence: HTTP {response_record.get('status_code')} {response_record.get('content_type') or ''}".strip())
    evidence = '\n'.join(part for part in evidence_parts if part)

    finding = Finding.from_legacy(
        {
            'title': title,
            'type': vuln_type or 'manual',
            'severity': severity,
            'confidence': int(payload.get('confidence') or 80),
            'url': target_url,
            'method': method,
            'param': parameter,
            'evidence': evidence,
            'remediation': str(payload.get('remediation') or 'Validate the issue manually and apply an appropriate fix.').strip(),
            'source': 'manual',
            'metadata': {
                'request_id': request_id,
                'response_id': (response_record or {}).get('response_id', ''),
                'operator_note': str(payload.get('operator_note') or '').strip(),
            },
        },
        target_url=target_url,
        scan_id=scan_id,
        auth_role=str(payload.get('auth_role') or (request_record or {}).get('auth_role') or 'manual'),
        discovery_method='manual',
    )
    repo.save_finding(finding)
    return jsonify({'scan_id': scan_id, 'finding': finding.to_dict()}), 201


@app.route('/api/corpus/<scan_id>/findings', methods=['GET'])
def list_corpus_findings(scan_id):
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    filters = {}
    for key in ('severity', 'vuln_type', 'auth_role'):
        value = request.args.get(key)
        if value:
            filters[key] = value
    findings = repo.list_findings(scan_id, filters)
    return jsonify({
        'scan_id': scan_id,
        'count': len(findings),
        'findings': findings,
    })


@app.route('/api/integrations/nuclei/status', methods=['GET'])
def nuclei_status_endpoint():
    payload = NucleiAssetManager().status().to_dict()
    payload['policy_options'] = policy_options()
    payload['template_trust'] = load_template_trust().to_dict()
    payload['template_trust_path'] = str(trust_config_path())
    return jsonify(payload)


@app.route('/api/integrations/nuclei/trust', methods=['GET'])
def nuclei_template_trust_get_endpoint():
    return jsonify({
        'path': str(trust_config_path()),
        'config': load_template_trust().to_dict(),
    })


@app.route('/api/integrations/nuclei/trust', methods=['POST'])
def nuclei_template_trust_save_endpoint():
    payload = request.get_json(silent=True) or {}
    config = save_template_trust(payload.get('config') or payload)
    return jsonify({
        'path': str(trust_config_path()),
        'config': config.to_dict(),
    })


@app.route('/api/integrations/nuclei/install', methods=['POST'])
def install_nuclei_endpoint():
    payload = request.get_json(silent=True) or {}
    version = str(payload.get('version') or 'latest').strip() or 'latest'
    result = NucleiAssetManager().install_or_update_engine(version=version)
    status = 200 if result.ok else 400
    return jsonify(result.to_dict()), status


@app.route('/api/integrations/nuclei/templates/update', methods=['POST'])
def update_nuclei_templates_endpoint():
    payload = request.get_json(silent=True) or {}
    result = NucleiAssetManager().update_templates(
        process_timeout=int(payload.get('process_timeout') or 180)
    )
    status = 200 if result.ok else 400
    return jsonify(result.to_dict()), status


@app.route('/api/integrations/nuclei/run', methods=['POST'])
def run_nuclei_endpoint():
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    payload = request.get_json(silent=True) or {}
    scan_id = str(payload.get('scan_id') or '').strip()
    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400
    scan_payload = repo.get_scan(scan_id)
    if not scan_payload:
        return jsonify({'error': 'Scan not found'}), 404

    targets = _targets_for_nuclei(repo, scan_id, payload, scan_payload)
    allow_intrusive = bool(payload.get('allow_intrusive') or False)
    policy_profile = str(payload.get('policy_profile') or payload.get('safety_profile') or '').strip().lower()
    if not policy_profile:
        policy_profile = 'professional' if allow_intrusive else 'safe'
    policy_acknowledged = bool(payload.get('policy_acknowledged') or payload.get('operator_acknowledged') or False)
    valid_policy, policy_error = validate_policy_acknowledgement(policy_profile, policy_acknowledged)
    if not valid_policy:
        return jsonify({'error': policy_error, 'policy_options': policy_options()}), 400
    requested_templates = _parse_list_value(payload.get('templates'))
    trust_result = apply_template_trust(
        templates=requested_templates,
        tags=_parse_list_value(payload.get('tags')),
        exclude_tags=_parse_list_value(payload.get('exclude_tags')),
    )
    if requested_templates and not trust_result['templates']:
        return jsonify({
            'error': 'All requested Nuclei template paths were blocked by the local trust policy.',
            'template_trust': trust_result,
        }), 400

    config = NucleiRunConfig(
        scan_id=scan_id,
        target_base_url=str(scan_payload.get('target_base_url') or ''),
        targets=targets,
        templates=trust_result['templates'],
        severity=_parse_list_value(payload.get('severity')) or ['critical', 'high', 'medium', 'low', 'info'],
        tags=trust_result['tags'],
        exclude_tags=trust_result['exclude_tags'],
        rate_limit=int(payload.get('rate_limit') or 5),
        timeout=int(payload.get('timeout') or 5),
        retries=int(payload.get('retries') or 0),
        process_timeout=int(payload.get('process_timeout') or 120),
        safe_templates_only=policy_profile == 'safe' and not allow_intrusive,
        nuclei_binary=str(payload.get('nuclei_binary') or ''),
        policy_profile=policy_profile,
        policy_acknowledged=policy_acknowledged,
    )

    adapter = NucleiAdapter(binary=config.nuclei_binary)
    result = adapter.run(config)
    if not result.available:
        return jsonify(result.to_dict()), 503
    if result.errors and result.raw_count == 0 and result.returncode not in (0, 1):
        return jsonify(result.to_dict()), 400

    for finding in result.findings:
        repo.save_finding(finding)
    for artifact in result.evidence:
        repo.save_evidence_artifact(artifact)

    active_scan = active_scans.setdefault(scan_id, {})
    result_payload = result.to_dict()
    result_payload['template_trust'] = {
        'warnings': trust_result.get('warnings', []),
        'blocked_templates': trust_result.get('blocked_templates', []),
        'config': trust_result.get('config', {}),
    }

    active_scan.setdefault('nuclei_runs', []).append(result_payload)
    active_scan['nuclei_summary'] = {
        'raw_count': result.raw_count,
        'findings': len(result.findings),
        'errors': len(result.errors),
        'targets': len(result.targets),
        'policy_profile': config.policy_profile,
    }
    existing = active_scan.setdefault('canonical_findings', [])
    existing.extend([finding.to_dict() for finding in result.findings])
    active_scan['total_vulnerabilities'] = len(existing) or active_scan.get('total_vulnerabilities', 0)
    _refresh_scan_artifacts(scan_id)

    return jsonify(result_payload)


@app.route('/api/intel/cve/enrich', methods=['POST'])
def enrich_cve_intel_endpoint():
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    payload = request.get_json(silent=True) or {}
    scan_id = str(payload.get('scan_id') or '').strip()
    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400
    scan_payload = repo.get_scan(scan_id)
    if not scan_payload:
        return jsonify({'error': 'Scan not found'}), 404

    finding_ids = set(_parse_list_value(payload.get('finding_ids')))
    raw_findings = []
    if finding_ids:
        for finding_id in finding_ids:
            finding = repo.get_finding(finding_id)
            if finding:
                raw_findings.append(finding)
    else:
        raw_findings = repo.list_findings(scan_id, {})
    findings = []
    for raw_finding in raw_findings:
        try:
            findings.append(finding_from_dict(raw_finding))
        except Exception:
            continue

    summary = enrich_findings(findings)
    for finding in findings:
        repo.update_finding(finding)

    active_scan = active_scans.setdefault(scan_id, {})
    active_scan['cve_intel_summary'] = {
        'cve_count': summary.get('cve_count', 0),
        'updated_findings': summary.get('updated_findings', 0),
        'kev_count': summary.get('kev_count', 0),
    }
    if not finding_ids:
        active_scan['canonical_findings'] = [finding.to_dict() for finding in findings]
    _refresh_scan_artifacts(scan_id)
    return jsonify({
        'scan_id': scan_id,
        **summary,
    })


@app.route('/api/authz/matrix/run', methods=['POST'])
def run_authorization_matrix_endpoint():
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    payload = request.get_json(silent=True) or {}
    scan_id = str(payload.get('scan_id') or '').strip()
    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400
    scan_payload = repo.get_scan(scan_id)
    if not scan_payload:
        return jsonify({'error': 'Scan not found'}), 404

    raw_profiles = payload.get('auth_profiles') or payload.get('profiles') or []
    if not isinstance(raw_profiles, list) or len(raw_profiles) < 2:
        return jsonify({'error': 'Provide at least two auth_profiles for matrix comparison'}), 400

    target_base_url = str(scan_payload.get('target_base_url') or payload.get('target_base_url') or '')
    auth_profiles = []
    try:
        for index, raw_profile in enumerate(raw_profiles):
            if not isinstance(raw_profile, dict):
                raise ValueError('Each auth profile must be an object')
            profile = build_auth_profile_from_config(
                raw_profile,
                base_url=target_base_url,
                default_name=f"matrix-role-{index + 1}",
            )
            auth_profiles.append(profile)
            repo.save_auth_profile(profile)

        result = run_authorization_matrix(
            repository=repo,
            scan_id=scan_id,
            auth_profiles=auth_profiles,
            request_ids=list(payload.get('request_ids') or []),
            max_requests=int(payload.get('max_requests') or 20),
            timeout=int(payload.get('timeout') or 10),
            safety_mode=str(payload.get('safety_mode') or scan_payload.get('safety_mode') or 'safe'),
            allow_state_changing=bool(payload.get('allow_state_changing') or False),
        )
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400

    active_scans.setdefault(scan_id, {}).setdefault('authz_matrix_runs', []).append(result.to_dict())
    return jsonify(result.to_dict())


@app.route('/api/proof/<finding_id>/task', methods=['POST'])
def create_proof_task_endpoint(finding_id):
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    finding_payload = repo.get_finding(finding_id)
    if not finding_payload:
        return jsonify({'error': 'Finding not found'}), 404
    payload = request.get_json(silent=True) or {}
    try:
        finding = Finding(**finding_payload)
        task = create_proof_task(
            finding,
            safety_mode=str(payload.get('safety_mode') or 'safe'),
            max_attempts=int(payload.get('max_attempts') or 1),
            requires_human_approval=bool(payload.get('requires_human_approval') or False),
        )
        repo.save_proof_task(task)
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'task': task.to_dict()})


@app.route('/api/proof/tasks', methods=['GET'])
def list_proof_tasks_endpoint():
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    finding_id = str(request.args.get('finding_id') or '').strip()
    tasks = repo.list_proof_tasks(finding_id=finding_id)
    return jsonify({
        'finding_id': finding_id,
        'count': len(tasks),
        'tasks': tasks,
    })


@app.route('/api/proof/<task_id>/run', methods=['POST'])
def run_proof_task_endpoint(task_id):
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    task_payload = repo.get_proof_task(task_id)
    if not task_payload:
        return jsonify({'error': 'Proof task not found'}), 404
    try:
        task = ProofTask(**task_payload)
        finding_payload = repo.get_finding(task.finding_id)
        if not finding_payload:
            return jsonify({'error': 'Finding not found'}), 404
        finding = Finding(**finding_payload)
        scan_payload = repo.get_scan(finding.scan_id) if finding.scan_id else None
        scan_config = ScanConfig(**scan_payload) if scan_payload else None
        technique_id = task.allowed_techniques[0] if task.allowed_techniques else ''
        executor = default_registry().get(technique_id)
        if not executor:
            return jsonify({'error': 'No deterministic proof executor is available for this task'}), 400
        result = run_proof_coroutine(executor.execute(task, ProofContext(
            finding=finding,
            scan_config=scan_config,
            repository=repo,
        )))
        persist_proof_result(repo, finding=finding, task=task, result=result)
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'result': result.to_dict()})


@app.route('/api/evidence/artifacts', methods=['GET'])
def list_evidence_artifacts_endpoint():
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    finding_id = str(request.args.get('finding_id') or '').strip()
    task_id = str(request.args.get('task_id') or '').strip()
    artifacts = repo.list_evidence_artifacts(finding_id=finding_id, task_id=task_id)
    return jsonify({
        'finding_id': finding_id,
        'task_id': task_id,
        'count': len(artifacts),
        'artifacts': artifacts,
    })


@app.route('/api/manual/save-request', methods=['POST'])
def manual_save_request():
    payload = request.get_json(silent=True) or {}
    method = str(payload.get('method') or 'GET').upper()
    url = str(payload.get('url') or '').strip()
    headers = payload.get('headers') or {}
    body = payload.get('body') or ''
    scan_id = str(payload.get('scan_id') or '').strip()
    auth_role = str(payload.get('auth_role') or 'manual')

    if method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}:
        return jsonify({'error': 'Unsupported HTTP method'}), 400
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return jsonify({'error': 'Manual save requires an absolute http(s) URL'}), 400
    if not isinstance(headers, dict):
        return jsonify({'error': 'headers must be an object'}), 400

    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503

    if not scan_id:
        scan_id = f"manual_{uuid.uuid4().hex[:10]}"
        repo.create_scan(ScanConfig(
            scan_id=scan_id,
            target_base_url=f"{parsed.scheme}://{parsed.netloc}",
            scope=[f"{parsed.scheme}://{parsed.netloc}"],
            safety_mode='safe',
            output_dir=REPORTS_DIR,
        ))

    request_record = RequestRecord.create(
        scan_id=scan_id,
        source='manual',
        method=method,
        url=url,
        headers=headers,
        body=body,
        auth_role=auth_role,
    )
    repo.save_request(request_record)
    return jsonify({
        'scan_id': scan_id,
        'request': request_record.to_dict(),
        'saved': True,
    })


@app.route('/api/manual/passive/<scan_id>/run', methods=['POST'])
def manual_passive_run(scan_id):
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    if not repo.get_scan(scan_id):
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(run_passive_checks(repo, scan_id))


@app.route('/api/manual/replay', methods=['POST'])
def manual_replay_request():
    payload = request.get_json(silent=True) or {}
    method = str(payload.get('method') or 'GET').upper()
    url = str(payload.get('url') or '').strip()
    headers = payload.get('headers') or {}
    body = payload.get('body') or ''
    scan_id = str(payload.get('scan_id') or '').strip()
    auth_role = str(payload.get('auth_role') or 'manual')
    safety_mode = str(payload.get('safety_mode') or 'safe').lower()
    allow_state_change = bool(payload.get('allow_state_change'))
    source = str(payload.get('source') or 'manual').strip().lower()

    if method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}:
        return jsonify({'error': 'Unsupported HTTP method'}), 400
    if source not in {'manual', 'replay', 'fuzzer', 'proof'}:
        return jsonify({'error': 'Unsupported manual replay source'}), 400
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return jsonify({'error': 'Manual replay requires an absolute http(s) URL'}), 400
    if safety_mode == 'safe' and method in {'PUT', 'PATCH', 'DELETE'} and not allow_state_change:
        return jsonify({'error': 'Safe mode blocks PUT, PATCH, and DELETE unless allow_state_change is true'}), 400
    if not isinstance(headers, dict):
        return jsonify({'error': 'headers must be an object'}), 400

    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503

    if not scan_id:
        scan_id = f"manual_{uuid.uuid4().hex[:10]}"
        repo.create_scan(ScanConfig(
            scan_id=scan_id,
            target_base_url=f"{parsed.scheme}://{parsed.netloc}",
            scope=[f"{parsed.scheme}://{parsed.netloc}"],
            safety_mode=safety_mode if safety_mode in {'safe', 'intrusive', 'lab'} else 'safe',
            output_dir=REPORTS_DIR,
        ))

    request_record = RequestRecord.create(
        scan_id=scan_id,
        source=source,
        method=method,
        url=url,
        headers=headers,
        body=body,
        auth_role=auth_role,
    )
    repo.save_request(request_record)

    start = time.time()
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            data=body if method not in {'GET', 'HEAD'} else None,
            timeout=max(1, min(int(payload.get('timeout') or 10), 30)),
            allow_redirects=False,
            verify=False,
        )
    except requests.RequestException as exc:
        return jsonify({
            'scan_id': scan_id,
            'request': request_record.to_dict(),
            'error': str(exc),
        }), 502

    response_record = ResponseRecord.create(
        request_id=request_record.request_id,
        status_code=response.status_code,
        headers=dict(response.headers),
        body=response.text,
        response_time_ms=int((time.time() - start) * 1000),
    )
    repo.save_response(response_record)

    return jsonify({
        'scan_id': scan_id,
        'request': request_record.to_dict(),
        'response': response_record.to_dict(),
    })


@app.route('/api/manual/proxy/start', methods=['POST'])
def manual_proxy_start():
    payload = request.get_json(silent=True) or {}
    repo = _storage_repo()
    if repo is None:
        return jsonify({'error': 'Corpus storage unavailable'}), 503
    try:
        config = ProxyConfig(
            host=str(payload.get('host') or '127.0.0.1'),
            port=int(payload.get('port') or 0),
            scan_id=str(payload.get('scan_id') or '').strip(),
            target_base_url=str(payload.get('target_base_url') or '').strip(),
            scope=[str(item).strip() for item in (payload.get('scope') or []) if str(item).strip()],
            excluded_hosts=[str(item).strip() for item in (payload.get('excluded_hosts') or []) if str(item).strip()],
            auth_role=str(payload.get('auth_role') or 'manual'),
            intercept_enabled=bool(payload.get('intercept_enabled') or payload.get('intercept')),
            intercept_timeout_sec=float(payload.get('intercept_timeout_sec') or 30),
            request_timeout_sec=float(payload.get('request_timeout_sec') or 20),
        )
        status = manual_proxy.start(repo, config)
    except RuntimeError as exc:
        return jsonify({'error': str(exc), 'status': manual_proxy.status()}), 409
    except (TypeError, ValueError) as exc:
        return jsonify({'error': f'Invalid proxy configuration: {exc}'}), 400
    return jsonify(status)


@app.route('/api/manual/proxy/stop', methods=['POST'])
def manual_proxy_stop():
    return jsonify(manual_proxy.stop())


@app.route('/api/manual/proxy/status', methods=['GET'])
def manual_proxy_status():
    return jsonify(manual_proxy.status())


@app.route('/api/manual/proxy/intercept', methods=['POST'])
def manual_proxy_intercept():
    payload = request.get_json(silent=True) or {}
    return jsonify(manual_proxy.set_intercept(bool(payload.get('enabled'))))


@app.route('/api/manual/proxy/pending', methods=['GET'])
def manual_proxy_pending():
    pending = manual_proxy.list_pending()
    return jsonify({
        'count': len(pending),
        'requests': pending,
    })


@app.route('/api/manual/proxy/pending/<request_id>', methods=['POST'])
def manual_proxy_decide(request_id):
    payload = request.get_json(silent=True) or {}
    action = str(payload.get('action') or '').lower()
    updates = payload.get('request') if isinstance(payload.get('request'), dict) else None
    try:
        found = manual_proxy.decide(request_id, action, updates)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    if not found:
        return jsonify({'error': 'Pending proxy request not found'}), 404
    return jsonify({'request_id': request_id, 'action': action})


@app.route('/api/manual/browser/open', methods=['POST'])
def manual_browser_open():
    payload = request.get_json(silent=True) or {}
    result = wraith_browser.open(
        target_url=str(payload.get('target_url') or payload.get('url') or '').strip(),
        scan_id=str(payload.get('scan_id') or manual_proxy.status().get('scan_id') or '').strip(),
        use_proxy=payload.get('use_proxy', True) is not False,
        proxy_status=manual_proxy.status(),
    )
    status = 200 if result.ok else 409
    if result.error and 'Playwright is unavailable' in result.error:
        status = 503
    return jsonify(result.to_dict()), status


@app.route('/api/manual/browser/status', methods=['GET'])
def manual_browser_status():
    return jsonify(wraith_browser.status().to_dict())


@app.route('/api/manual/browser/close', methods=['POST'])
def manual_browser_close():
    return jsonify(wraith_browser.close().to_dict())


@app.route('/api/mode', methods=['GET'])
def get_mode():
    mode_mgr = get_mode_manager()
    return jsonify({'current_mode': mode_mgr.current_mode, 'config': mode_mgr.get_mode_config()})


@socketio.on('connect')
def handle_connect():
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


if __name__ == '__main__':
    debug_enabled = os.environ.get("SCANNER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    host = os.environ.get("SCANNER_HOST", "0.0.0.0")
    port = int(os.environ.get("SCANNER_PORT", "5001"))

    print("=" * 60)
    print("Vulnerability Scanner API Server v4.0")
    print("=" * 60)
    print(f"Server:   http://localhost:{port}")
    print("SAST:     Semgrep + Cross-File Taint + Secrets/Deps")
    print("Scanners: SQLi, XSS (reflected+stored+DOM), IDOR, CSRF,")
    print("          CMDi, Path Traversal, Open Redirect, SSRF (OOB),")
    print("          XXE, SSTI, Headers, Components, WordPress")
    print("Upgrades: Adaptive payload mutation, Deep-state SPA, OOB mapping")
    print(f"Debug:    {'enabled' if debug_enabled else 'disabled'}")
    print("=" * 60)
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug_enabled,
        use_reloader=debug_enabled,
        allow_unsafe_werkzeug=True,
    )
