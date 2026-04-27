# Wraith v4

Async DAST and SAST scanner for modern web applications, SPAs, and GitHub repositories.

Wraith now ships with four major engine upgrades plus the first VA+Proof platform groundwork:

- Intelligent payload mutation for noisy DAST responses like WAF block pages, `403`s, and `5xx` responses.
- Cross-file taint analysis for SAST, layered on top of Semgrep and the existing secrets and dependency scanner.
- Deep-state SPA exploration that mutates browser storage and walks multi-step flows before fuzzing.
- Richer OOB profiling for blind SSRF-style callbacks with per-parameter correlation and egress hints.
- Canonical scan schemas, stable finding IDs, redaction, JSON exports, and a durable SQLite request/response corpus.

## What It Scans

### DAST

- SQL injection
- Reflected, DOM, and stored XSS
- SSRF with in-band and OOB confirmation
- XXE
- SSTI
- Command injection
- Path traversal
- IDOR
- Open redirect
- CSRF
- Headers and crypto misconfigurations
- GraphQL and WebSocket surfaces
- WordPress-specific checks

### SAST

- Semgrep AST findings
- Cross-file taint findings from route or request source to dangerous sink
- Hardcoded secrets and credential patterns
- Dependency CVEs through OSV-backed manifest parsing
- Common misconfiguration patterns

## Architecture

```text
React Terminal UI
        |
        v
Flask API Server  --->  PDF Reporting
        |
        +--> WebCrawler + Playwright
        |      |
        |      +--> Deep-state storage mutation
        |      +--> SPA/API/WebSocket discovery
        |      +--> OpenAPI/Postman/HAR/GraphQL imports
        |
        +--> AsyncScanEngine
        |      |
        |      +--> DAST modules
        |      +--> Adaptive response intelligence
        |      +--> OOB correlation
        |
        +--> Repo SAST
               |
               +--> Semgrep
               +--> Cross-file taint analyzer
               +--> Secrets/dependency scanner
```

## Install

### Requirements

- Python 3.9+
- Node.js 16+
- Git
- Chromium for Playwright

### Python dependencies

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
```

### Frontend dependencies

```bash
cd scanner-terminal
npm install
cd ..
```

## Optional Integrations

- `semgrep`: recommended for the full SAST experience. Without it, Wraith still runs taint, secret, and dependency analysis.
- `OPENAI_API_KEY`: enables optional LLM-assisted payload mutation in the response-intelligence layer. Without it, Wraith uses the built-in heuristic mutator.
- `WRAITH_DB_PATH`: optional path for the local SQLite corpus database. Defaults to `reports/wraith.sqlite3`.

## Run

### Backend API

```bash
python api_server.py
```

The API listens on `http://127.0.0.1:5001`.

### Frontend terminal

```bash
cd scanner-terminal
npm start
```

The Wraith website opens on `http://127.0.0.1:3000`. It starts with a product home page, then lets you choose Automated Scan or Manual Scan. Automated mode uses a Burp Enterprise-inspired scan workspace with a scan list, status strip, tabs, visual dashboards, corpus, terminal, and PDF/JSON report actions. Manual mode provides HTTP proxy capture, request history, a Repeater-style editor, response inspector, Decoder, reporting actions, and terminal panel.

### CLI

```bash
python main.py --url http://127.0.0.1:5000 --output reports/local.pdf
```

Canonical JSON output is also supported:

```bash
python main.py --url http://127.0.0.1:5000 --output reports/local.json
```

The JSON export uses schema `wraith.scan.v1` and includes the scan config, coverage, canonical findings, stable finding IDs, CVSS/CWE/OWASP fields, proof status, and redacted evidence.

### API Imports

Wraith can seed scans from API descriptions and captured traffic. Imported requests are normalized into `RequestCandidate` objects, saved to the SQLite corpus with source `import`, and merged into the existing URL/form scan pipeline.

```bash
python main.py --url https://app.example.test --import-openapi openapi.json --output reports/api.json
python main.py --url https://app.example.test --import-postman collection.json --import-har traffic.har
python main.py --url https://app.example.test --import-graphql schema.json
```

Supported importer inputs:

- OpenAPI 3.x / Swagger 2 JSON. YAML works when PyYAML is installed.
- Postman collection v2.1 JSON.
- HAR files exported from browser/devtools traffic.
- GraphQL introspection JSON or SDL files.

The Flask API accepts the same inputs under `imports`:

```json
{
  "url": "https://app.example.test",
  "imports": {
    "openapi": ["openapi.json"],
    "postman": ["collection.json"],
    "har": ["traffic.har"],
    "graphql": [{"path": "schema.json", "endpoint_url": "https://app.example.test/graphql"}]
  }
}
```

Imported candidates appear in JSON report metadata under `api_imports`. Sensitive headers from HAR traffic are redacted before corpus storage.

### API Sequence Workflows

Phase 4 adds a YAML/JSON sequence runner for API workflows that need state from earlier responses. It executes bounded HTTP steps with the active auth session, extracts variables, reuses them in later requests, runs assertions, and stores every request/response in the SQLite corpus as replay traffic.

```bash
python main.py --url https://app.example.test --sequence-workflow workflows/order-flow.yaml --output reports/sequence.json
```

Example YAML:

```yaml
name: order flow
steps:
  - name: create order
    method: POST
    url: /api/orders
    json:
      sku: demo
    extract:
      order_id:
        jsonpath: $.id
    assertions:
      - status_code: 201

  - name: read order
    method: GET
    url: /api/orders/{{order_id}}
    assertions:
      - status_code: 200
      - jsonpath: $.id
        equals: "{{order_id}}"
```

Safe mode skips `DELETE`, `PATCH`, and `PUT` steps unless the step is explicitly marked with `safe: true`, `allow_in_safe_mode: true`, `disposable: true`, or `uses_disposable_resource: true`.

API scans can pass workflows inline or by file path:

```json
{
  "url": "https://app.example.test",
  "sequence_workflows": ["workflows/order-flow.yaml"]
}
```

Sequence results appear in JSON report metadata under `sequence_workflows`.

### Auth Profiles

Wraith supports reusable auth profiles for authenticated scans:

- anonymous
- static headers
- bearer tokens
- cookies
- Playwright `storage_state` files

CLI examples:

```bash
python main.py --url http://127.0.0.1:5000 --bearer-token "$TOKEN" --auth-role user_a
python main.py --url http://127.0.0.1:5000 --auth-header "X-API-Key=secret" --auth-cookie "sessionid=value"
python main.py --url http://127.0.0.1:5000 --storage-state reports/auth_user_a_storage_state.json --auth-role user_a
```

Record a browser login without storing a password:

```bash
python main.py --url http://127.0.0.1:5000 --record-login http://127.0.0.1:5000/login --record-login-output reports/auth_user_a_storage_state.json --auth-role user_a
```

Add a session health check:

```bash
python main.py --url http://127.0.0.1:5000 --storage-state reports/auth_user_a_storage_state.json --auth-health-url http://127.0.0.1:5000/dashboard --auth-health-text Dashboard
```

API scans can pass the same fields under `auth`:

```json
{
  "url": "http://127.0.0.1:5000",
  "auth": {
    "type": "playwright_storage",
    "role": "user_a",
    "storage_state_path": "reports/auth_user_a_storage_state.json",
    "session_health_check": {
      "health_check_url": "http://127.0.0.1:5000/dashboard",
      "expected_status": 200,
      "expected_text": "Dashboard"
    }
  }
}
```

Auth profiles are saved to the local corpus with secrets redacted. Playwright storage state files are referenced by path; Wraith does not store passwords.

## Terminal Commands

- `scan <url>`
- `scan <url> --depth 3`
- `scan <url> --timeout 20`
- `scanrepo <github-url>`
- `scanrepo <github-url> --token <token>`
- `scanrepo <github-url> --branch <branch>`
- `status <scan-id>`
- `download <scan-id>`
- `help`
- `clear`

Backend API scans write `reports/scan_<scan-id>.json` beside the PDF. Download it with:

```text
GET http://127.0.0.1:5001/api/download-json/<scan-id>
```

Inspect persisted corpus traffic from the frontend Corpus panel or through the API:

```text
GET http://127.0.0.1:5001/api/corpus/<scan-id>/requests
GET http://127.0.0.1:5001/api/corpus/request/<request-id>
GET http://127.0.0.1:5001/api/corpus/<scan-id>/findings
POST http://127.0.0.1:5001/api/manual/replay
POST http://127.0.0.1:5001/api/manual/proxy/start
GET  http://127.0.0.1:5001/api/manual/proxy/status
POST http://127.0.0.1:5001/api/manual/proxy/intercept
GET  http://127.0.0.1:5001/api/manual/proxy/pending
POST http://127.0.0.1:5001/api/manual/proxy/pending/<request-id>
POST http://127.0.0.1:5001/api/manual/proxy/stop
POST http://127.0.0.1:5001/api/proof/<finding-id>/task
POST http://127.0.0.1:5001/api/proof/<task-id>/run
```

Request filters include `method`, `host`, `path_contains`, `status_code`, `content_type`, `source`, `auth_role`, `parameter_name`, and `has_finding`.
Manual replay sends a bounded operator-specified request, blocks destructive verbs in safe mode unless explicitly allowed, and stores the sanitized exchange as source `manual`.

Manual proxy capture starts a local HTTP proxy, stores captured requests/responses in the SQLite corpus as source `proxy`, and can optionally pause requests for explicit `forward`, `drop`, or edit-before-forward. This first proxy slice intentionally does not MITM HTTPS traffic; HTTPS CONNECT returns a clear unsupported response until certificate-managed interception is added.

Proof Mode is a deterministic post-scan verifier. The first executor safely proves open redirects by mutating the affected parameter to a controlled `.invalid` target, refusing out-of-scope findings, not following the redirect, storing the proof request/response as source `proof`, and linking sanitized evidence back to the finding.

## Canonical Models and Corpus

Phase 0/1 introduces stable models under `scanner.core.models`:

- `Finding`
- `RequestRecord`
- `ResponseRecord`
- `EvidenceArtifact`
- `ScanConfig`
- `AuthProfile`
- `ProofTask`

Legacy scanner dictionaries are converted into canonical `Finding` objects with deterministic IDs based on target, normalized endpoint, method, parameter, vuln type, auth role, and evidence type. This lets repeated scans deduplicate findings across changing object IDs such as `/users/123` and `/users/456`.

The local corpus is stored with SQLite through `scanner.storage.repository` and defaults to:

```text
reports/wraith.sqlite3
```

The corpus currently persists scan configs, crawler-discovered requests/forms, async DAST request/response exchanges, canonical findings, evidence artifacts, auth profiles, OOB events, and proof task records.

Secrets are redacted before storage by default, including Authorization headers, cookies, bearer tokens, JWTs, API keys, session IDs, password-like fields, and token-like URL/body values.

## New Engine Details

### Intelligent Payload Mutation

When a target reflects input but responds with a likely block page or noisy error, Wraith:

1. fingerprints the response context,
2. classifies the likely block condition,
3. generates a small batch of context-aware mutations,
4. retries only those payloads,
5. validates exploitability with sink-aware checks.

This is designed to cut false positives and avoid blasting static payload lists at every endpoint.

### Cross-File Taint Analysis

The taint analyzer walks Python and JavaScript repository code, tracks request-derived values across assignments and function calls, and reports only when tainted data reaches sinks like:

- database execution functions,
- OS command execution,
- path/file access,
- SSRF-style outbound request helpers,
- dangerous template or response sinks.

### Deep-State SPA Fuzzing

Before fuzzing a hydrated SPA, Wraith now:

- snapshots `localStorage`, `sessionStorage`, and IndexedDB samples,
- flips privileged flags and role-like values,
- advances likely wizard flows,
- re-extracts routes, forms, and privileged UI hints.

### OOB Network Mapping

Blind SSRF callbacks are now labeled per vector and parameter, then correlated into a lightweight network map with:

- callback protocol,
- callback host,
- remote address,
- request latency bucket,
- vector profile,
- inference notes.

These hints are heuristic and should be treated as supporting evidence, not ground truth infrastructure attribution.

## Safe Demo

Wraith includes a local vulnerable target under `test_app`.

### 1. Start the demo app

```bash
python test_app/vulnerable_app.py
```

### 2. Start the API

```bash
python api_server.py
```

### 3. Run a scan

```bash
python -c "import requests; print(requests.post('http://127.0.0.1:5001/api/scan', json={'url': 'http://127.0.0.1:5000'}).json())"
```

Or use the frontend terminal and run:

```text
scan http://127.0.0.1:5000
```

## Tests

```bash
python -m unittest discover -s tests
```

Focused upgrade regression tests live in:

- `tests/test_advanced_engine_upgrades.py`
- `tests/test_auth_profiles.py`
- `tests/test_canonical_storage.py`
- `tests/test_corpus_api.py`
- `tests/test_startup_smoke.py`

Wraith resolves Semgrep from common Python script locations and adds the discovered directory to child process `PATH`, which helps Windows installs where `semgrep.exe` and `pysemgrep.exe` live together outside the shell path.

## Notes

- The React workbench keeps the original terminal-style UX and now exposes scan setup, progress, API imports, sequence workflows, and a request/response corpus viewer.
- PDF reports include the merged findings from DAST, Semgrep, taint analysis, and secrets or dependency scanning.
- The repo may contain local artifacts like `reports/` or `test.db`; Wraith does not require them for installation.

## Responsible Use

Scan only systems you own or are explicitly authorized to assess.
