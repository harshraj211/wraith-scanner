# Wraith v4

Async DAST and SAST scanner for modern web applications, SPAs, and GitHub repositories.

Wraith now ships with four major engine upgrades:

- Intelligent payload mutation for noisy DAST responses like WAF block pages, `403`s, and `5xx` responses.
- Cross-file taint analysis for SAST, layered on top of Semgrep and the existing secrets and dependency scanner.
- Deep-state SPA exploration that mutates browser storage and walks multi-step flows before fuzzing.
- Richer OOB profiling for blind SSRF-style callbacks with per-parameter correlation and egress hints.

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

The terminal UI opens on `http://127.0.0.1:3000`.

### CLI

```bash
python main.py --url http://127.0.0.1:5000 --output reports/local.pdf
```

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
python -m unittest
```

Focused upgrade regression tests live in:

- `tests/test_advanced_engine_upgrades.py`
- `tests/test_startup_smoke.py`

## Notes

- The React terminal keeps the original terminal-style UX and now exposes deep-state, mutation, taint, and OOB status summaries.
- PDF reports include the merged findings from DAST, Semgrep, taint analysis, and secrets or dependency scanning.
- The repo may contain local artifacts like `reports/` or `test.db`; Wraith does not require them for installation.

## Responsible Use

Scan only systems you own or are explicitly authorized to assess.
