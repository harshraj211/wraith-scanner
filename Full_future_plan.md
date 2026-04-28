# Wraith Future Plan: Desktop Browser, Manual Proxy, Enterprise UI, and Scanner Depth

Date: 2026-04-27

This file replaces the older long-form benchmark plan. The new direction is more product-specific: Wraith should become a clean professional VA + Proof platform with a web UI, optional desktop `.exe`, controlled browser, request capture, manual testing tools, strong reporting, and deeper scanner coverage.

The product thesis stays:

> Wraith finds modern web vulnerabilities, safely proves high-confidence issues, links runtime evidence to source-code context, and produces report-ready artifacts that a professional can defend.

## Important Safety Boundary

Wraith is for authorized testing. We should not build destructive exploitation, malware, credential theft, uncontrolled payload generation, persistence, lateral movement, or data exfiltration.

For WAF and firewall handling, the goal is:

- Detect blocking behavior.
- Measure coverage loss.
- Retry with bounded, non-destructive payload variants.
- Clearly label blocked, inconclusive, and confirmed results.
- Let operators import custom payloads for authorized engagements.

The goal is not "bypass any firewall at any cost." That creates legal, safety, and false-positive problems. The safe product phrase should be **WAF-aware validation**, not unlimited evasion.

---

# 1. Immediate UI Cleanup

## Problem

The current frontend is still visually cramped in automated mode. The screenshot shows:

- Too much content visible at once.
- Nested panels competing for space.
- Vertical scrollbars inside several panels.
- Heavy font weight everywhere.
- The setup form, dashboard, progress, and report strip all fighting for the first viewport.
- It looks closer to a debug console than a polished enterprise product.

## Direction

Make the Wraith web UI quieter and more like Burp Suite Enterprise:

- Light enterprise shell.
- Left scan list.
- Top workspace header.
- Scan metadata bar.
- Tabs for `Overview`, `Issues`, `Scanned URLs`, `Scan Details`, `Reporting & Logs`.
- Only one primary content mode per tab.
- No giant nested dashboard plus setup form in the same viewport.
- Better spacing, smaller typography, fewer heavy borders.

## Implementation Steps

1. Introduce frontend tab state instead of anchor-only sections:
   - `automatedTab = overview | issues | urls | details | reporting`
   - `manualTab = proxy | repeater | intruder | decoder | logger | reporting`

2. Automated mode layout:
   - Left: scan list and filters.
   - Top: title, status, actions.
   - Main tab: only current tab content.
   - Move setup form into `Scan Details`.
   - Move terminal/log events into `Reporting & Logs`.
   - Keep overview focused on charts and summary cards.

3. Manual mode layout:
   - Left: captured request history.
   - Main: tabbed tools.
   - Right: inspector/evidence drawer only when needed.

4. Design system:
   - Font: `Inter`, fallback system UI.
   - Base font size: 14px.
   - Headings: 20-24px in app shell, not hero-scale.
   - Border radius: 4-6px.
   - Colors:
     - background: `#f5f7fb`
     - panels: `#ffffff`
     - border: `#dfe6ef`
     - primary blue: `#1f93ff`
     - high severity: `#ef3e5c`
     - medium: `#ff7043`
     - low: `#1f93ff`
     - info: `#7a8796`

---

# 2. Web UI vs Desktop `.exe`

## Recommended Product Shape

Use a two-part product:

1. **Wraith Web Console**
   - Runs in browser.
   - Good for dashboards, scan setup, report review, CI artifacts, team/server mode.

2. **Wraith Desktop Agent**
   - Windows `.exe`.
   - Bundles or controls local backend services.
   - Opens the Wraith controlled browser.
   - Runs the local proxy capture engine.
   - Handles CA certificate setup and local artifacts.

Do not make the public website auto-download an `.exe` immediately when the user clicks Start Scan. That feels suspicious and will trigger browser/AV distrust. Better flow:

- User clicks `Start Scan`.
- They choose:
  - `Use Web Console`
  - `Download Desktop Agent`
- Desktop agent download page explains what the agent does:
  - local proxy
  - controlled browser
  - request capture
  - safe proof execution
  - local storage

## Packaging Options

Recommended first choice: **Tauri**

- Smaller `.exe`.
- Rust shell with web frontend.
- Can launch Python backend sidecar.
- Better security posture than Electron.

Alternative: **Electron**

- Easier to bundle Chromium.
- Easier to build a "browser-like" shell.
- Larger app.

Recommended staged approach:

1. Keep React web console as-is.
2. Add desktop packaging with Tauri.
3. Launch controlled Chromium via Playwright from backend.
4. Later, if you want a fully embedded browser UI, evaluate Electron.

---

# 3. Wraith Controlled Browser

## Goal

Manual mode should open a Wraith-controlled browser where every request can be captured, correlated, replayed, fuzzed, decoded, and attached to evidence.

## Architecture

```text
Wraith Desktop Agent
  |
  +-- React UI
  +-- Flask/FastAPI backend
  +-- Local proxy service
  +-- Playwright/Chromium controlled browser
  +-- SQLite corpus
  +-- Evidence artifact store
```

## Controlled Browser Flow

1. User opens Manual Scan.
2. Wraith starts local proxy:
   - default `127.0.0.1:8088`
3. Wraith launches Chromium with:
   - proxy set to `127.0.0.1:8088`
   - isolated user data directory
   - optional test CA installed/trusted for this browser profile
4. User browses target app inside Wraith browser.
5. Proxy records requests/responses to corpus.
6. UI shows captured history in real time.
7. User sends requests to:
   - Repeater
   - Intruder
   - Decoder
   - Proof task
   - Report evidence

## Backend Libraries

Recommended:

- `mitmproxy` for HTTP/HTTPS interception.
- `playwright` for controlled Chromium.
- `websockets` or Socket.IO for live request feed.
- SQLite now, Postgres later.

Why `mitmproxy`:

- Mature interception.
- HTTPS support.
- Addon API.
- Request/response hooks.
- Can save flows.

## Required Proxy Features

Phase 1:

- Start/stop proxy.
- Capture HTTP/HTTPS request metadata.
- Save request/response to corpus.
- Stream capture events to UI.
- Scope allowlist.
- Excluded hosts.
- Sensitive header redaction.

Phase 2:

- Pause/forward/drop.
- Modify request before forwarding.
- Modify response before returning.
- Match/replace rules.
- WebSocket frame capture.
- Export selected flows as HAR.

Phase 3:

- HTTP/2 support verification.
- TLS certificate management UI.
- Browser profile manager.
- Per-target proxy profiles.

---

# 4. Manual Tools

## 4.1 Proxy History

Features:

- Live request table.
- Method, host, path, status, MIME, length, time, source, role.
- Search/filter:
  - host
  - path
  - status
  - MIME
  - method
  - has parameters
  - has finding
  - in scope
- Request/response split view.
- Pretty views:
  - raw
  - headers
  - params
  - cookies
  - JSON
  - XML
  - HTML

## 4.2 Repeater

Current backend already has `POST /api/manual/replay`. Expand it into real Repeater:

- Send selected captured request to Repeater.
- Multiple tabs.
- Editable method, URL, headers, body.
- Auth profile injection.
- Response diff against baseline.
- Save replayed exchange to corpus.
- Add to report evidence.

Backend endpoint direction:

- Keep `POST /api/manual/replay`.
- Add request tab persistence:
  - `POST /api/manual/repeater/tabs`
  - `PUT /api/manual/repeater/tabs/<tab_id>`
  - `POST /api/manual/repeater/tabs/<tab_id>/send`

## 4.3 Intruder

Build a bounded, safe Intruder-style fuzzer.

Modes:

- Sniper: one insertion point at a time.
- Pitchfork: multiple payload lists move together.
- Cluster bomb: all combinations, with hard caps.

Safety:

- Global max requests.
- Per-host rate limit.
- Stop on 429/403 spike.
- Stop on 5xx spike.
- Safe mode blocks destructive verbs unless explicitly allowed.

Analysis:

- Status code clustering.
- Response length clustering.
- Title clustering.
- JSON shape hash.
- DOM hash.
- Timing buckets.
- Interesting diff markers.

## 4.4 Decoder

Add a powerful Decoder tab.

Supported transforms:

- URL encode/decode.
- HTML entity encode/decode.
- Base64 encode/decode.
- Base64URL encode/decode.
- Hex encode/decode.
- Unicode escape encode/decode.
- JWT decode.
- JSON beautify/minify.
- XML beautify.
- Gzip/deflate if bytes are available.
- Hash:
  - MD5
  - SHA1
  - SHA256
  - SHA512
- HMAC helper when user supplies a key.

Safety:

- Never auto-submit decoded secrets anywhere.
- Redact tokens in logs.

Implementation:

- Most transforms can be pure frontend JavaScript.
- JWT decode should not verify by default; show `unverified decode`.
- Optional backend crypto endpoint for HMAC/advanced binary handling.

## 4.5 Comparer

Add request/response comparer:

- Raw text diff.
- Header diff.
- JSON semantic diff.
- Response timing comparison.
- Highlight changed auth/user/object fields.

Useful libraries:

- frontend: `diff`, `jsondiffpatch`, or custom minimal diff.
- backend: `deepdiff`.

---

# 5. Automated Scan Experience

Automated mode should feel like Burp Enterprise scan detail pages.

## Tabs

1. Overview
   - KPI cards.
   - Issues by severity.
   - Severity trend.
   - Scanned URL donut.
   - Most serious vulnerabilities.

2. Issues
   - Finding table.
   - Severity, confidence, proof status, endpoint, parameter, role.
   - Click opens finding drawer.
   - Evidence, remediation, references.

3. Scanned URLs
   - URL table from corpus.
   - Status, source, MIME, response time.
   - Link to request/response.

4. Scan Details
   - Target.
   - Auth profiles.
   - Imports.
   - Sequence workflows.
   - Modules.
   - Safety mode.

5. Reporting & Logs
   - PDF download.
   - JSON download.
   - SARIF later.
   - JUnit later.
   - Evidence zip later.
   - Progress events.
   - Errors/warnings.

## What to Build Next

Immediate:

- Move current setup form out of Overview into Scan Details.
- Make Overview only charts and summary.
- Add Issues table.
- Add Scanned URLs table using corpus endpoint.
- Add report card with PDF/JSON download buttons.

---

# 6. PDF Reporting Roadmap

Current PDF exists, but it needs to feel like a professional pentest deliverable.

## Add Sections

- Cover page.
- Scope and rules of engagement.
- Executive summary.
- Methodology.
- Auth roles tested.
- Coverage metrics.
- Issues summary.
- Detailed findings.
- Discovery evidence.
- Proof evidence.
- Request/response excerpts.
- Screenshots.
- OOB callbacks.
- Remediation plan.
- Retest steps.
- Appendix.

## Implementation Direction

Move from direct ReportLab composition to:

- Jinja2 HTML templates.
- Playwright `page.pdf()` rendering.
- CSS designed specifically for reports.

Outputs:

- `report.html`
- `report.pdf`
- `wraith.json`
- `wraith.sarif`
- `junit.xml`
- `evidence.zip`

---

# 7. Scanner Module Expansion

## DAST Additions

High value:

- Authorization Matrix / BOLA role-diff engine.
  - v1 implemented direction: replay existing object-specific corpus requests under supplied `user_a`, `user_b`, `anonymous`, or `admin` profiles.
  - Safe mode sends only read-only requests, refuses out-of-scope URLs, stores source `authz` traffic, and emits sanitized diff evidence.
  - Next step: integrate disposable test-resource creation and sequence-workflow setup before enabling state-changing authorization checks.
- JWT weakness checks.
- CORS deeper checks.
- Cache poisoning checks.
- HTTP request smuggling indicators.
- Host header injection.
- Prototype pollution.
- NoSQL injection.
- LDAP injection.
- OAuth/OIDC misconfiguration.
- File upload validation.
- Mass assignment.
- Rate-limit and brute-force protection checks.
- GraphQL auth/BOLA checks.
- WebSocket auth and message fuzzing.
- API schema drift checks.

Medium value:

- CRLF injection.
- Clickjacking/frame checks.
- Subdomain takeover checks.
- CSP bypass hints.
- Session fixation.
- Insecure cookie scope/domain/path.

## SAST Additions

Languages:

- TypeScript.
- Java.
- PHP.
- Go.

Framework route extraction:

- Flask.
- Django.
- FastAPI.
- Express.
- Next.js.
- React Router.
- Spring Boot.
- Laravel.

Source/runtime correlation:

- Map DAST endpoint to source route.
- Map SAST sink to DAST finding.
- Show source trace in finding drawer.

---

# 8. CVE Coverage Expansion

## Do Not Try To Manually Rebuild Nuclei

Nuclei already has huge community coverage. Wraith should integrate it.

## Implementation

Add a `NucleiAdapter`:

- Run Nuclei against discovered hosts/endpoints. **Implemented v1:** Wraith can run local Nuclei against explicit targets or persisted corpus URLs.
- Support template path configuration. **Implemented v1:** API and frontend accept template files/directories.
- Managed desktop/web asset updates. **Implemented v1:** status, engine install/update, and template update endpoints plus Automated Workspace controls.
- Support private template repositories.
- Pin template version/hash in reports.
- Import Nuclei results into Wraith canonical `Finding`. **Implemented v1:** JSONL matches are converted to canonical findings and evidence artifacts.
- De-duplicate against Wraith native findings.
- Keep safe defaults. **Implemented v1:** rate/process limits are bounded and unsafe template tags are excluded unless explicitly enabled.

Add CVE intelligence:

- OSV for dependencies.
- NVD API for CVE metadata. **Implemented v1:** CVE-backed findings can be enriched from the NVD CVE 2.0 API.
- EPSS score for exploit likelihood. **Implemented v1:** FIRST EPSS scores and percentiles are added to finding metadata.
- CISA KEV flag. **Implemented v1:** CISA Known Exploited Vulnerabilities catalog matches are added to finding metadata.
- Known exploited in the wild flag.

Prioritization score:

```text
risk = severity + confidence + exploit_maturity + asset_exposure + proof_status + KEV/EPSS boost
```

---

# 9. WAF-Aware Validation

## Goals

- Detect blocking and degraded coverage.
- Avoid noisy false positives.
- Retry bounded safe variants.
- Explain blocked/inconclusive findings.

## Features

- WAF fingerprinting:
  - status code shifts
  - block page similarity
  - header markers
  - CDN/WAF vendor hints
  - timing behavior

- Payload mutation:
  - encoding variants
  - case variation
  - safe whitespace/comment variants
  - context-aware quoting
  - JSON/XML/form-specific formatting

- Circuit breakers:
  - repeated 403
  - repeated 429
  - 5xx spike
  - latency spike
  - session invalidation

## Safety Rule

No unlimited firewall bypass mode. Use bounded, logged, operator-approved payload catalogs.

---

# 10. Desktop Installer Plan

## Windows `.exe`

Recommended build path:

1. Package Python backend:
   - PyInstaller.
2. Package frontend:
   - React build assets.
3. Desktop shell:
   - Tauri first.
4. Installer:
   - WiX Toolset or NSIS.

Desktop app starts:

- Local backend.
- React UI.
- Proxy service.
- Controlled browser launcher.

## Installer UX

- Explain local services.
- Ask before installing CA certificate.
- Let user choose local data directory.
- Add "Open Wraith Browser" button.
- Add "Start Proxy" button.

---

# 11. Prioritized Build Order

## Phase A: Clean Current Frontend

1. Fix spacing and layout.
2. Add tab state.
3. Move setup into Scan Details.
4. Add Issues and Scanned URLs tabs.
5. Add report downloads to Reporting tab.

## Phase B: Manual Repeater

1. Repeater tabs.
2. Save tab state.
3. Send selected corpus request to Repeater.
4. Response diff.
5. Attach replay evidence to finding.

## Phase C: Proxy Capture

1. Add mitmproxy service.
2. Start/stop proxy endpoints.
3. Capture request/response to corpus.
4. Stream capture events to UI.
5. Scope controls.

## Phase D: Controlled Browser

1. Launch Chromium with proxy.
2. Isolated browser profile.
3. Browser status in UI.
4. Open target in Wraith Browser.
5. Capture traffic automatically.

## Phase E: Decoder and Comparer

1. Frontend Decoder.
2. JWT decode.
3. Hash/HMAC helpers.
4. Response comparer.
5. Send selected request/response into Decoder/Comparer.

## Phase F: Intruder

1. Payload positions.
2. Payload lists.
3. Sniper mode.
4. Rate limits.
5. Clustering.
6. Pitchfork/cluster bomb with hard caps.

## Phase G: Reports

1. HTML report.
2. Playwright PDF rendering.
3. Evidence zip.
4. SARIF.
5. JUnit.

## Phase H: CVE and Nuclei

1. Nuclei adapter. **V1 implemented:** backend adapter, API endpoint, frontend Automated Workspace panel, canonical finding import, and evidence persistence.
2. Template management. **V1 implemented:** managed status/install/update endpoints and UI controls for engine and template updates.
3. CVE enrichment.
4. EPSS/KEV prioritization.

## Phase I: Desktop `.exe`

1. Tauri shell.
2. Backend sidecar.
3. Proxy/browser service.
4. Installer.
5. Code signing later.

---

# 12. What We Should Build First

Start with **Phase A + Phase B**.

Reason:

- Fixes the messy UI immediately.
- Makes Manual mode useful before building full proxy.
- Reuses existing corpus and `/api/manual/replay`.
- Gives a stable foundation for Intruder, Decoder, and controlled browser.

After that, build proxy capture and controlled browser.
