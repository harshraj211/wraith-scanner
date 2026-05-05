# Wraith Enterprise Upgrade Plan

Date: 2026-05-05

This roadmap turns Wraith from a strong scanner/workbench into a defendable enterprise AppSec platform. The product direction is:

> capture -> test -> prove -> report -> assign -> retest -> track

The plan is intentionally phased so each release improves real operator workflow without breaking the existing desktop, web, CLI, SQLite, and report paths.

## Phase 1: Burp-Like Manual Workbench

Goal: make Wraith useful as a daily authorized web testing console.

Priority upgrades:

1. HTTPS interception architecture
   - Local CA generation.
   - Operator-visible certificate install guide.
   - Scope allowlist and excluded hosts before interception.
   - HTTPS request/response capture.
   - WebSocket capture.
   - HAR export.
   - Clear trust and risk status page.
2. Repeater hardening
   - Better baseline selection.
   - Auth profile injection.
   - Save replay as evidence.
   - Export selected exchange.
3. Safe Intruder
   - Sniper, pitchfork, and cluster-bomb modes with hard caps.
   - Rate limits and stop conditions for 429/403/5xx spikes.
   - Response length, timing, title, and JSON-shape clustering.
4. Decoder
   - URL, HTML, Base64, Base64URL, Hex, JWT, JSON/XML formatting.
   - Hash and HMAC helpers.
   - Gzip/deflate support.
5. Comparer
   - Raw response diff.
   - Header diff.
   - JSON semantic diff.
   - Timing comparison.
   - Send selected corpus/repeater responses into comparison.

Current start: dedicated Comparer workflow backed by the existing manual response comparison API.

## Phase 2: Enterprise Vulnerability Management

Goal: make findings trackable over time across apps and teams.

Priority upgrades:

1. Finding lifecycle
   - New, triaged, confirmed, assigned, fixed, retested, closed.
   - Accepted risk and false positive branches.
2. Sites and applications
   - Projects, environments, owners, auth profiles, scan profiles.
   - Last scan, open risk, SLA due date.
3. Scan scheduling
   - Daily, weekly, monthly, and scan-window controls.
   - Recurring scan templates.
   - New/fixed/reopened/existing comparison.
4. Ticketing integrations
   - Jira, GitHub Issues, GitLab, Linear.
   - Severity/confidence trigger rules.
   - Status sync back into Wraith.
5. Reporting upgrades
   - HTML, CSV, SARIF, JUnit, Markdown, evidence ZIP.
   - Executive, developer, retest, and compliance views.

## Phase 3: DevSecOps And CI/CD

Goal: make Wraith easy to run in engineering pipelines.

Priority upgrades:

1. GitHub Action and GitLab/Jenkins examples.
2. Docker scanner image.
3. SARIF and JUnit outputs.
4. Severity-threshold exit codes.
5. Baseline suppression mode.
6. PR comments with concise findings and evidence links.

## Phase 4: Server Mode And Scale

Goal: support multi-user teams and larger scan programs.

Priority upgrades:

1. PostgreSQL storage mode alongside local SQLite.
2. Redis-backed scan queue.
3. Worker process model.
4. Scan cancellation, pause, resume, and retry.
5. Object storage for evidence artifacts.
6. Health checks and worker heartbeat.

## Phase 5: Distributed Agents

Goal: scan internal assets safely from the right network location.

Priority upgrades:

1. Central server with registered agents.
2. Agent registration tokens.
3. Agent groups for staging, internal, cloud, and production-safe networks.
4. Per-agent concurrency limits.
5. Kubernetes deployment.
6. Agent health and queue visibility.

## Phase 6: Enterprise Access Control

Goal: make Wraith safe for teams and customers.

Priority upgrades:

1. Users, organizations, workspaces, projects.
2. Roles: admin, security lead, pentester, developer, viewer.
3. SSO/OIDC/SAML.
4. Scoped API keys.
5. Audit logs for scans, evidence views, exports, severity changes, and lifecycle changes.

## Phase 7: Premium Analytics

Goal: make Wraith feel like an executive-grade AppSec command center.

Priority upgrades:

1. Risk dashboards.
2. SLA tracking.
3. Trend charts.
4. Asset exposure scoring.
5. EPSS and CISA KEV prioritization.
6. Custom branded reports.
7. AI-assisted remediation summaries that never execute payloads.

## Safety Principles

- Keep Proof Mode deterministic and bounded.
- Keep LLMs optional and never allow arbitrary payload execution.
- Keep intrusive behavior behind explicit operator approval.
- Keep HTTPS interception explicit, scoped, and transparent.
- Keep secrets redacted in storage, logs, reports, and exports.
- Keep local desktop mode usable without cloud or external services.
