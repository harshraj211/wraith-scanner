# Wraith v4 Future Plan: Benchmark, Gap Analysis, and VA+PT Architecture

Date: 2026-04-26

This plan is intentionally blunt. Wraith v4 has some genuinely strong ideas, especially SPA state mutation, OOB correlation, and lightweight cross-file taint, but the best commercial tools still win on authentication, workflow maturity, extensibility, verification depth, reporting polish, and enterprise deployment.

The goal should not be "replace Burp tomorrow." The winning wedge is: **automated SPA/API discovery + finding-to-proof workflow + source/runtime correlation + clean CI artifacts**, while keeping destructive exploitation behind strict safety policy gates.

## Sources Checked

- PortSwigger Burp Scanner docs: browser-powered scanning with embedded Chromium, custom BChecks, API scanning, Collaborator/OAST.
  - https://portswigger.net/burp/documentation/scanner/browser-powered-scanning
  - https://portswigger.net/burp/documentation/scanner
  - https://portswigger.net/burp/documentation/scanner/api-scanning-reqs
  - https://portswigger.net/burp/documentation/collaborator
  - https://portswigger.net/burp/documentation/scanner/bchecks
- ProjectDiscovery Nuclei docs: YAML templates, fuzzing for unknown vulnerabilities, workflows, public templates, Interactsh/OAST.
  - https://docs.projectdiscovery.io/opensource/nuclei
  - https://docs.projectdiscovery.io/templates
  - https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview
  - https://docs.projectdiscovery.io/tools/nuclei/running
- OWASP ZAP docs: Automation Framework and API-oriented jobs including OpenAPI/SOAP/GraphQL.
  - https://www.zaproxy.org/docs/automate/automation-framework/
  - https://www.zaproxy.org/docs/desktop/addons/graphql-support/automation/
- Invicti/Acunetix docs: proof-based scanning, API discovery/scanning, DAST+IAST positioning.
  - https://www.invicti.com/features/advanced/overview/
  - https://www.invicti.com/platform-overview
  - https://www.acunetix.com/support/docs/api-types-formats/
- Semgrep docs: taint mode, Pro interprocedural/interfile analysis, language coverage and memory requirements.
  - https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
  - https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-examples
  - https://cloudflare.semgrep.dev/products/pro-engine/
- Caido docs: modern manual testing workflow, Scanner plugin, HTTPQL search, AI Assistant.
  - https://docs.caido.io/
  - https://docs.caido.io/app/tutorials/scanner
  - https://docs.caido.io/guides/search
  - https://docs.caido.io/app/quickstart/assistant
- Groq docs: structured outputs, JSON schema modes, prompting guidance, API reference.
  - https://console.groq.com/docs/structured-outputs
  - https://console.groq.com/docs/prompting
  - https://console.groq.com/docs/api-reference
- OpenAI and Anthropic model docs checked for fallback-provider context.
  - https://platform.openai.com/docs/models/o3
  - https://platform.openai.com/docs/guides/reasoning-best-practices
  - https://docs.anthropic.com/en/docs/about-claude/models/all-models

---

# Part 1: Real-World Benchmark

## Executive Benchmark Summary

Wraith v4 competes best against scanners when the target is a modern SPA with hidden client-side routes, mutable browser storage, GraphQL/WebSocket surfaces, and a repo available for SAST correlation. It does **not** yet compete with Burp Suite Pro or Caido as a daily manual pentest workbench, with Nuclei as a massive community coverage engine, with Invicti/Acunetix for enterprise proof-based scanning, or with Semgrep Pro for mature multi-language SAST.

The biggest truth: **coverage claims are not enough**. Professional testers choose tools that preserve session state, let them inspect and replay every request, prove findings without damaging the target, suppress noise, export clean evidence, and integrate with their reporting workflow.

## Dimension-by-Dimension Comparison

| Dimension | Wraith v4 Today | Burp Suite Pro | Nuclei | OWASP ZAP | Invicti / Acunetix | Semgrep Pro | Caido |
|---|---|---|---|---|---|---|---|
| Detection accuracy / false positives | Good direction because of sink-aware validation, response fingerprinting, OOB confirmation, and deduplication. Still likely noisy for IDOR, CSRF, headers, race conditions, DOM XSS, and business logic. | Strong active scanner, mature insertion-point analysis, browser-powered crawl/audit, Collaborator OAST, and manual verification workflow. | Excellent when templates are precise; noisy or shallow when template quality is weak. Scales better than it reasons. | Decent open-source baseline; accuracy varies by add-ons and configuration. | Strongest commercial claim here due to proof-based scanning and IAST options. Treat vendor accuracy claims as marketing, but the architecture is mature. | Strong SAST accuracy when rules are tuned and Pro dataflow applies. | Manual-first; scanner plugin is growing. Strong user workflow, less proven scan corpus than Burp. |
| SPA / modern framework coverage | One of Wraith's best differentiators: Playwright crawl, storage snapshots, deep-state mutation, route re-extraction. Needs coverage maps and deterministic replay. | Browser-powered scanning uses embedded Chromium by default, but complex SPAs still need manual crawl help. | Weak unless fed URLs/HARs/templates; not a deep app-state crawler. | AJAX spider helps, but modern SPA auth/state handling is still work. | Strong commercial crawling and API discovery; less transparent to the tester. | SAST can detect unsafe patterns in React/Next/Vue/Angular but does not perform DAST navigation. | Excellent manual SPA workflow if tester drives it; automated scanner still newer. |
| Authentication handling | Basic/form/bearer/API key/custom headers/cookies exist. Missing robust OAuth/OIDC refresh, MFA pause, role profiles, token renewal, session health checks, and recorded login workflows. | Mature session handling, macros, login flows, manual proxy capture, extensions. | Mostly external; feed authenticated requests/templates. | Supports authentication but takes careful setup; automation can be brittle. | Strong enterprise auth workflows and scheduled scans. | Uses source context, not runtime sessions. | Strong manual proxy session workflow; modern UX. |
| SAST depth | Semgrep + custom cross-file taint for Python/JS. Interesting, but far from Semgrep Pro breadth and precision. | Not SAST-focused. | Not SAST-focused, though templates can inspect exposed files/configs. | Not SAST-focused. | Mostly DAST/IAST/SCA depending product tier. | Benchmark leader in this comparison for SAST: interprocedural and interfile analysis across multiple languages in Pro. | Not SAST-focused. |
| OOB / blind confirmation | Strong feature: per-parameter callback correlation and egress hints. Needs private OAST server option, durable correlation store, and evidence retention. | Burp Collaborator is mature and deeply integrated into scanner/manual checks. | Interactsh integration is a major strength. | Add-ons/workflows possible, less polished. | Commercial proof-based engines often verify blind issues well. | Not applicable except code indicators. | Manual OOB possible through workflows/plugins, not as dominant as Burp. |
| Payload intelligence / WAF evasion | Good v4 idea: response intelligence and context-aware mutation. Needs measurement, bounded mutation catalog, and adaptive retry budgets. | Very mature insertion points and audit logic; BChecks/custom scan checks extend coverage. | Template and fuzzing DSL is powerful; community velocity beats Wraith. | Scriptable but less elegant. | Commercial engines have years of tuning and safety controls. | Rules are static/dataflow, not DAST payloads. | Replay/Automate and AI Assistant make manual payload iteration pleasant. |
| Reporting quality | PDF exists and maps OWASP/CWE/CVSS. Current report still reads like scanner output, not a professional pentest deliverable. Needs scope, coverage, evidence chain, remediation ownership, retest status, and better proof sections. | Good issue details, but many consultants still export and rewrite. | Raw output is not enough; requires triage/report layer. | Baseline reports are serviceable, not premium. | Strong enterprise reporting and dashboards. | Strong developer/security workflow reports, SARIF/PR comments. | Great for workflow notes/evidence capture, but not a complete consulting report alone. |
| CI/CD readiness | Has CLI and tests, but needs stable JSON/SARIF/JUnit, Docker image, exit thresholds, baseline suppression, API auth profiles, and scan budgets. | Enterprise better than Pro for CI. | Excellent CLI-native CI fit. | Excellent CI fit through Automation Framework and Docker. | Strong enterprise scheduling/integrations. | Excellent CI/PR integration. | Less CI-first, more interactive. |
| API testing | GraphQL and WebSocket support are good starts. Missing OpenAPI/Postman/HAR import, authenticated sequence testing, schema-aware fuzzing, and gRPC/protobuf. | Can parse OpenAPI, SOAP WSDL, Postman, GraphQL under documented constraints. | Strong if templates and discovered endpoints exist; API testing is still partly alpha/templated. | Automation framework supports API jobs. | Strong API import and discovery; Acunetix docs list REST/OpenAPI/Swagger/RAML/WADL/Postman, SOAP/WSDL, GraphQL SDL. | Can find server-side API code issues, not runtime protocol behavior. | Strong manual request handling; scanner plugin still maturing. |
| Exploitation capability | Currently zero beyond confirmation probes. This is a major gap if VA+PT is the product direction. | Manual exploitation workbench is the industry default. | Some templates include exploit-oriented checks, but mostly detection. | Manual and scripted exploitation possible, less polished. | Proof-based scanning verifies exploitability, but does not replace a human pentester. | Not exploitation. | Manual exploitation workflow is a core draw; AI Assistant can suggest vectors/PoCs. |

## Tool-by-Tool Assessment

## Wraith vs Burp Suite Pro

Burp Pro is still the professional web pentest default because it is both a scanner and a manual workbench. Its scanner uses browser-powered crawling/auditing with embedded Chromium, and Collaborator gives mature OAST for blind vulnerabilities. BChecks and Java custom scan checks also give a real extension path.

Where Wraith competes:

- SPA-specific storage mutation and route re-extraction could beat default Burp scans on some modern apps if Wraith can prove coverage.
- SAST + DAST correlation can produce evidence Burp Pro does not natively provide.
- A purpose-built "finding to proof to report" pipeline could be faster than Burp for repeatable authorized assessments.

Where Burp wins hard:

- Manual testing workflow: intercept, replay, intruder-style fuzzing, target map, history, session rules, extensions.
- Auth workflows and session recovery.
- Trust: consultants know how to defend Burp findings to clients.
- OAST and custom check ecosystem.

Critical product implication: do not try to copy all of Burp. Build the parts Burp does not unify well: **automated SPA state exploration, source/runtime correlation, and report-ready evidence bundles**.

## Wraith vs Nuclei

Nuclei's advantage is not deep reasoning; it is distribution and template velocity. Its YAML templates, workflows, fuzzing support, public template auto-updates, and Interactsh integration make it brutally efficient at checking internet-scale known exposures.

Where Wraith competes:

- Deep app-state DAST and browser-driven discovery.
- Per-finding validation beyond simple matcher logic.
- Richer SPA/API context if Wraith captures traffic well.

Where Nuclei wins hard:

- Community coverage for fresh CVEs and exposed products.
- CI simplicity.
- Template authoring and sharing.
- Speed and horizontal scale.

Recommendation: integrate Nuclei rather than compete with it. Add a `NucleiAdapter` that can:

- Run nuclei against discovered URLs, hosts, technologies, and extracted API endpoints.
- Pin templates by version for reproducible reports.
- Import results into Wraith's unified finding schema.
- Let users attach private template repositories.

## Wraith vs OWASP ZAP

ZAP is the open-source automation baseline. It is not as polished as Burp, but the Automation Framework, API, Docker usage, and add-ons make it a practical CI scanner.

Where Wraith competes:

- Better modern SPA feature ambition.
- Python-native module development may be faster for your codebase.
- SAST integration is outside ZAP's core value.

Where ZAP wins:

- Established automation model.
- Docker and CI/CD friendliness.
- Community trust and integrations.

Recommendation: Wraith should surpass ZAP specifically in developer ergonomics: clean JSON/SARIF output, simple auth profile files, deterministic scan plans, and better reports.

## Wraith vs Invicti / Acunetix

Invicti/Acunetix win on enterprise DAST maturity: proof-based scanning, asset inventory, scheduling, scan agents, dashboards, API discovery/scanning, and compliance-friendly reporting. Invicti claims very high scan accuracy; treat the exact number as vendor marketing, but proof-based scanning is the right architectural goal.

Where Wraith competes:

- Developer-controlled local scanner with inspectable logic.
- Lower-cost research/consulting workflow.
- Potentially better source/runtime correlation if implemented well.

Where commercial DAST wins:

- Executive-ready reports and dashboards.
- Auth and scan stability at enterprise scale.
- Verified proofs and fewer false positives.
- Asset management and governance.

Recommendation: copy the architectural principle, not the product bulk: **every high/critical finding should have a verification oracle and evidence artifact**.

## Wraith vs Semgrep Pro

Semgrep Pro is the SAST benchmark in this list. Its Pro engine supports interprocedural analysis and interfile dataflow for key languages, with documented memory tradeoffs. Wraith's custom Python/JavaScript taint engine is valuable, but it should be treated as a focused supplement, not a peer competitor yet.

Where Wraith competes:

- Purpose-built web source-to-sink checks can be good if narrow and precise.
- DAST correlation can prioritize SAST findings that map to live endpoints.

Where Semgrep Pro wins:

- Multi-language support.
- Rule ecosystem.
- Developer workflow, CI, PR comments, suppression management.
- Mature dataflow engine and traces.

Recommendation: make Wraith SAST a **correlation layer**:

- Use Semgrep output as primary AST signal.
- Keep Wraith taint for high-signal Python/JS web patterns.
- Link SAST sinks to DAST endpoints through route extraction and framework mapping.
- Export SARIF so findings can live in GitHub Advanced Security, GitLab, DefectDojo, or Semgrep pipelines.

## Wraith vs Caido

Caido is gaining traction because it feels modern. It is fast, clean, plugin-oriented, and built around manual testing flow: intercept, replay, automate, search, plugins, and increasingly scanner/AI features. Caido's docs describe an official Scanner plugin with passive/active checks, rate limiting, presets, and a paid AI Assistant that can suggest attack vectors and PoC ideas.

Where Wraith competes:

- Automation-first scanning and report generation.
- SAST/DAST fusion.
- SPA state mutation as a differentiated capability.

Where Caido wins:

- Daily tester UX.
- Request history/search/replay ergonomics.
- Manual exploitation loop.
- Plugin ecosystem trajectory.

Recommendation: Manual Mode must be more than "choose modules." It needs to feel like a focused workbench around Wraith's unique intelligence: **turn crawler discoveries and findings into replayable, explainable, reportable proof tasks**.

---

# Part 2: Gap Analysis and Improvement Roadmap

## Top 5 Critical Gaps

## Gap 1: Authentication and Session Depth

This is the largest practical blocker. Professional scans fail when they cannot stay authenticated, traverse roles, refresh tokens, handle MFA, or recover state after logout.

Current Wraith has form/basic/bearer/API key/custom header/cookie support, but that is not enough for OAuth/OIDC SPAs, short-lived JWTs, SSO redirects, MFA, CSRF-token refresh, or role-based IDOR testing.

Concrete implementation direction:

- Add `AuthProfile` as a first-class object:
  - `profile_id`, `name`, `base_url`, `role`, `auth_type`, `storage_state_path`, `session_health_check`, `refresh_strategy`, `redaction_rules`.
- Use Playwright `browser_context.storage_state()` to save and restore authenticated browser state.
- Add a login recorder:
  - User manually logs in once through a Playwright-controlled browser.
  - Wraith stores cookies/localStorage/sessionStorage and a HAR-lite login trace.
  - Do not store passwords by default; store encrypted profile data if persistence is enabled.
- Add session health checks:
  - URL, expected status, expected text/selector, negative logout indicators.
  - Run before each scan phase and before each exploitation task.
- Add token refresh adapters:
  - Static bearer refresh command: user supplies a script/command returning JSON `{headers,cookies,expires_at}`.
  - OAuth/OIDC browser refresh: revisit app and wait for token renewal.
  - JWT expiry parser: decode exp claim without trusting it for authorization.
- Add MFA support:
  - "Pause for human" checkpoint in UI.
  - Optional TOTP via `pyotp` only when user explicitly provides a seed.
- Add role profiles:
  - At least `anonymous`, `user_a`, `user_b`, `admin`.
  - IDOR and authorization tests should compare role-specific response fingerprints.

Useful libraries:

- Playwright storage state APIs.
- `authlib` for OAuth/OIDC helpers.
- `pyjwt` for JWT decoding.
- `pyotp` for optional TOTP.
- `cryptography` or OS keyring for local secret encryption.

## Gap 2: Manual Workbench and Request Corpus

Wraith is currently a scanner with a terminal UI, not a pentester workbench. A professional will still open Burp/Caido because they need request history, replay, diffing, intruder-like fuzzing, scope controls, notes, and evidence capture.

Concrete implementation direction:

- Store every discovered/proxied/generated request in a durable request corpus:
  - Use SQLite for local single-user mode, Postgres for team/server mode.
  - Tables: `requests`, `responses`, `scan_tasks`, `findings`, `evidence_artifacts`, `auth_profiles`, `oob_events`.
- Build a request detail view:
  - Raw request/response.
  - Pretty JSON/XML/form views.
  - Header/body diff between baseline and mutated requests.
  - "Send to Replay", "Send to Fuzzer", "Create Finding", "Attach Evidence".
- Add Replay:
  - Editable method/path/query/headers/body.
  - Environment variables and auth profile injection.
  - Response diff against baseline.
- Add Fuzzer:
  - Pitchfork/cluster-bomb-style payload positions.
  - Rate limit, delay, max requests, stop conditions.
  - Response clustering by status, length, title, DOM hash, JSON shape, timing bucket.
- Add a query language or pragmatic filters:
  - Start simple with fields: method, host, path, status, mime, source, has_param, finding_id, response_hash, auth_role.
  - Later add HTTPQL-like search.

Useful libraries:

- `sqlite-utils` or SQLAlchemy for local DB.
- `mitmproxy` as an optional proxy-core integration if you want true intercepting proxy behavior.
- `deepdiff` for structured JSON diffs.
- `jsonpath-ng` for JSON extraction.

## Gap 3: API Security Import and Sequence Testing

GraphQL/WebSocket support is good, but professional API testing is schema- and sequence-heavy. REST APIs often require OpenAPI/Postman/HAR imports and multi-step workflows before vulnerable endpoints are reachable.

Concrete implementation direction:

- Add importers:
  - OpenAPI 3.x / Swagger 2: `prance`, `openapi-spec-validator`, `jsonschema`.
  - Postman collections: parse collection v2.1 JSON.
  - HAR import: browser/devtools exported traffic.
  - GraphQL SDL/introspection JSON: `graphql-core`.
  - gRPC proto: shell out to `grpcurl` initially, later use `grpcio` + `grpcio-tools`.
- Generate request candidates from schemas:
  - Required fields get type-appropriate benign values.
  - Auth requirements map to Wraith auth profiles.
  - Parameters are tagged by location: path/query/header/cookie/body/json-field/graphql-var.
- Add stateful API sequence runner:
  - Capture variables from one response using JSONPath/regex/header selectors.
  - Feed variables into later requests.
  - Define sequences in YAML:
    - `login -> create resource -> read resource -> update resource -> delete resource`
  - For production-safe mode, disallow destructive verbs unless endpoint is explicitly marked safe or the user enables intrusive mode.
- Add authorization matrix testing:
  - Same request under role A, role B, admin, anonymous.
  - Compare status, response shape, object ownership fields, and data sensitivity.

## Gap 4: Verified Proof Architecture

Current Wraith finds and reports. The next leap is proof, but proof must be controlled. If the tool simply asks an LLM to generate payloads and executes them, it will produce unreliable results and operational risk.

Concrete implementation direction:

- Create an `exploitation/` package separate from DAST modules:
  - `planner.py`: turns findings into proposed `ExploitPlan`.
  - `policies.py`: safety policy and allowed technique catalog.
  - `executors/`: deterministic executors by vuln class.
  - `verifiers/`: success oracles.
  - `evidence.py`: artifacts, screenshots, excerpts, redaction.
  - `providers/`: Groq/OpenAI/Claude/local model adapters.
- LLM should choose from a **catalog** of allowed proof techniques, not free-form exploit arbitrary targets.
- Execution must be deterministic code with hard limits:
  - Max attempts per finding.
  - Per-host and per-endpoint budgets.
  - No shell/RCE payloads in production-safe mode.
  - No destructive writes unless a workflow explicitly marks a test resource as disposable.
- Create a standard evidence schema:

```json
{
  "finding_id": "string",
  "task_id": "string",
  "mode": "safe|intrusive|lab",
  "technique_id": "string",
  "attempts": [],
  "result": "succeeded|partial|failed|blocked|skipped",
  "confidence_delta": 0,
  "artifacts": [],
  "redactions_applied": [],
  "operator_approval": {
    "required": true,
    "approved_by": null,
    "approved_at": null
  }
}
```

## Gap 5: Professional Reporting and CI Artifacts

The current PDF generator is useful but not consulting-grade. It also appears to include encoding artifacts in some text strings, which should be cleaned before reports go to clients.

Concrete implementation direction:

- Add output formats:
  - `wraith.json`: canonical full result.
  - `wraith.sarif`: SAST/DAST where applicable.
  - `junit.xml`: CI gate compatibility.
  - `report.pdf`: executive/client report.
  - `evidence.zip`: raw sanitized artifacts.
- Report sections needed:
  - Cover page with client/app/scope/date/version.
  - Executive summary with risk narrative, not just counts.
  - Scope and rules of engagement.
  - Methodology and tool configuration.
  - Coverage metrics: URLs, forms, APIs, roles, auth status, crawl depth, skipped endpoints.
  - Findings summary by severity, asset, vuln class, and exploitability.
  - Detailed findings with discovery evidence and proof evidence separated.
  - Exploitation safety mode and limitations.
  - Business impact and technical impact.
  - Remediation with owner/status/due date fields.
  - Retest status.
  - Appendix: raw HTTP evidence, SAST traces, OOB callbacks, screenshots, scan logs.
- Use HTML-to-PDF instead of building complex PDFs directly in ReportLab:
  - Jinja2 templates + Playwright PDF rendering gives better layout control.
  - Keep ReportLab only if you want a pure-Python fallback.

## Prioritized Roadmap

## Phase 0: Stabilize the Product Surface, 1-2 Weeks

Build these first because every future feature depends on stable data:

1. Define canonical schemas:
   - `Finding`
   - `RequestRecord`
   - `ResponseRecord`
   - `EvidenceArtifact`
   - `ScanConfig`
   - `AuthProfile`
2. Add JSON output for every scan.
3. Add stable finding IDs:
   - Hash of target, normalized endpoint, parameter, vuln type, evidence type, auth role.
4. Add report redaction:
   - Secrets, cookies, bearer tokens, API keys, PII-like values.
5. Fix report encoding and generate a small sample report in CI.

## Phase 1: Auth Profiles and Request Corpus, 2-4 Weeks

This is the highest capability jump per engineering effort.

1. Implement Playwright login recording and `storageState` reuse.
2. Add session health checks and automatic re-auth.
3. Add role profiles.
4. Persist request/response corpus in SQLite.
5. Add request replay API and UI panel.

Why first: better auth instantly improves DAST coverage, IDOR testing, SPA crawling, API testing, and future exploitation proof.

## Phase 2: API Import and Sequence Runner, 3-5 Weeks

1. OpenAPI/Postman/HAR importers.
2. Schema-aware request generation.
3. YAML workflow runner with variables.
4. Role-based authorization matrix.
5. GraphQL operation generation from schema/introspection.

Why second: professional targets are increasingly API-first. This also gives Manual Mode real substance.

## Phase 3: Proof Engine Without LLM, 3-5 Weeks

Build deterministic exploitation proof before Groq.

1. Create `exploitation/` package and task model.
2. Implement safe proof executors:
   - Reflected XSS browser execution proof with screenshot/console event.
   - SSRF OOB proof using existing callback mapping.
   - SQLi boolean/time/error confirmation without data extraction.
   - Open redirect proof through redirect-chain validation.
   - Path traversal proof using benign, non-sensitive fingerprint files only in lab/safe allowlist mode.
   - GraphQL introspection/misconfig proof.
3. Add safety policies and attempt budgets.
4. Add evidence artifacts to report.

Why before LLM: if deterministic proof is weak, LLM guidance will amplify noise.

## Phase 4: Groq-Guided Planner, 2-4 Weeks

1. Add provider abstraction:
   - `GroqProvider`
   - `OpenAIProvider`
   - `AnthropicProvider`
   - `NoLLMProvider`
2. Use Groq for:
   - Technique selection from allowed catalog.
   - Evidence oracle selection.
   - Payload-template parameterization, not unconstrained exploit generation.
3. Add JSON schema validation and retry.
4. Add model confidence and "skip if insufficient context".
5. Log every LLM prompt/response with redaction for auditability.

## Phase 5: Manual Mode That Can Compete, 6-10 Weeks

1. Intercept/proxy mode or mitmproxy integration.
2. Searchable request corpus.
3. Replay, fuzzer, comparer.
4. Payload manager.
5. OOB console.
6. Finding notebook and report builder.
7. Plugin/check SDK.

## Phase 6: CI/CD and Enterprise Fit, 3-6 Weeks

1. Docker image.
2. GitHub Action.
3. SARIF/JUnit exports.
4. Exit thresholds.
5. Baseline suppression.
6. DefectDojo/Jira/GitHub issue export.
7. Scan budgets and resumable jobs.

## Flask + Playwright + React Architecture Risks

Current stack can work for a local tool, but it will strain as scan complexity grows.

Risks:

- Flask + global `active_scans` is not durable. A process crash loses scan state.
- Thread-per-scan model will become painful with Playwright browser contexts and long-running OOB polling.
- Mixing sync requests, async aiohttp, Playwright, and subprocess Semgrep increases deadlock/timeouts risk.
- Report generation is synchronous and monolithic.
- No durable job queue means scans cannot pause/resume/retry cleanly.
- Playwright is resource-heavy; multiple scans need browser context pooling and memory caps.
- Secrets in auth configs need encrypted storage and redaction.
- No formal plugin boundary means scanners will become tightly coupled.

Recommended architecture:

- Keep React frontend.
- Replace or supplement Flask endpoints with FastAPI when you introduce typed schemas and async endpoints. Flask can remain initially if migration cost matters.
- Add a worker queue:
  - Redis + RQ/Celery for simple Python deployment.
  - Arq if you want async-native Redis workers.
  - Dramatiq is also a clean option.
- Add durable storage:
  - SQLite for local desktop mode.
  - Postgres for server/team mode.
  - Object store/local artifact directory for screenshots, HARs, PDFs, evidence zips.
- Add an event bus:
  - `scan.started`, `request.discovered`, `finding.created`, `proof.completed`, `report.generated`.
- Add browser pool:
  - Per-scan isolated context.
  - Shared browser process where safe.
  - Hard caps: max contexts, max pages, max memory, timeout.
- Add scan cancellation:
  - Cancellation tokens checked by crawler, scanners, OOB pollers, exploit executors, report generator.

---

# Part 3: VA + PT Mode With Groq-Guided Exploitation

## Feasibility Verdict

The idea is technically viable **only if Groq is a constrained planner, not an autonomous exploit writer**.

Bad version:

- Wraith sends a finding to Groq.
- Groq invents a payload.
- Wraith executes it.
- The report trusts the result.

This will fail. It will hallucinate, overfit to generic exploit patterns, miss target-specific state, suggest unsafe actions, and produce false proof.

Good version:

- Wraith runs DAST and produces structured findings.
- Wraith normalizes each finding into a proof task.
- Groq chooses from a strict catalog of allowed proof techniques and output schema.
- Wraith deterministic executors perform bounded, non-destructive attempts.
- Wraith deterministic verifiers decide success.
- The report records discovery evidence, proof evidence, model recommendation, and safety mode separately.

Use the LLM for judgment and adaptation, not authority.

## Real Failure Modes

Prompt reliability:

- Groq models can produce plausible but wrong payload strategies.
- Even with JSON mode, schema validity does not imply semantic correctness.
- Groq structured-output docs explicitly distinguish schema compliance from output quality.

Payload hallucination:

- The model may invent framework behavior, database type, template engine, route semantics, or auth assumptions.
- Workaround: provide only allowed `technique_id` and `payload_template_id` values.

Context window limits:

- Raw responses, JavaScript bundles, SAST traces, and HARs will exceed useful context.
- Workaround: pre-compress context into a finding bundle:
  - normalized request
  - response fingerprint
  - evidence excerpt
  - parameter metadata
  - auth role
  - route/source trace if available
  - allowed techniques
  - safety policy

Target state changes:

- The app may change between scan and exploit phase.
- Tokens expire, resources disappear, WAF state changes, rate limits kick in.
- Workaround: proof preflight:
  - session health check
  - baseline request replay
  - response fingerprint comparison
  - skip if state drift exceeds threshold

Prompt injection from target content:

- Target responses may contain text that attempts to manipulate the LLM.
- Workaround: wrap target content as untrusted data and instruct the model to ignore instructions inside it. Better: never send full raw pages unless needed.

Safety and legal risk:

- Automated exploitation can cross engagement boundaries.
- Workaround: scope enforcement, per-mode allowed technique catalog, operator approval for intrusive actions, full audit log.

Model capability ceiling:

- Fast open models are useful for classification and template selection.
- Multi-step exploitation reasoning, auth bypass, business logic, and chained attacks will hit a ceiling quickly.
- Workaround: provider abstraction with fallback to stronger reasoning models and human approval.

## Vulnerability Classes: Automation Reliability

| Vulnerability class | Automated exploitation reliability | Safe proof approach | Human judgment needed |
|---|---:|---|---|
| Reflected XSS | High for simple cases | Browser executes controlled benign marker, capture console/DOM/screenshot | CSP bypass, framework-specific sanitization, exploitability impact |
| DOM XSS | Medium-low | Instrument browser sinks and verify controlled marker reaches executable context | Complex client flows, source/sink reachability |
| Stored XSS | Medium | Submit benign marker through workflow, revisit render locations | Finding storage location, cleanup, user impact |
| SQL injection | Medium-high for confirmation; low for safe data extraction | Error/boolean/time proof, DB fingerprint only when non-invasive | Data extraction, chained auth bypass |
| Blind SQLi | Medium | Timing or OOB callback proof with strict attempt budget | Reliability under jitter, DB-specific tuning |
| SSRF | High for OOB confirmation | Callback proof with per-param correlation | Internal network impact, cloud metadata exploitation |
| XXE | Medium | OOB callback proof or parser-behavior proof | File read impact, parser-specific escalation |
| SSTI | Medium for detection; low for safe RCE proof | Engine fingerprint and benign arithmetic/string evaluation when safe | RCE chains, sandbox escapes |
| Command injection | Medium for timing/OOB; dangerous for exploitation | Non-destructive timing/OOB proof only | Any real command output or post-exploitation |
| Path traversal | Medium | Benign known-file fingerprint only; avoid sensitive file reads by default | Impact validation and platform nuance |
| IDOR / BOLA | Medium if role profiles exist; low without them | Compare same object requests across role profiles and object corpus | Business context and data sensitivity |
| Open redirect | High | Redirect-chain validation to controlled harmless domain | Phishing/business impact |
| CSRF | Low-medium | Missing token + SameSite/Origin checks + optional browser PoC in lab | Real exploitability depends on auth/browser/site behavior |
| GraphQL misconfig | High for introspection/config issues; medium for auth flaws | Schema/introspection/query-depth proof within budget | Business object authorization |
| WebSocket injection/auth | Medium-low | Replay message mutations and compare structured responses | Stateful protocols and custom message semantics |
| Race conditions | Low-medium | Bounded concurrent replay against explicitly safe operations | Financial/business impact and cleanup |
| Dependency CVEs | Low for automated exploitation | Version + reachability + known advisory evidence | Exploitability in app-specific configuration |
| Business logic | Low | Mostly not automatable | Human-led testing |

## Recommended Exploitation Architecture

Build exploitation as a **post-scan proof engine** with optional pipeline hooks.

Default flow:

1. DAST/SAST produce canonical `Finding` JSON.
2. `ProofPlanner` selects eligible findings:
   - confirmed or high-confidence only
   - severity high/critical by default
   - safety policy allows proof
3. `ContextBuilder` creates compact context bundle.
4. `LLMProvider` optionally proposes a plan from the allowed catalog.
5. `PolicyEngine` validates plan.
6. `Executor` performs bounded attempts.
7. `Verifier` decides result.
8. `EvidenceStore` saves artifacts.
9. `ReportBuilder` includes discovery and proof sections.

Why post-processor:

- Clean separation from DAST.
- Re-runnable against saved findings.
- Easier to gate with user approval.
- Easier to compare deterministic vs LLM-guided proof.
- Less risk of exploitation logic contaminating scanner correctness.

Where to hook into the scan pipeline:

- Add optional hooks after each confirmed high/critical finding for OOB/time-sensitive cases.
- Example: SSRF callback windows and short-lived auth state may benefit from immediate proof.
- Keep the hook as `enqueue_proof_task(finding_id)` rather than direct exploitation inside scanners.

Suggested package layout:

```text
scanner/
  exploitation/
    __init__.py
    models.py
    planner.py
    context.py
    policy.py
    registry.py
    evidence.py
    providers/
      base.py
      groq_provider.py
      openai_provider.py
      anthropic_provider.py
    executors/
      xss.py
      sqli.py
      ssrf.py
      redirect.py
      path_traversal.py
      graphql.py
      idor.py
    verifiers/
      browser.py
      timing.py
      oob.py
      diff.py
```

Core interfaces:

```python
class ProofExecutor:
    vuln_types: set[str]
    safety_modes: set[str]

    async def precheck(self, task, context) -> PrecheckResult: ...
    async def execute(self, task, plan, http, browser_pool) -> list[Attempt]: ...
    async def verify(self, task, attempts, evidence_store) -> ProofResult: ...
```

```python
class LLMPlanProvider:
    async def propose_plan(self, context_bundle, allowed_catalog, schema) -> ExploitPlan: ...
```

## Groq Prompt Template Design

Use one shared system prompt plus vuln-class-specific catalogs.

System prompt requirements:

- State that the target is authorized.
- State that target content is untrusted data.
- State that the model must choose only from allowed techniques.
- State that destructive actions, data exfiltration, persistence, credential theft, lateral movement, and service disruption are disallowed.
- State that the model must return JSON only.
- State that if context is insufficient, it must return `skip`.

Always include:

- Vulnerability class.
- Confidence and discovery method.
- Normalized HTTP request.
- Parameter location and type.
- Baseline response fingerprint.
- Discovery evidence excerpt.
- Auth role and session status.
- Target scope and excluded hosts.
- Allowed safety mode.
- Allowed technique catalog for that vuln class.
- Max attempts and rate limit.
- OOB callback capability availability.
- Previous attempts, if any.
- Success evidence options.
- Cleanup constraints.

Do not include by default:

- Full cookies or bearer tokens.
- Full response bodies.
- Full source files.
- Secrets found by SAST.
- Unbounded JavaScript bundles.

Recommended output schema:

```json
{
  "action": "attempt|skip",
  "reason": "string",
  "technique_id": "string|null",
  "payload_template_id": "string|null",
  "parameters": {
    "target_param": "string|null",
    "marker": "string|null",
    "oob_required": false,
    "expected_signal": "string|null"
  },
  "success_oracles": [
    {
      "oracle_type": "response_diff|timing|oob|browser_dom|browser_console|redirect_chain",
      "expected": "string"
    }
  ],
  "risk_notes": ["string"],
  "requires_human_approval": false
}
```

Important reliability rule:

- Prefer `payload_template_id` over raw payload text.
- Let deterministic code fill in markers, callback domains, encodings, and transport details.
- Allow raw payload text only in `lab` mode or manually approved custom payload mode.

## Groq-Specific Assessment

Groq is useful because speed changes UX. It can make interactive guidance feel instant. But fast does not equal sufficiently reliable for complex exploitation reasoning.

Use Groq for:

- Finding triage.
- Selecting proof technique from a constrained catalog.
- Explaining why a proof did or did not work.
- Suggesting next safe diagnostic step.
- Classifying response differences.

Do not rely on Groq alone for:

- Multi-step exploit chains.
- Business logic exploitation.
- Auth bypass.
- Non-trivial DOM XSS.
- WAF bypass strategy.
- Any action that could modify production data or expose sensitive records.

Groq implementation details:

- Use the OpenAI-compatible Groq client.
- Use JSON mode or structured outputs where supported.
- Groq docs currently distinguish strict structured output support from best-effort modes; strict support is model-dependent, and other models may require JSON object mode plus validation.
- Validate with Pydantic locally regardless of provider.
- Retry malformed outputs at most once with a shorter repair prompt.
- Use a model/provider router:
  - Groq for default fast planning.
  - Stronger reasoning provider for complex or low-confidence cases.
  - NoLLM deterministic fallback for CI and offline mode.

About "OpenAI o3 or Claude fallback":

- Do not hard-code `o3` as the long-term answer. OpenAI's current docs mark o3 as succeeded by GPT-5, so use a provider abstraction and configurable model IDs.
- Anthropic model availability also changes quickly. Treat Claude as a configurable provider, not an architecture dependency.
- Name the setting `reasoning_provider` and `reasoning_model`, not `use_o3`.

## Safety Architecture

Modes:

- `safe`: default. Non-destructive proof only. No data extraction. No state-changing exploit unless against a disposable test object created by Wraith.
- `intrusive`: requires explicit operator approval and engagement metadata. Allows controlled state changes and deeper proof.
- `lab`: unrestricted for local vulnerable apps and CTF-style labs only.

Policy engine checks:

- Target URL is in scope.
- Redirects stay in scope unless testing open redirect to a controlled Wraith domain.
- Auth role is allowed.
- HTTP method is allowed.
- Endpoint is not tagged as destructive unless test resource exists.
- Max attempts not exceeded.
- Rate limit not exceeded.
- Response indicates logout, lockout, account risk, or WAF escalation: stop.
- OOB events map to current task correlation ID.

Kill switches:

- Global stop.
- Per-scan cancel.
- Per-host circuit breaker:
  - repeated 429/403/5xx
  - latency spike
  - WAF block page spike
  - session invalidation
  - evidence of target instability

Audit log:

- Who enabled VA+PT.
- Scope.
- Safety mode.
- LLM provider/model.
- Prompt hash and redacted prompt.
- Plan returned.
- Policy decisions.
- Requests sent.
- Evidence captured.
- Cleanup actions.

## Manual Mode: Minimum Feature Set Worth Using

Manual Mode will not beat Burp/Caido by having checkboxes for scanner modules. It becomes useful when it gives a tester fast pivots from Wraith's automated intelligence.

Minimum viable professional Manual Mode:

- Intercept or import traffic:
  - Native proxy or mitmproxy integration.
  - HAR import as a fallback.
- Target map and searchable request history.
- Replay:
  - Editable request.
  - Auth profile injection.
  - Response diff.
- Fuzzer:
  - Payload positions.
  - Payload lists.
  - Rate limits.
  - Response clustering.
- Workflow/sequence editor:
  - Variables extracted from prior responses.
  - Reusable auth and setup steps.
- Auth profile manager:
  - Recorded Playwright sessions.
  - Multi-role switching.
- OOB console:
  - Callback list.
  - Correlation to request/finding/parameter.
- GraphQL client:
  - Introspection import.
  - Operation builder.
  - Variable fuzzing.
- WebSocket client:
  - Message history.
  - Replay/mutate frames.
- Finding notebook:
  - Attach requests/responses/screenshots.
  - Mark false positive.
  - Promote to report finding.
- SAST correlation view:
  - Show route/source/sink next to runtime endpoint.
- Export:
  - PDF/JSON/SARIF/evidence zip.

What would make a pentester prefer Wraith:

- "This finding has runtime proof, source trace, replay request, screenshot, and remediation draft already bundled."
- "I can switch user roles and run IDOR/BOLA comparisons automatically."
- "It finds SPA states Burp/Caido did not crawl unless I drove them manually."
- "It turns an OpenAPI/Postman collection into a tested, reportable workflow quickly."

## Reporting: Professional Post-Exploitation Deliverable

A real pentest report must separate:

- Discovery evidence: what indicated the vulnerability.
- Exploitation/proof evidence: what demonstrated impact.
- Scope and safety: what the tool was allowed to do.
- Business impact: why the client should care.
- Remediation: what engineering should change.

For each exploited finding include:

- Title.
- Severity.
- CVSS score and vector with rationale.
- CWE/OWASP mapping.
- Affected endpoint, parameter, role, and preconditions.
- Discovery method.
- Discovery evidence.
- Exploitation safety mode.
- Exploitation method category.
- Exact proof result:
  - succeeded
  - partially succeeded
  - failed
  - skipped by policy
  - blocked by WAF/session/scope
- Evidence:
  - sanitized request/response excerpts
  - screenshot
  - OOB callback
  - timing samples
  - response diff
  - SAST trace if available
- Data handling note:
  - whether sensitive data was accessed
  - whether data was redacted
  - whether test data was used
- Cleanup performed.
- Remediation.
- Retest steps.

What's missing from the current PDF:

- Clear scope and rules of engagement.
- Auth roles used and coverage per role.
- Coverage metrics.
- Evidence artifact indexing.
- Distinction between scan indicator and exploit proof.
- Retest status.
- False positive / accepted risk workflow.
- Report versioning and reviewer sign-off.
- Redaction policy.
- Professional appendices for raw evidence.
- Better formatting control and removal of encoding artifacts.

## Final Architecture Decision

Build the VA+PT system, but name the first version **Proof Mode**, not "Auto Exploit Mode."

Reason:

- Clients and cautious users will trust "proof mode" more.
- It sets the right engineering constraint: demonstrate exploitability without unnecessary harm.
- It keeps the LLM bounded to planning and explanation.
- It still gives you the compelling report upgrade you want.

Suggested mode design:

- Manual Mode:
  - Workbench for requests, replay, fuzzing, workflows, auth, payloads, OOB, and evidence.
- Automated Mode:
  - VA Only.
  - VA + Proof:
    - Safe default.
    - Intrusive requires explicit approval.
    - Lab unlocks more aggressive payload catalogs for local targets.

The core product thesis should be:

> Wraith does not just find issues. It preserves the path to the issue, proves it safely when allowed, correlates runtime evidence with source evidence, and emits a report a professional can defend.

