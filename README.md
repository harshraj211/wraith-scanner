<div align="center">
  
# WRAITH v4
### The Open-Source Enterprise Application Security Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/React-19+-61DAFB.svg)](https://reactjs.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**A full-stack, DevSecOps-ready SAST/DAST vulnerability scanner designed to rival commercial platforms like Burp Suite Enterprise and Snyk.**

</div>

---

## 🚀 Overview
Wraith is not just a script—it is a distributed microservices architecture built for modern AppSec teams. It bridges the gap between automated CI/CD security gates and deep, manual pentesting workbenches. 

From Cloud IaC misconfigurations and Entropy-based secret detection to Boolean-based SQLi exploitation and HTTPS MITM interception, Wraith provides end-to-end vulnerability management.

## 🏗️ Architecture
Wraith runs as a simple local Flask API plus React frontend for demos and single-machine usage.

| Component | Technology | Description |
|-----------|------------|-------------|
| **Frontend** | React 19, TailwindCSS | Burp-style workbench, executive dashboards, real-time scan progress. |
| **API Gateway** | Flask, Pydantic | Schema validation, optional API-key auth, and local rate limiting. |
| **Scan Engine** | Python, aiohttp, Playwright | Async DAST engine, DOM rendering, WAF fingerprinting, deterministic exploitation. |
| **SAST Engine** | Semgrep, Custom Taint | AST analysis, Shannon entropy secret detection, IaC/K8s manifest scanning. |
| **Storage** | SQLite | Local scan state, corpus, findings, and report artifacts. |

## 🛡️ Core Capabilities

### 1. Advanced DAST Engine (Dynamic Testing)
- **WAF Fingerprinting & Evasion:** Automatically detects Cloudflare/AWS WAF and mutates payloads using context-aware encoding (JSON vs URL) and inline comments to bypass regex filters.
- **Deterministic Proof Engine:** Doesn't just guess vulnerabilities—it proves them. Uses Boolean-based `1=1` vs `1=2` logic to extract database versions, guaranteeing zero false positives for SQLi.
- **Modern API Coverage:** Native scanners for gRPC reflection, GraphQL DoS (Batching/Depth), and Cloud Metadata SSRF (169.254.x.x).
- **Business Logic Flaws:** Automated detection of Mass Assignment (privilege escalation) and HTTP Parameter Pollution (HPP).

### 2. Deep SAST & SCA (Static Testing)
- **Beyond Regex:** Uses Shannon Entropy analysis to detect high-randomness hardcoded secrets (JWTs, custom API keys) that standard regex misses.
- **Lockfile SCA:** Parses `package-lock.json`, `poetry.lock`, and `go.sum` to map exact transitive dependency trees for CVE matching.
- **Infrastructure as Code (IaC):** Scans Terraform and Kubernetes manifests for insecure defaults (e.g., public S3 buckets, privileged containers).

### 3. The Manual Workbench (Burp Suite Alternative)
- **True HTTPS Interception:** Built on `mitmproxy`, Wraith dynamically generates local CA certificates to decrypt and log TLS traffic to the database.
- **Repeater & Intruder:** Replay requests with modified headers/payloads, with built-in diffing to compare baseline vs. malicious responses.

### 4. Enterprise DevSecOps Integration
- **CI/CD CLI:** A standalone CLI tool that runs scans in GitHub Actions/Jenkins, failing the pipeline (exit code 1) if HIGH/CRITICAL findings are discovered.
- **SARIF v2.1.0 Compliant:** Generates fully compliant SARIF reports with `partialFingerprints` for direct integration into the GitHub Security tab.
- **Ticketing Automation:** Automatically pushes triaged findings to Jira (creating formatted bug tickets) and sends color-coded Slack alerts for CRITICAL vulnerabilities.

## ⚙️ Quick Start (Local)

Wraith does not require Docker, Redis, or PostgreSQL for the local demo setup.

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/wraith-scanner.git
cd wraith-scanner

# 2. Install backend dependencies
pip install -r requirements.txt

# 3. Start the API
python api_server.py

# 4. Start the frontend in another terminal
cd scanner-terminal
npm install
npm start

# Frontend UI: http://localhost:3000
# API Server: http://localhost:5001/api/overview
```

## 🔒 Security & Self-Defense
Wraith is built to be safely exposed to the internet:
- **SSRF Immunity:** Middleware resolves all domains to IP addresses and blocks requests to RFC 1918 private networks and Cloud Metadata endpoints, preventing the scanner from being used as a proxy.
- **Multi-Tenancy & RBAC:** API keys are scoped to specific organizations (`tenant_id`). A user from Org A cannot query findings for Org B.
- **Memory Hardening:** The async HTTP client streams responses in chunks and strictly enforces a 10MB limit to prevent OOM crashes when scanning targets that host large media files.

## 🧪 DevSecOps Pipeline (GitHub Actions)

Add Wraith to your CI/CD pipeline to block vulnerable code from merging:

```yaml
# .github/workflows/wraith-devsecops.yml
name: Wraith Security Scan
on: [pull_request]

jobs:
  wraith-sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Wraith SAST (Fail on High)
        run: |
          pip install -r requirements.txt
          python cli.py --target . --mode SAST --output-format sarif --output-file wraith.sarif --fail-on HIGH
      - name: Upload to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: wraith.sarif
```

## 📈 The Tech Stack
- **Backend:** Python 3.11, Flask, aiohttp, Pydantic
- **Frontend:** React 19, TailwindCSS, Socket.IO
- **Security Tools:** Semgrep, Nuclei, Playwright
- **Database:** SQLite

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<div align="center">
  <sub>Built with ❤️ by Harsh. Designed to secure the modern web.</sub>
</div>
