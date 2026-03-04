<div align="center">

# 🛡️ Vibe 
**Enterprise-Grade, Asynchronous DAST & SAST Scanning Engine**

[![Python Version](https://img.shields.io/badge/Python-3.9+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Node.js Version](https://img.shields.io/badge/Node.js-16+-green.svg?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

<p align="center">
  A high-performance, comprehensive security assessment framework engineered for ethical hackers, red teams, and modern DevSecOps pipelines.
</p>

</div>

---

## 📖 Table of Contents
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#-usage)
  - [Web Terminal UI](#1-web-terminal-ui-recommended)
  - [Command Line Interface](#2-command-line-interface-cli)
- [Testing Environment](#-testing-environment)
- [Disclaimer](#-responsible-use-disclaimer)
- [License & Author](#-license--author)

---

## 📖 Overview

**Vibe** is an advanced web vulnerability scanner that unifies **Dynamic Application Security Testing (DAST)** and **Static Application Security Testing (SAST)** into a single, highly concurrent platform. 

Moving beyond traditional static HTML scraping, Vibe leverages a headless browser architecture to dynamically map modern Single Page Applications (SPAs) and intercept hidden API routes. Built on the `aiohttp` and `asyncio` libraries, its core engine executes hundreds of non-blocking vulnerability checks simultaneously while strictly respecting target server rate limits.

---

## ✨ Key Features

### 🚀 High-Performance Core Architecture
* **True Asynchronous Engine:** Powered by `aiohttp`, the matrix dispatcher runs concurrent scanning modules bypassing GIL bottlenecks, reducing comprehensive scan times from hours to minutes.
* **SPA-Aware Reconnaissance:** Utilizes `async_playwright` to dynamically execute JavaScript, hydrate modern web frameworks (React, Angular, Vue), and capture background `fetch`/`XHR` API requests.
* **Smart Concurrency & Throttling:** Implements `asyncio.Semaphore` rate-limiting, exponential backoff, and `429/503` retry logic to ensure stability and prevent accidental Denial-of-Service (DoS).
* **Out-of-Band (OAST) Detection:** Natively integrates with `interactsh` to capture blind, asynchronous vulnerabilities (e.g., SSRF, blind SQLi) via DNS/HTTP callbacks.

### 🔍 Dynamic Scanning (DAST)
Proactively detects critical vulnerabilities across 17 specialized modules:
* **Injection Flaws:** Error-based, boolean-blind, and time-based SQLi, Command Injection (CMDi), and XXE.
* **Client-Side Attacks:** Reflected and DOM-based Cross-Site Scripting (XSS).
* **Broken Access Control:** Insecure Direct Object Reference (IDOR) and Path Traversal.
* **Network & Configuration:** Server-Side Request Forgery (SSRF), Open Redirects, CSRF, and Security Header misconfigurations.

### 🛡️ Static Scanning (SAST)
Analyzes remote GitHub repositories for source-code level vulnerabilities:
* **Semgrep Integration:** AST-based static analysis utilizing both community-driven and custom rulesets.
* **Secrets Detection:** High-entropy string analysis to uncover hardcoded credentials, tokens, and API keys.
* **Dependency Auditing:** Interfaces with the OSV API to identify known CVEs in `package.json` and `requirements.txt` files.

### 📊 Professional Reporting
Generates comprehensive, deduplicated PDF reports featuring:
* Executive summaries coupled with **CVSS v3.1** scoring.
* Granular vulnerability distribution metrics and charts.
* Dynamic, context-aware remediation guidelines.
* Direct mapping to the **OWASP Top 10** framework.

---

## 🏗️ Architecture

```mermaid
graph TD
    A[Web Terminal UI / React] -->|WebSocket / HTTP| B(Flask API Server)
    B --> C{AsyncScanEngine}
    C -->|Matrix Dispatch| D[DAST Modules]
    C -->|Subprocess| E[SAST Modules]
    D --> F[Playwright Crawler]
    D --> G[aiohttp Payload Delivery]
    F -->|Maps SPAs & APIs| G
    G -->|Identifies Vulns| H[Reporting Engine]
    E -->|Semgrep / OSV| H
    H --> I((PDF Report))
🚀 Getting Started
Prerequisites
Ensure your system meets the following minimum requirements before installing Vibe:

Python: v3.9 or higher

Node.js: v16 or higher (required for Web Terminal)

npm: v8 or higher

Git: Required for cloning target repositories during SAST scans

Installation
Windows (PowerShell)

# 1. Clone the repository
git clone [https://github.com/harshraj211/vulnerability-scanner.git](https://github.com/harshraj211/vulnerability-scanner.git)
cd vulnerability-scanner

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install Playwright browser binaries
playwright install chromium

# 5. Initialize required directories
mkdir reports

# 6. Install Web Terminal dependencies
cd scanner-terminal
npm install
cd ..

Linux / macOS (Bash)
# Clone the repository
git clone [https://github.com/harshraj211/vulnerability-scanner.git](https://github.com/harshraj211/vulnerability-scanner.git)
cd vulnerability-scanner

# Run the automated install script
chmod +x install.sh
./install.sh
(Alternatively, you can run the Windows steps manually, using source venv/bin/activate to activate the virtual environment.)

💻 Usage
Vibe is designed for flexibility and can be operated via an interactive browser-based Web Terminal or a traditional Command Line Interface.

1. Web Terminal UI (Recommended)
Experience Vibe through a sleek, React-based security console.

Start the Backend API:
# Ensure your virtual environment is active
python api_server.py
# The API will run on http://localhost:5001

Start the Frontend Terminal:
# In a new terminal window
cd scanner-terminal
npm start
# The UI will open at http://localhost:3000

Available Terminal Commands:

scan <url> - Launch an asynchronous DAST scan against a target URL.

scanrepo <github-url> - Clone and execute SAST analysis on a remote repository.

status <scan-id> - Monitor the live progress of an active scan.

report <scan-id> - Download the final PDF vulnerability report.

help - View all available commands.

2. Command Line Interface (CLI)
Ideal for CI/CD integration, automated pipelines, or batch processing.
# Standard DAST Scan
python main.py --url [http://target.com](http://target.com) --output reports/report.pdf

# Aggressive Scan (Higher Concurrency)
python main.py --url [http://target.com](http://target.com) --mode aggressive

# Scan with custom network timeouts (in seconds)
python main.py --url [http://target.com](http://target.com) --timeout 15

🧪 Testing Environment
To safely verify your installation and test Vibe's capabilities, a deliberately vulnerable Python/Flask application is included in the /test_app directory. We strongly recommend running your first scan against this local environment.
# 1. Start the vulnerable application (in terminal 1)
python test_app/vulnerable_app.py

# 2. Launch a scan against the local instance (in terminal 2)
python main.py --url [http://127.0.0.1:5000](http://127.0.0.1:5000) --output reports/local_test.pdf

⚖️ Responsible Use Disclaimer
Vibe is strictly an ethical hacking tool designed exclusively for authorized security assessments and educational purposes.

Authorization Required: You must only scan targets, networks, and applications that you explicitly own or have written, legally binding consent to test.

Legality: Unauthorized vulnerability scanning is a cybercrime in most jurisdictions.

Non-Destructive Design: This tool is designed to identify and report vulnerabilities, not to actively exploit them, maintain persistence, or exfiltrate sensitive data.

The developer assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by the utilization of this program.

👨‍💻 Author
Harsh Raj Cyber Security Student & Developer
