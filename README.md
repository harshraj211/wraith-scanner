This README is designed to present your scanner as a mature, production-ready tool. It emphasizes the specific architectural upgrades we've implemented (like the true asynchronous engine and SPA reconnaissance) which set it apart from basic student projects.

Markdown
<div align="center">

# 🛡️ Vibe - Web Vulnerability Scanner

**An Enterprise-Grade, Asynchronous DAST & SAST Scanning Engine**

[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Node.js 16+](https://img.shields.io/badge/Node.js-16+-green.svg?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Cross-Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

<p align="center">
  A high-performance security assessment framework built for ethical hackers, red teams, and DevSecOps pipelines. 
</p>

</div>

---

## 📖 Overview

Vibe is a comprehensive web vulnerability scanner that combines **Dynamic Application Security Testing (DAST)** and **Static Application Security Testing (SAST)** into a single, highly concurrent framework. 

Moving beyond traditional static HTML scraping, Vibe utilizes a headless browser architecture to dynamically map Single Page Applications (SPAs) and intercept hidden API routes. Its core engine is built on `aiohttp` and `asyncio`, allowing it to execute hundreds of non-blocking vulnerability checks simultaneously while respecting server rate limits.

---

## ✨ Key Features

### 🚀 Core Architecture
* **True Asynchronous Engine:** Powered by `aiohttp`, the matrix dispatcher runs concurrent scanning modules without GIL bottlenecks, reducing scan times from hours to minutes.
* **SPA-Aware Reconnaissance:** Utilizes `async_playwright` to execute JavaScript, hydrate modern frameworks (React, Angular, Vue), and intercept background `fetch`/`XHR` API requests.
* **Smart Concurrency:** Implements `asyncio.Semaphore` rate-limiting, exponential backoff, and `429/503` retry logic to prevent accidental Denial-of-Service (DoS) on target servers.
* **Out-of-Band (OAST) Detection:** Integrates with `interactsh` to catch blind, asynchronous vulnerabilities like SSRF and blind SQLi via DNS/HTTP callbacks.

### 🔍 DAST Modules (Dynamic Scanning)
Detects critical vulnerabilities across 17 distinct modules:
* **Injection:** Error-based, boolean-blind, and time-based SQLi, Command Injection (CMDi), and XXE.
* **Client-Side:** Reflected and DOM-based Cross-Site Scripting (XSS).
* **Access Control:** Insecure Direct Object Reference (IDOR) and Path Traversal.
* **Network & Config:** Server-Side Request Forgery (SSRF), Open Redirects, CSRF, and Security Header disclosures.

### 🛡️ SAST Modules (Static Scanning)
Scans GitHub repositories for source-code vulnerabilities:
* **Semgrep Integration:** AST-based static analysis utilizing community and custom rulesets.
* **Secrets Detection:** High-entropy string analysis for hardcoded credentials and API keys.
* **Dependency Auditing:** Queries the OSV API to identify known CVEs in `package.json` and `requirements.txt`.

### 📊 Professional Reporting
Generates comprehensive, deduplicated PDF reports featuring:
* Executive summaries with CVSS v3.1 scoring.
* Granular vulnerability distribution metrics.
* Dynamic, context-aware remediation steps.
* Mapping to the OWASP Top 10 framework.

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
🛠️ Prerequisites
Python: v3.9 or higher

Node.js: v16 or higher (for the Web Terminal)

npm: v8 or higher

Git: For cloning repositories during SAST scans

🚀 Installation
Windows (PowerShell)
PowerShell
# 1. Clone the repository
git clone [https://github.com/harshraj211/vulnerability-scanner.git](https://github.com/harshraj211/vulnerability-scanner.git)
cd vulnerability-scanner

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install Playwright browsers
playwright install chromium

# 5. Initialize directories
mkdir reports

# 6. Install Web Terminal dependencies
cd scanner-terminal
npm install
cd ..
Linux / macOS
Bash
# Clone the repository
git clone [https://github.com/harshraj211/vulnerability-scanner.git](https://github.com/harshraj211/vulnerability-scanner.git)
cd vulnerability-scanner

# Run the automated install script
chmod +x install.sh
./install.sh
(Alternatively, you can run the Windows steps manually, using source venv/bin/activate for the virtual environment.)

💻 Usage
Vibe can be operated via a traditional CLI or through an interactive, browser-based Web Terminal.

1. The Web Terminal (Recommended)
Experience the tool through a sleek, React-based hacking console.

Start the Backend API:

Bash
# Ensure your virtual environment is active
python api_server.py
# Runs on http://localhost:5001
Start the Frontend Terminal:

Bash
# In a new terminal window
cd scanner-terminal
npm start
# Opens at http://localhost:3000
Terminal Commands:

scan <url> - Launch an asynchronous DAST scan against a target URL.

scanrepo <github-url> - Clone and run SAST analysis on a repository.

status <scan-id> - Check the live progress of an active scan.

report <scan-id> - Download the final PDF vulnerability report.

help - View all available commands.

2. Command Line Interface (CLI)
Run scans directly from your terminal for easy CI/CD integration or batch processing.

Bash
# Standard DAST Scan
python main.py --url [http://target.com](http://target.com) --output reports/report.pdf

# Aggressive Scan (Higher Concurrency)
python main.py --url [http://target.com](http://target.com) --mode aggressive

# Scan with custom network timeouts
python main.py --url [http://target.com](http://target.com) --timeout 15
🧪 Testing Environment
A deliberately vulnerable Python/Flask application is included in the /test_app directory. We strongly recommend testing the scanner against this application first to verify your installation.

Bash
# 1. Start the vulnerable application
python test_app/vulnerable_app.py

# 2. Launch a scan against the local instance
python main.py --url [http://127.0.0.1:5000](http://127.0.0.1:5000) --output reports/local_test.pdf
⚖️ Responsible Use Disclaimer
Vibe is an ethical hacking tool designed exclusively for authorized security assessments.

Authorization Required: You must only scan targets, networks, and applications that you explicitly own or have written consent to test.

Legality: Unauthorized vulnerability scanning is illegal.

Non-Destructive: This tool is designed to identify vulnerabilities, not to actively exploit them or exfiltrate sensitive data.

The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

👨‍💻 Author
Harsh Raj Cyber Security Student
