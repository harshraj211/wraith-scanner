# 🔒 Vulnerability Scanner – Multi-Mode Web Security Assessment Tool

A modular, Python-based web vulnerability scanner designed for **ethical security testing**, **labs**, and **CTF environments**.  
This project focuses on **accurate detection**, **controlled validation**, and **professional reporting**, with strict separation between safe scanning and CTF-specific behavior.

---

## 🎯 Core Capabilities

### 🔍 Vulnerability Detection
* **SQL Injection** (error-based & time-based)
* **Cross-Site Scripting** (reflected XSS)
* **IDOR** (Insecure Direct Object Reference)
* **Command Injection** (CMDi)
* **Path Traversal**
* **Open Redirect**
* **CSRF** (token presence & state-change validation)
* **WordPress surface detection**

---

### 🧠 Scanning Engine Design
* Recursive crawler with depth control
* URL & form parameter extraction
* Request rate limiting and throttling
* Validation engine to reduce false positives
* Root-cause-based deduplication
* CVSS score calculation support

---

## 🧪 Multi-Mode Operation (Key Design Feature)

The scanner supports **explicit operating modes** to separate ethical testing from CTF-only behavior.

| Mode | Purpose |
| :--- | :--- |
| `scan` | Safe vulnerability detection only (default) |
| `lab` | Controlled validation for labs & test apps |
| `ctf` | Flag discovery and limited exploitation (CTFs only) |
| `ctf-auth` | Authenticated CTF testing using user-provided credentials |

⚠️ **CTF modes must only be used in legal lab / CTF environments.**

---

### 🚩 Flag Detection (CTF Modes Only)
* Detects common flag formats: `flag{...}`, `HTB{...}`, `picoCTF{...}`
* Read-only detection (no destructive actions)
* Designed to assist, not replace, manual exploitation

---

## 📄 Reporting
* **PDF vulnerability reports**
* Executive summary
* Affected endpoints
* Payload & evidence
* Confidence level
* CVSS scoring
* Findings are grouped by **root cause**, not duplicated per endpoint

---

## 💻 Interfaces

* **CLI interface** (`main.py`)
* **Web terminal UI** (React-based, Kali-style)
* **REST API backend** (`api_server.py`)

---

## 🚀 Installation

### Requirements
* Python 3.9+
* Node.js (for web terminal UI)

### Setup
```bash
git clone https://github.com/harshraj211/vulnerability-scanner.git
cd vulnerability-scanner
mkdir reports (in window powershell)
mkdir -p reports (in linux)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

**Command for Windows/powershell**
🔹 Basic Scan
python main.py --url http://example.com --output test_report.pdf (windows/powershell)

🔹 Scan with Verbose Output
python main.py --url http://example.com --verbose

🔹 Scan with Custom Crawl Depth
python main.py --url http://example.com --depth 3 --output report.pdf

🔹 Scan with Custom Timeout
python main.py --url http://example.com --timeout 20

🔹 CTF Mode
python main.py --url http://ctf-target.com --mode ctf

🔹 Authenticated CTF Mode
python main.py --url http://ctf-target.com --mode ctf-auth --username admin --password admin123

**Command for 🐧 Linux / macOS**

🔹 Basic Scan
python main.py --url http://example.com --output test_report.pdf

🔹 Scan with Verbose Output
python main.py --url http://example.com --verbose

🔹 Scan with Custom Crawl Depth
python main.py --url http://example.com --depth 3 --output report.pdf

🔹 Scan with Custom Timeout
python main.py --url http://example.com --timeout 20

🔹 CTF mode
python main.py --url http://ctf-target.com --mode ctf

🔹 Authenticated CTF mode
python main.py --url http://ctf-target.com --mode ctf-auth --username admin --password admin123





Optional editable install:
pip install -e .

📖 Usage
CLI Mode
python main.py --url http://target.com

Common options:
--depth 3
--timeout 15
--output report.pdf
--verbose

Web Terminal Mode
1. Start API server
python api_server.py

2. Start UI
cd scanner-terminal
npm install
npm start

3. Open: http://localhost:3000
🧪 Testing Environment
A deliberately vulnerable test application is included.

1. Run the app:
python test_app/vulnerable_app.py

2. Scan it:
python main.py --url http://127.0.0.1:5000 --output test_report.pdf

🗂 Project Structure
scanner/
├── core/                # Crawling engine
├── modules/             # Vulnerability scanners
├── reporting/           # PDF report generation
├── utils/
│   ├── mode_manager.py
│   ├── validator.py
│   ├── deduplication.py
│   ├── rate_limiter.py
│   └── cvss_calculator.py
scanner-terminal/        # React web terminal
test_app/                # Vulnerable test application

🔐 Ethics & Responsible Use
          Scan only systems you own or have permission to test.

          Unauthorized scanning is illegal and unethical.

          CTF modes are disabled by default.

          This tool is for learning, labs, and research.

📚 Roadmap
          [ ] Improved confidence scoring model

          [ ] Context-aware severity assessment

          [ ] API endpoint scanning

          [ ] Auth flow simulation (labs only)

          [ ] JSON / SARIF export

          [ ] Advanced false-positive suppression

👨‍💻 Author

Harsh Raj
Cyber Security Student
GitHub: https://github.com/harshraj211



