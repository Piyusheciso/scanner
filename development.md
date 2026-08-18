# Web Recon Scanner — Developer Guide

## 1. Overview

Web Recon Scanner is a modular Python-based reconnaissance framework designed for authorized VAPT assessments.

The project separates:

- CLI/orchestration
- Target validation
- HTTP reconnaissance
- External tool execution
- Homepage and JavaScript discovery
- JavaScript analysis
- Sensitive file checks
- Finding generation
- Report generation

The scanner is designed so that new functionality can be added as separate modules without putting all logic inside `scanner.py`.

---

# 2. Development Principles

The project follows these principles:

1. Keep `scanner.py` as the orchestrator.
2. Keep individual scanner functionality inside `modules/`.
3. Keep report generation inside `reporting/`.
4. Return structured data from modules.
5. Avoid printing inside low-level modules unless required.
6. Handle external-tool failures gracefully.
7. Do not terminate the entire scan because one step fails.
8. Keep report data JSON-compatible.
9. Keep each step independently testable.
10. Keep future development modular.

---

# 3. Project Structure

Current project structure:

```text
Scanner/
│
├── scanner.py
├── config.py
├── requirements.txt
├── README.md
├── DEVELOPMENT.md
│
├── modules/
│   ├── __init__.py
│   │
│   ├── target.py
│   ├── http_recon.py
│   │
│   ├── whatweb.py
│   ├── subdomains.py
│   ├── nmap_scan.py
│   │
│   ├── homepage.py
│   ├── javascript.py
│   │
│   ├── js_analysis.py
│   ├── sensitive_files.py
│   │
│   └── findings.py
│
├── reporting/
│   ├── __init__.py
│   ├── json_report.py
│   └── html_report.py
│
├── logs/
│   └── scanner.log
│
├── output/
│   └── <target>/
│
└── venv/