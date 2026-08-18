# Web Recon Scanner

Automated web reconnaissance tool for authorized VAPT and security assessment.

The scanner performs reconnaissance against a target and collects information such as:

- Target and URL information
- HTTP/HTTPS availability
- HTTP response information
- Security headers
- Web technologies
- Subdomains
- Open ports and services
- Homepage information
- JavaScript files
- Basic JavaScript pattern analysis
- Common sensitive files
- Potential security findings
- JSON and HTML reports

> **Important:** Use this scanner only against systems you own or have explicit permission to assess.

---

## 1. Requirements

### Operating System

The scanner is currently designed and tested for:

- Windows
- VS Code
- Python 3.x

Linux/Kali support can be added later.

---

## 2. Python Requirements

Create and activate a virtual environment.

### Create virtual environment

```cmd
python -m venv venv