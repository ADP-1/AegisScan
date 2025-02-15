# AegisScan 🔒

[![CI/CD](https://github.com/yourusername/aegisscan/actions/workflows/main.yml/badge.svg)](https://github.com/yourusername/aegisscan/actions) [![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

A CLI-based web application security analyzer for detecting SQLi, XSS, and CSRF vulnerabilities.

## Features

- 🛡️ Comprehensive vulnerability scanning (SQLi, XSS, CSRF)
- ⚡ Real-time scanning progress and results
- 📊 Multi-format reports (JSON, TXT, HTML)
- 🔄 CI/CD pipeline integration
- 📦 Lightweight and modular architecture

## Installation

### Prerequisites
- Python 3.8+
- Git

### Setup
```bash
# Clone repository
git clone https://github.com/yourusername/aegisscan.git
cd aegisscan

# Initialize virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.\.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Initialize submodules (for security tools)
git submodule update --init --recursive
```

## Usage
```bash
# Basic scan
python security_scanner.py -u https://example.com

# Full scan with all tests
python security_scanner.py -u https://example.com --all

# Custom scan with specific output
python security_scanner.py -u https://example.com --sqlmap --xss --output report.json
```

## Command Line Options
```
  -u URL, --url URL     Target URL to scan
  --depth DEPTH         Scan depth (1-5)
  --sqlmap              Run SQL injection tests
  --xss                 Run XSS tests
  --csrf                Run CSRF tests
  --all                 Run all security tests
  --format {json,txt,html}  Report format
  --output OUTPUT       Output file name
```

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License
MIT License - See [LICENSE](LICENSE) for details 