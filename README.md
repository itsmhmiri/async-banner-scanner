# Async Banner Scanner

**High-Performance Asynchronous Network Port and Service Banner Scanner**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`async-banner-scanner` is a lightweight, high-concurrency network reconnaissance tool written in Python. It executes fast asynchronous TCP Connect scans across CIDR subnets, IP lists, and hostnames, and actively probes open ports to identify services and extract software version banners (e.g., `OpenSSH_8.9p1`, `Apache/2.4.52`, `vsftpd 3.0.3`).

---

## Features

- **Asynchronous Concurrency:** Built on Python's native `asyncio` event loop with `asyncio.Semaphore` rate-limiting to prevent operating system socket exhaustion (`EMFILE`).
- **Target Specification:** Supports single IP addresses, hostnames, CIDR blocks (e.g., `192.168.1.0/24`), and target list files (`-iL`).
- **Flexible Port Selection:** Supports custom port ranges (e.g., `1-1024`), comma-separated lists, and built-in top port presets (`--top-ports 100` / `1000`).
- **Banner Grabbing & Fingerprinting:**
  - Passive reading of initial service greetings (SSH, FTP, SMTP).
  - Active protocol probing for web services (HTTP `HEAD /`) and generic network listeners.
  - Regex pattern matching to extract service names and version numbers.
- **Structured Reporting:** Real-time console output via `rich`, with JSON (`--json`) and CSV (`--csv`) export formats.
- **Robust Error Handling:** Resilient against socket timeouts, firewall packet drops (tarpits), connection resets, and non-UTF-8 binary responses.

---

## Architecture

```
+-------------------------------------------------------------+
|                      CLI & Target Parser                    |
|                (Argparse / Rich Progress UI)                |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                 Target Iterator / Job Queue                 |
|             (CIDR Expansion & Port List Generator)          |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                     Concurrency Limiter                     |
|                   (asyncio.Semaphore)                       |
+------------------------------+------------------------------+
                               |
            +------------------+------------------+
            v                                     v
+-----------------------+             +-----------------------+
|  Worker: TCP Connect  |             |  Worker: TCP Connect  |
|  (asyncio.open_conn)  |             |  (asyncio.open_conn)  |
+-----------+-----------+             +-----------+-----------+
            | (If OPEN)                           | (If OPEN)
            v                                     v
+-----------------------+             +-----------------------+
| Protocol Probe Engine |             | Protocol Probe Engine |
|   (Banner Grabbing)   |             |   (Banner Grabbing)   |
+-----------+-----------+             +-----------+-----------+
            |                                     |
            +------------------+------------------+
                               |
                               v
+-------------------------------------------------------------+
|                  Regex Fingerprint Parser                   |
|              (Matches Service Strings & Versions)           |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                 Output Formatter & Exporters                |
|                  (Console / JSON / CSV)                     |
+-------------------------------------------------------------+
```

---

## Project Structure

```
async-banner-scanner/
├── pyproject.toml              # Build configuration and project metadata
├── requirements.txt            # Runtime dependencies
├── requirements-dev.txt        # Development and testing dependencies
├── README.md                   # Project documentation
├── async_banner_scanner/       # Core package
│   ├── __init__.py             # Package version
│   ├── __main__.py             # Entrypoint (`python -m async_banner_scanner`)
│   ├── cli.py                  # CLI arguments and flags
│   ├── models.py               # Data models (Target, ScanResult, PortStatus)
│   ├── target_parser.py        # CIDR and port range parsing
│   ├── scanner.py              # Async TCP connection engine
│   ├── banner.py               # Banner grabbing and fingerprinting
│   └── output.py               # Console (Rich), JSON, and CSV formatters
└── tests/                      # Test suite
    ├── __init__.py
    ├── test_target_parser.py
    ├── test_banner_parser.py
    └── test_scanner_mock.py
```

---

## Setup & Installation

### Requirements
- Python 3.10 or higher

### Development Setup

1. **Activate virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   pip install -e .
   ```

---

## Usage (CLI Preview)

```bash
# Scan a single host for top 100 ports
async-banner-scanner -t 192.168.1.10 --top-ports 100

# Scan a subnet for specific ports with concurrency limit of 300
async-banner-scanner -t 192.168.1.0/24 -p 21,22,80,443 -c 300

# Export scan results to JSON and CSV
async-banner-scanner -t targets.txt -p 1-1024 -oJ results.json -oC results.csv
```

---

## Legal & Ethical Disclaimer

> [!WARNING]
> This tool is intended for authorized penetration testing, security auditing, and educational use only. Scanning networks without explicit authorization from the target owner may violate applicable laws. The authors assume no liability for misuse.
