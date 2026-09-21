# Async Banner Scanner

A fast and lightweight TCP port scanner and service banner grabber written in Python. 

<p align="center">
  <img src="assets/scanner-demo.gif" alt="Async Banner Scanner Demonstration" width="850">
</p>

Built with network reconnaissance and security assessments in mind, **Async Banner Scanner** scans single IP addresses, CIDR network ranges, hostnames, or target lists from a file concurrently using Python's native `asyncio`. Beyond simply detecting open ports, it probes responsive services to grab protocol banners (such as OpenSSH, Apache, Nginx, vsFTPd, Redis, MySQL, and more) and extract software versions.

---

### Features

- **High-Concurrency Scanning**: Uses `asyncio` streams and semaphore throttling (`-c / --concurrency`) to scan thousands of ports rapidly without exhausting operating system file descriptors or sockets.
- **Flexible Target Input**:
  - Single IPv4 and IPv6 addresses (`192.168.1.10`, `::1`)
  - CIDR network blocks (e.g., `192.168.1.0/24`, `10.0.0.0/28`)
  - Hostnames / FQDNs (e.g., `scanme.nmap.org`, `localhost`)
  - Target files containing mixed IPs, hostnames, and CIDRs (`-t targets.txt`)
- **Versatile Port Selection**:
  - Comma-separated lists (`21,22,80,443`)
  - Port ranges (`1-1024`, `8000-8080`)
  - Predefined top ports presets (`--top-ports 100` or `--top-ports 1000`)
  - Defaults to top 100 common ports if omitted
- **Smart Banner Grabbing & Fingerprinting**:
  - **Passive Listen**: Catches immediate service greetings (SSH, FTP, SMTP, POP3).
  - **Active Probing**: Sends targeted HTTP probes (`HEAD / HTTP/1.1`) to web services and text commands (`\r\n`, `HELP`) to generic ports.
  - **Regex Fingerprints**: Automatically parses and matches service names and software versions.
- **Rich Terminal UI**: Displays real-time progress bars, color-coded status tables (Open, Closed, Filtered), latency measurements in milliseconds, and a scan summary.
- **Structured Data Export**: Export results cleanly to **JSON** (`-oJ results.json`) and **CSV** (`-oC results.csv`).

---

### Tech Stack

- **Python 3.10+**
- **Core Standard Library**: `asyncio`, `socket`, `ipaddress`, `argparse`, `re`, `json`, `csv`
- **Terminal UI**: [`rich`](https://github.com/Textualize/rich) for formatted tables, styled colors, and progress tracking
- **Testing**: `pytest`, `pytest-asyncio`

---

### Getting Started

#### 1. Clone the repository
```bash
git clone https://github.com/itsmhmiri/async-banner-scanner.git
cd async-banner-scanner
```

#### 2. Create and activate a virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install dependencies
```bash
pip install -e .
```

For development and running tests, install test dependencies:
```bash
pip install -e ".[dev]"
```

---

### Usage & Examples

Once installed, you can run the tool using `async-scanner` or via `python -m async_banner_scanner`.

#### Basic scan on top 100 ports
```bash
async-scanner -t 192.168.1.1
```

#### Scan specific ports with banner grabbing
```bash
async-scanner -t 192.168.1.50 -p 21,22,80,443,3306,8080
```

#### Scan a CIDR subnet on top 1000 ports with custom concurrency
```bash
async-scanner -t 10.0.0.0/24 --top-ports 1000 -c 300 --timeout 1.0
```

#### Scan targets from a file and export to JSON & CSV
```bash
async-scanner -t targets.txt -p 80,443,8080 -oJ output.json -oC output.csv
```

#### Fast port-only scan (skip active banner grabbing)
```bash
async-scanner -t 192.168.1.1 -p 1-1024 --no-banner
```

#### Verbose mode (show closed and filtered ports too)
```bash
async-scanner -t scanme.nmap.org -p 20-25 -v
```

---

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target IP, CIDR (e.g. `192.168.1.0/24`), hostname, or file path | *(Required)* |
| `-p`, `--ports` | Port list (e.g. `80,443`) or range (`1-1024`) | Top 100 ports |
| `--top-ports` | Scan top N common ports (`100` or `1000`) | `100` |
| `-c`, `--concurrency` | Maximum concurrent asynchronous worker tasks | `200` |
| `--timeout` | Connection and probe timeout in seconds | `1.5` |
| `--no-banner` | Skip banner extraction (fast port-only scan) | Enabled |
| `-oJ`, `--json` | Export scan results to JSON file | None |
| `-oC`, `--csv` | Export scan results to CSV file | None |
| `-v`, `--verbose` | Enable verbose diagnostic logging and display all port statuses | False |
| `-V`, `--version` | Show program version and exit | - |

---

### Running Tests

To run the automated unit and integration tests (including local mock socket tests):

```bash
pytest -v
```


