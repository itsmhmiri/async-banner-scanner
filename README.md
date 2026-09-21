# Async Banner Scanner

A fast and lightweight TCP port scanner and service banner grabber written in Python. 

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

---

# اسکنر ناهمگام پورت و بنر سرویس‌ها (Async Banner Scanner)

یک ابزار سریع، سبک و ناهمگام (Asynchronous) برای اسکن پورت‌های TCP و استخراج بنر سرویس‌های شبکه که با پایتون پیاده‌سازی شده است.

این ابزار با تمرکز بر سرعت و کارایی در مراحل شناسایی شبکه و ارزیابی‌های امنیتی طراحی شده است. **Async Banner Scanner** با بهره‌گیری از کتابخانه داخلی `asyncio` در پایتون، توانایی اسکن هم‌زمان آدرس‌های تکی، رنج‌های شبکه‌ای CIDR، نام دامنه‌ها یا فایل‌های حاوی لیستی از اهداف را دارد؛ بدون اینکه سیستم میزبان را با کمبود سوکت یا فایل دیسکریپتور مواجه کند. علاوه بر تشخیص باز یا بسته بودن پورت، این ابزار با پورت‌های باز تعامل برقرار کرده و بنر سرویس‌ها (نظیر OpenSSH، Apache، Nginx، vsFTPd، Redis، MySQL و...) را دریافت کرده و نسخه آن‌ها را شناسایی می‌کند.

---

### امکانات و قابلیت‌ها

- **اسکن هم‌زمان و پرسرعت**: استفاده از استریم‌های `asyncio` و کنترل هم‌زمانی از طریق Semaphore (`-c / --concurrency`) برای اسکن سریع هزاران پورت بدون ایجاد فشار نامتعارف روی سوکت‌های سیستم‌عامل.
- **پشتیبانی کامل و منعطف از اهداف**:
  - آدرس‌های IPv4 و IPv6 به‌صورت تکی (`192.168.1.10` و `::1`)
  - بلاک‌های شبکه بر پایه CIDR (مانند `192.168.1.0/24` یا `10.0.0.0/28`)
  - نام دامنه‌ها و هاست‌نیم‌ها (`scanme.nmap.org` یا `localhost`)
  - فایل متنی حاوی اهداف مختلف (`-t targets.txt`)
- **انتخاب متنوع پورت‌ها**:
  - لیست جدا شده با کاما (`21,22,80,443`)
  - محدوده‌های عددی (`1-1024` یا `8000-8080`)
  - پریست‌های آماده از پرکاربردترین پورت‌ها (`--top-ports 100` یا `--top-ports 1000`)
  - انتخاب خودکار ۱۰۰ پورت پرکاربرد در صورت عدم تعیین پورت
- **استخراج هوشمند بنر و انگشت‌نگاری (Fingerprinting)**:
  - **دریافت پسیو**: گرفتن سریع پیام خوش‌آمدگویی سرویس‌ها پس از برقراری اتصال (SSH, FTP, SMTP, POP3).
  - **پروب‌های اکتیو**: ارسال درخواست‌های وب (`HEAD / HTTP/1.1`) به سرویس‌های وب و ارسال کاراکترهای خط فرمان (`\r\n`, `HELP`) به سایر سرویس‌ها.
  - **تشخیص سرویس و نسخه**: شناسایی نام نرم‌افزار و نسخه آن با الگوهای Regex.
- **رابط کاربری زیبا در ترمینال**: نمایش زنده نوار پیشرفت، جدول رنگی با جزئیات وضعیت پورت‌ها (باز، بسته، فیلترشده)، تاخیر اتصال به میلی‌ثانیه و خلاصه نهایی اسکن با کتابخانه Rich.
- **خروجی ساختاریافته**: امکان ذخیره مستقیم گزارش‌ها در دو قالب پرکاربرد **JSON** (`-oJ results.json`) و **CSV** (`-oC results.csv`).

---

### استک فنی

- **پایتون نسخه 3.10 به بالا**
- **کتابخانه‌های استاندارد**: `asyncio`, `socket`, `ipaddress`, `argparse`, `re`, `json`, `csv`
- **رابط کاربری ترمینال**: کتابخانه [`rich`](https://github.com/Textualize/rich) برای رسم جداول زیبا و نوار پیشرفت
- **تست‌ها**: `pytest`, `pytest-asyncio`

---

### راهنمای شروع به کار

#### ۱. کلون کردن مخزن
```bash
git clone https://github.com/itsmhmiri/async-banner-scanner.git
cd async-banner-scanner
```

#### ۲. ساخت و فعال‌سازی محیط مجازی
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### ۳. نصب نیازمندی‌ها
```bash
pip install -e .
```

جهت نصب ابزارهای مربوط به تست و توسعه:
```bash
pip install -e ".[dev]"
```

---

### نحوه استفاده و مثال‌های کاربردی

پس از نصب، می‌توانید از دستور `async-scanner` یا اجرای ماژول پایتون `python -m async_banner_scanner` استفاده کنید.

#### اسکن سریع ۱۰۰ پورت پرکاربرد
```bash
async-scanner -t 192.168.1.1
```

#### اسکن پورت‌های مشخص به همراه دریافت بنر
```bash
async-scanner -t 192.168.1.50 -p 21,22,80,443,3306,8080
```

#### اسکن یک ساب‌نت روی ۱۰۰۰ پورت برتر با هم‌زمانی و تایم‌اوت سفارشی
```bash
async-scanner -t 10.0.0.0/24 --top-ports 1000 -c 300 --timeout 1.0
```

#### اسکن اهداف از روی فایل متنی و دریافت خروجی JSON و CSV
```bash
async-scanner -t targets.txt -p 80,443,8080 -oJ output.json -oC output.csv
```

#### اسکن سریع بدون دریافت بنر (صرفاً بررسی باز بودن پورت‌ها)
```bash
async-scanner -t 192.168.1.1 -p 1-1024 --no-banner
```

#### اجرای حالت پرجزئیات (نمایش پورت‌های بسته و فیلترشده)
```bash
async-scanner -t scanme.nmap.org -p 20-25 -v
```

---

### راهنمای پارامترهای خط فرمان (CLI Options)

| گزینه | توضیحات | پیش‌فرض |
|-------|---------|---------|
| `-t`, `--target` | آدرس آی‌پی، رنج CIDR (مانند `192.168.1.0/24`)، دامنه یا مسیر فایل اهداف | *(اجباری)* |
| `-p`, `--ports` | لیست پورت‌ها (مانند `80,443`) یا بازه پورت‌ها (`1-1024`) | ۱۰۰ پورت برتر |
| `--top-ports` | اسکن N پورت پرکاربرد (`100` یا `1000`) | `100` |
| `-c`, `--concurrency` | حداکثر تعداد درخواست‌های هم‌زمان در صف | `200` |
| `--timeout` | حداکثر زمان انتظار برای برقراری اتصال و پاسخ برحسب ثانیه | `1.5` |
| `--no-banner` | صرف‌نظر از دریافت بنر سرویس‌ها (اسکن سریع‌تر) | غیرفعال (بنر دریافت می‌شود) |
| `-oJ`, `--json` | ذخیره نتایج اسکن در قالب فایل JSON | ندارد |
| `-oC`, `--csv` | ذخیره نتایج اسکن در قالب فایل CSV | ندارد |
| `-v`, `--verbose` | لاگ کامل تشخیصی و نمایش تمام پورت‌های بسته و فیلترشده در جدول | False |
| `-V`, `--version` | نمایش نسخه برنامه و خروج | - |

---

### اجرای تست‌های خودکار

برای اجرای کامل تست‌های واحد و یکپارچه‌سازی (به همراه شبیه‌ساز سرورهای سوکت داخلی):

```bash
pytest -v
```
