"""Protocol probing and service banner fingerprinting engine."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Known default ports to fallback service names if banner yields no distinct signature
DEFAULT_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http",
    8080: "http",
    8443: "https",
    8888: "http",
    9200: "elasticsearch",
    27017: "mongodb",
}

# HTTP and TLS ports list for targeted active probing
HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 3000, 5000}
HTTPS_PORTS = {443, 8443, 9443}


def clean_banner_text(raw_bytes: bytes) -> str:
    """Safely decode raw socket bytes to human-readable banner text.

    Args:
        raw_bytes: Raw bytes received from socket.

    Returns:
        Sanitized, decoded string with control codes cleaned.
    """
    # Replace non-decodable bytes
    decoded = raw_bytes.decode("utf-8", errors="replace")
    # Replace null bytes and non-printable control characters, preserving newlines and tabs
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", " ", decoded)
    # Strip excessive surrounding whitespace
    return cleaned.strip()


def fingerprint_banner(
    banner_raw: Optional[str], port: int = 0
) -> Tuple[str, Optional[str]]:
    """Analyze banner text and port to determine service name and software version.

    Args:
        banner_raw: Captured banner string (if any).
        port: Destination port number for contextual heuristic fallback.

    Returns:
        Tuple of (service_name, service_version).
    """
    if not banner_raw:
        service_name = DEFAULT_PORT_SERVICES.get(port, "unknown")
        return service_name, None

    banner_str = banner_raw.strip()

    # 1. SSH Fingerprint: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    ssh_match = re.search(r"SSH-\d\.\d+-([^\r\n]+)", banner_str)
    if ssh_match:
        software = ssh_match.group(1).strip()
        # Take the first token before comment/distribution details (e.g. OpenSSH_8.9p1)
        version = software.split()[0] if software else software
        return "ssh", version

    # 2. HTTP Server Banner or Status Line
    server_header = re.search(r"Server:\s*([^\r\n]+)", banner_str, re.IGNORECASE)
    http_software = re.search(
        r"(Apache|nginx|Microsoft-IIS|lighttpd|Werkzeug|Cloudflare|Caddy|Node\.js|Express)(?:/([\d.]+))?",
        banner_str,
        re.IGNORECASE,
    )
    if server_header:
        srv_val = server_header.group(1).strip()
        return "http", srv_val
    elif http_software:
        vendor = http_software.group(1)
        ver_num = http_software.group(2)
        version_str = f"{vendor}/{ver_num}" if ver_num else vendor
        return "http", version_str
    elif re.search(r"^HTTP/\d\.\d\s+\d{3}", banner_str, re.IGNORECASE):
        # Detected HTTP response line without Server header
        return "http", None

    # 3. FTP Banner: 220 (vsFTPd 3.0.3), 220 ProFTPD 1.3.5 Server
    ftp_match = re.search(
        r"^220[- ].*(vsftpd|ProFTPD|FileZilla|Pure-FTPd|Microsoft FTP Service)[ /]?([\d.]+)?",
        banner_str,
        re.IGNORECASE | re.MULTILINE,
    )
    if ftp_match:
        product = ftp_match.group(1)
        ver = ftp_match.group(2)
        version = f"{product} {ver}".strip() if ver else product
        return "ftp", version
    elif re.search(r"^220[- ].*FTP", banner_str, re.IGNORECASE | re.MULTILINE):
        return "ftp", None

    # 4. SMTP Banner: 220 mail.example.com ESMTP Postfix
    smtp_match = re.search(
        r"^220[- ].*(Postfix|Exim|Sendmail|ESMTP|Microsoft ESMTP MAIL Service)",
        banner_str,
        re.IGNORECASE | re.MULTILINE,
    )
    if smtp_match:
        software = smtp_match.group(1)
        return "smtp", software
    elif re.search(r"^220[- ].*SMTP", banner_str, re.IGNORECASE | re.MULTILINE):
        return "smtp", None

    # 5. MySQL / MariaDB Handshake
    mysql_match = re.search(
        r"([\d.]+-(?:MariaDB|community|[a-zA-Z0-9_.-]+))|mysql_native_password",
        banner_str,
        re.IGNORECASE,
    )
    if mysql_match:
        version = mysql_match.group(1)
        return "mysql", version

    # 6. Redis Response: -ERR, -DENIED, or redis_version:x.x
    redis_match = re.search(
        r"(?:redis_version:([\d.]+)|-ERR|-DENIED|-NOAUTH)",
        banner_str,
        re.IGNORECASE,
    )
    if redis_match:
        version = redis_match.group(1)
        return "redis", version

    # 7. POP3 Banner: +OK Dovecot ready.
    if re.search(r"^\+OK\s+", banner_str):
        pop3_soft = re.search(r"^\+OK\s+([A-Za-z0-9_-]+)", banner_str)
        version = pop3_soft.group(1) if pop3_soft else None
        return "pop3", version

    # 8. IMAP Banner: * OK [CAPABILITY ...] Courier-IMAP
    if re.search(r"^\*\s+OK\s+", banner_str):
        return "imap", None

    # 9. Telnet Prompts / IAC
    if re.search(r"(?:login:|Password:|Telnet|User Access Verification)", banner_str, re.IGNORECASE):
        return "telnet", None

    # Fallback to port-based heuristic if available
    service_name = DEFAULT_PORT_SERVICES.get(port, "unknown")
    return service_name, None


async def _safe_read(reader: asyncio.StreamReader, timeout: float, max_bytes: int = 1024) -> bytes:
    """Read bytes from stream reader within timeout, catching connection reset / EOF."""
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data or b""
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return b""


async def grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    timeout: float = 1.5,
) -> Tuple[Optional[str], str, Optional[str]]:
    """Probes open TCP connection to extract service banner and identify software version.

    Follows a two-stage probing process:
    1. Passive listen (up to timeout/2 or 1.0s) for initial greeting banners (SSH, FTP, SMTP).
    2. Active probing if initial read is empty:
       - HTTP/HTTPS ports: send HEAD / HTTP/1.1 request.
       - Generic ports: send newline triggers or HELP.

    Args:
        reader: Active asyncio StreamReader.
        writer: Active asyncio StreamWriter.
        host: Target hostname or IP.
        port: Target TCP port number.
        timeout: Total timeout allocated for banner grabbing.

    Returns:
        Tuple of (banner_raw, service_name, service_version).
    """
    raw_data = b""

    # Stage 1: Passive Read (services like SSH, FTP, SMTP greet upon connect)
    greeting_ports = {21, 22, 23, 25, 110, 119, 143, 993, 995, 3306}
    passive_timeout = min(timeout, 0.8) if port in greeting_ports else min(timeout, 0.2)
    raw_data = await _safe_read(reader, timeout=passive_timeout, max_bytes=1024)

    # Stage 2: Active Probing if passive greeting was not received
    if not raw_data:
        try:
            if port in HTTP_PORTS or port in HTTPS_PORTS:
                # Active probe: HTTP HEAD request
                http_probe = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 (compatible; AsyncBannerScanner/0.1)\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii", errors="replace")
                writer.write(http_probe)
                await writer.drain()
                raw_data = await _safe_read(reader, timeout=timeout, max_bytes=1024)
            else:
                # Active probe: generic line break trigger
                writer.write(b"\r\n\r\n")
                await writer.drain()
                raw_data = await _safe_read(reader, timeout=min(timeout, 0.3), max_bytes=1024)

                # Secondary generic probe if still empty
                if not raw_data:
                    writer.write(b"HELP\r\n")
                    await writer.drain()
                    raw_data = await _safe_read(reader, timeout=min(timeout, 0.3), max_bytes=1024)

                # Tertiary HTTP probe fallback for web servers on non-standard ports
                if not raw_data:
                    http_probe = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: Mozilla/5.0 (compatible; AsyncBannerScanner/0.1)\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("ascii", errors="replace")
                    writer.write(http_probe)
                    await writer.drain()
                    raw_data = await _safe_read(reader, timeout=min(timeout, 0.5), max_bytes=1024)
        except (ConnectionError, OSError) as err:
            logger.debug(f"Active probe error on {host}:{port}: {err}")

    if not raw_data:
        service_name, version = fingerprint_banner(None, port=port)
        return None, service_name, version

    cleaned = clean_banner_text(raw_data)
    service_name, version = fingerprint_banner(cleaned, port=port)
    return cleaned, service_name, version


# UDP default port mappings
DEFAULT_UDP_PORT_SERVICES = {
    53: "domain",
    67: "bootps",
    68: "bootpc",
    69: "tftp",
    88: "kerberos-sec",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmptrap",
    389: "cldap",
    445: "microsoft-ds",
    500: "isakmp",
    514: "syslog",
    520: "rip",
    631: "ipp",
    1194: "openvpn",
    1434: "ms-sql-m",
    1701: "l2tp",
    1812: "radius",
    1813: "radius-acct",
    1900: "ssdp",
    2049: "nfs",
    3478: "stun",
    4500: "nat-t-ike",
    5060: "sip",
    5353: "mdns",
    5683: "coap",
    11211: "memcached",
}


def get_udp_probe(port: int, host: str = "127.0.0.1") -> bytes:
    """Generate a protocol-specific UDP probe payload for the specified port.

    Args:
        port: Destination UDP port number.
        host: Destination host address.

    Returns:
        Bytes sequence to transmit.
    """
    if port == 53:
        # DNS standard query for google.com (Type A, Class IN)
        return b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
    elif port == 123:
        # NTP client request (NTPv3, client mode 3, 48 bytes)
        return b"\x1b" + (b"\x00" * 47)
    elif port in (161, 162):
        # SNMPv1 GetRequest for sysDescr.0 (community 'public')
        return (
            b"\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x13\x37\x42\x00"
            b"\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01"
            b"\x01\x01\x00\x05\x00"
        )
    elif port == 137:
        # NetBIOS Name Service: Node Status query
        return (
            b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        )
    elif port == 1900:
        # SSDP M-SEARCH discovery probe
        return (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )
    elif port == 5060:
        # SIP OPTIONS ping
        return (
            b"OPTIONS sip:nm@nm SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1337\r\n"
            b"Max-Forwards: 70\r\n"
            b"To: <sip:nm@nm>\r\n"
            b"From: <sip:nm@nm>;tag=1337\r\n"
            b"Call-ID: 1337@nm\r\n"
            b"CSeq: 1 OPTIONS\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
    elif port == 1434:
        # Microsoft SQL Server Browser probe (CLNT_UCAST_EX)
        return b"\x02"
    elif port == 69:
        # TFTP Read Request (RRQ) for test.txt
        return b"\x00\x01test.txt\x00octet\x00"
    elif port == 5353:
        # mDNS query for _services._dns-sd._udp.local
        return (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
        )
    else:
        # Generic UDP trigger
        return b"\r\n\r\n"


def fingerprint_udp_banner(
    data: bytes, port: int = 0
) -> Tuple[Optional[str], str, Optional[str]]:
    """Analyze UDP response data and port to identify service and version details.

    Args:
        data: Raw UDP payload bytes received from host.
        port: Target UDP port number.

    Returns:
        Tuple of (banner_raw, service_name, service_version).
    """
    if not data:
        service_name = DEFAULT_UDP_PORT_SERVICES.get(port, "unknown")
        return None, service_name, None

    # 1. DNS Response (port 53 or 5353)
    if port in (53, 5353) or (len(data) >= 12 and data[:2] == b"\x13\x37"):
        service_name = "mdns" if port == 5353 else "domain"
        flags = int.from_bytes(data[2:4], "big")
        rcode = flags & 0x0F
        rcode_names = {0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain", 5: "Refused"}
        rcode_str = rcode_names.get(rcode, f"RCode={rcode}")
        banner_raw = f"DNS Response ({rcode_str})"
        return banner_raw, service_name, rcode_str

    # 2. NTP Response (port 123 or 48-byte NTP response)
    if port == 123 or (len(data) == 48 and (data[0] & 0x07) == 4):
        version = (data[0] >> 3) & 0x07
        stratum = data[1]
        ver_str = f"NTPv{version} (Stratum {stratum})"
        banner_raw = f"NTP Server Stratum={stratum} Version={version}"
        return banner_raw, "ntp", ver_str

    # 3. SNMP Response (port 161, 162 or ASN.1 sequence starting with 0x30)
    if port in (161, 162) or (data.startswith(b"\x30") and b"public" in data):
        # Extract printable strings inside SNMP response
        all_strings = [
            s.decode("utf-8", errors="ignore")
            for s in re.findall(rb"[\x20-\x7e]{4,}", data)
            if s != b"public"
        ]
        version_str = all_strings[0] if all_strings else None
        banner_raw = f"SNMP Response: {version_str}" if version_str else "SNMP Agent Active"
        return banner_raw, "snmp", version_str

    # 4. NetBIOS Name Service (port 137)
    if port == 137 or (len(data) > 56 and data[2:4] == b"\x84\x00"):
        match = re.search(rb"([A-Za-z0-9_-]{3,15})", data[56:])
        name_str = match.group(1).decode("ascii", errors="ignore") if match else None
        banner_raw = f"NetBIOS Name: {name_str}" if name_str else "NetBIOS-NS Active"
        return banner_raw, "netbios-ns", name_str

    # 5. SSDP / UPnP (port 1900 or HTTP/1.)
    if port == 1900 or data.startswith(b"HTTP/1."):
        cleaned = clean_banner_text(data)
        service, version = fingerprint_banner(cleaned, port=port)
        return cleaned, "ssdp" if service == "unknown" else service, version

    # 6. SIP (port 5060 or starts with SIP/2.0)
    if port == 5060 or data.startswith(b"SIP/2.0"):
        cleaned = clean_banner_text(data)
        srv_match = re.search(r"(?:Server|User-Agent):\s*([^\r\n]+)", cleaned, re.IGNORECASE)
        ver = srv_match.group(1).strip() if srv_match else None
        return cleaned, "sip", ver

    # 7. MSSQL Browser (port 1434)
    if port == 1434 and data.startswith(b"\x05"):
        cleaned = clean_banner_text(data[3:])
        ver_match = re.search(r"Version;([0-9.]+)", cleaned, re.IGNORECASE)
        ver = ver_match.group(1) if ver_match else None
        return cleaned, "ms-sql-m", ver

    # 8. TFTP (port 69)
    if port == 69 and len(data) >= 4 and data[:2] == b"\x00\x05":
        err_msg = clean_banner_text(data[4:])
        return f"TFTP Error: {err_msg}", "tftp", None

    # Fallback to general text decoding and fingerprinting
    cleaned = clean_banner_text(data)
    service_name = DEFAULT_UDP_PORT_SERVICES.get(port, "unknown")
    if cleaned:
        fp_serv, fp_ver = fingerprint_banner(cleaned, port=port)
        if fp_serv != "unknown":
            service_name = fp_serv
        return cleaned, service_name, fp_ver

    return None, service_name, None
