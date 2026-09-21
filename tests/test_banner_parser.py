"""Unit tests for banner cleaning and regex fingerprint identification."""

import pytest

from async_banner_scanner.banner import (
    clean_banner_text,
    fingerprint_banner,
)


def test_clean_banner_text():
    raw = b"SSH-2.0-OpenSSH_8.9p1\x00\x01\x1b[2J\r\n"
    cleaned = clean_banner_text(raw)
    assert "\x00" not in cleaned
    assert "SSH-2.0-OpenSSH_8.9p1" in cleaned


def test_fingerprint_ssh():
    banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    service, version = fingerprint_banner(banner, port=22)
    assert service == "ssh"
    assert version == "OpenSSH_8.9p1"

    banner_dropbear = "SSH-2.0-dropbear_2020.81"
    service, version = fingerprint_banner(banner_dropbear, port=2222)
    assert service == "ssh"
    assert version == "dropbear_2020.81"


def test_fingerprint_http_server_header():
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html"
    service, version = fingerprint_banner(banner, port=80)
    assert service == "http"
    assert version == "nginx/1.18.0"


def test_fingerprint_http_apache():
    banner = "HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
    service, version = fingerprint_banner(banner, port=8080)
    assert service == "http"
    assert version == "Apache/2.4.52 (Ubuntu)"


def test_fingerprint_http_status_line_only():
    banner = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    service, version = fingerprint_banner(banner, port=80)
    assert service == "http"


def test_fingerprint_ftp():
    banner = "220 (vsFTPd 3.0.3)\r\n"
    service, version = fingerprint_banner(banner, port=21)
    assert service == "ftp"
    assert version == "vsFTPd 3.0.3"

    banner_proftpd = "220 ProFTPD 1.3.5 Server (ProFTPD Default Installation)\r\n"
    service, version = fingerprint_banner(banner_proftpd, port=21)
    assert service == "ftp"
    assert "ProFTPD" in (version or "")


def test_fingerprint_smtp():
    banner = "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
    service, version = fingerprint_banner(banner, port=25)
    assert service == "smtp"
    assert version == "Postfix"


def test_fingerprint_mysql():
    banner = "5.7.33-0ubuntu0.16.04.1\x00\x00\x00\n\x00\x00\x00mysql_native_password"
    service, version = fingerprint_banner(banner, port=3306)
    assert service == "mysql"
    assert "5.7.33" in (version or "")

    banner_mariadb = "10.5.12-MariaDB-1:10.5.12+maria~focal"
    service, version = fingerprint_banner(banner_mariadb, port=3306)
    assert service == "mysql"
    assert "MariaDB" in (version or "")


def test_fingerprint_redis():
    banner_denied = "-DENIED Authentication required."
    service, version = fingerprint_banner(banner_denied, port=6379)
    assert service == "redis"

    banner_ver = "# Server\r\nredis_version:6.2.6\r\nredis_git_sha1:00000000\r\n"
    service, version = fingerprint_banner(banner_ver, port=6379)
    assert service == "redis"
    assert version == "6.2.6"


def test_fingerprint_telnet():
    banner = "Debian GNU/Linux 11\r\nlogin: "
    service, version = fingerprint_banner(banner, port=23)
    assert service == "telnet"


def test_fingerprint_fallback_by_port():
    service, version = fingerprint_banner(None, port=443)
    assert service == "https"
    assert version is None

    service, version = fingerprint_banner(None, port=22)
    assert service == "ssh"

    service, version = fingerprint_banner(None, port=99999)
    assert service == "unknown"
