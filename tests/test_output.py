"""Unit tests for output exporters and console reporting."""

import csv
import json
import os
import tempfile
from io import StringIO

from rich.console import Console

from async_banner_scanner.models import PortStatus, ScanResult
from async_banner_scanner.output import (
    create_progress_bar,
    export_csv,
    export_json,
    print_results_table,
)


def sample_results():
    return [
        ScanResult(
            host="192.168.1.10",
            port=22,
            status=PortStatus.OPEN,
            latency_ms=1.45,
            banner_raw="SSH-2.0-OpenSSH_8.9p1",
            service_name="ssh",
            service_version="OpenSSH_8.9p1",
        ),
        ScanResult(
            host="192.168.1.10",
            port=80,
            status=PortStatus.OPEN,
            latency_ms=2.10,
            banner_raw="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
            service_name="http",
            service_version="nginx/1.18.0",
        ),
        ScanResult(
            host="192.168.1.10",
            port=445,
            status=PortStatus.CLOSED,
            latency_ms=None,
            banner_raw=None,
            service_name="microsoft-ds",
            service_version=None,
        ),
        ScanResult(
            host="192.168.1.10",
            port=8080,
            status=PortStatus.FILTERED,
            latency_ms=None,
            banner_raw=None,
            service_name="http",
            service_version=None,
        ),
    ]


def test_export_json():
    results = sample_results()
    with tempfile.TemporaryDirectory() as td:
        file_path = os.path.join(td, "sub", "output.json")
        export_json(results, file_path)
        assert os.path.exists(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data) == 4
        assert data[0]["host"] == "192.168.1.10"
        assert data[0]["port"] == 22
        assert data[0]["status"] == "OPEN"
        assert data[0]["latency_ms"] == 1.45
        assert data[0]["service_name"] == "ssh"
        assert data[0]["service_version"] == "OpenSSH_8.9p1"


def test_export_csv():
    results = sample_results()
    with tempfile.TemporaryDirectory() as td:
        file_path = os.path.join(td, "sub", "output.csv")
        export_csv(results, file_path)
        assert os.path.exists(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 4
        assert rows[0]["host"] == "192.168.1.10"
        assert rows[0]["port"] == "22"
        assert rows[0]["status"] == "OPEN"
        assert rows[0]["service_name"] == "ssh"
        assert rows[2]["status"] == "CLOSED"


def test_print_results_table_open_only():
    results = sample_results()
    buf = StringIO()
    console = Console(file=buf, no_color=True, width=120)
    print_results_table(results, console=console, show_all=False, duration_sec=1.2)
    output = buf.getvalue()
    assert "Scan Results" in output
    assert "192.168.1.10" in output
    assert "22" in output
    assert "80" in output
    assert "Open: 2" in output
    assert "Closed: 1" in output
    assert "Filtered: 1" in output


def test_print_results_table_show_all():
    results = sample_results()
    buf = StringIO()
    console = Console(file=buf, no_color=True, width=120)
    print_results_table(results, console=console, show_all=True, duration_sec=0.5)
    output = buf.getvalue()
    assert "Scan Results" in output
    assert "CLOSED" in output
    assert "FILTERED" in output


def test_print_results_table_empty():
    buf = StringIO()
    console = Console(file=buf, no_color=True, width=120)
    print_results_table([], console=console, show_all=False, duration_sec=0.1)
    output = buf.getvalue()
    assert "No open ports discovered" in output


def test_create_progress_bar():
    progress = create_progress_bar()
    assert progress is not None
