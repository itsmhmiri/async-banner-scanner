"""Unit and functional tests for CLI arguments and execution entrypoint."""

import os
import tempfile
import pytest

from async_banner_scanner.cli import build_parser, main


def test_cli_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["-t", "192.168.1.1"])

    assert args.target == "192.168.1.1"
    assert args.ports is None
    assert args.top_ports is None
    assert args.concurrency == 200
    assert args.timeout == 1.5
    assert args.grab_banner is True
    assert args.output_json is None
    assert args.output_csv is None
    assert args.verbose is False


def test_cli_parser_custom_options():
    parser = build_parser()
    args = parser.parse_args([
        "-t", "10.0.0.0/24",
        "-p", "80,443",
        "-c", "50",
        "--timeout", "3.0",
        "--no-banner",
        "-oJ", "scan.json",
        "-oC", "scan.csv",
        "-v",
    ])

    assert args.target == "10.0.0.0/24"
    assert args.ports == "80,443"
    assert args.concurrency == 50
    assert args.timeout == 3.0
    assert args.grab_banner is False
    assert args.output_json == "scan.json"
    assert args.output_csv == "scan.csv"
    assert args.verbose is True


def test_cli_parser_top_ports():
    parser = build_parser()
    args = parser.parse_args(["-t", "127.0.0.1", "--top-ports", "1000"])
    assert args.top_ports == 1000


def test_cli_parser_missing_target():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["-p", "80"])


def test_cli_execution_invalid_port():
    code = main(["-t", "127.0.0.1", "-p", "invalid-port"])
    assert code == 1


def test_cli_execution_unresolvable():
    code = main(["-t", "nonexistent-domain-xyz-404.local", "-p", "80"])
    assert code == 1


def test_cli_execution_success():
    with tempfile.TemporaryDirectory() as td:
        json_out = os.path.join(td, "results.json")
        csv_out = os.path.join(td, "results.csv")

        # Scan a single localhost port that finishes quickly
        code = main([
            "-t", "127.0.0.1",
            "-p", "1",
            "-c", "1",
            "--timeout", "0.2",
            "-oJ", json_out,
            "-oC", csv_out,
        ])

        assert code == 0
        assert os.path.exists(json_out)
        assert os.path.exists(csv_out)
