"""Unit tests for target, CIDR, hostname, and port specification parsing."""

import os
import tempfile
import pytest

from async_banner_scanner.models import Target
from async_banner_scanner.target_parser import (
    TOP_100_PORTS,
    TOP_1000_PORTS,
    generate_targets,
    parse_ports,
    parse_targets,
)


def test_parse_ports_single():
    assert parse_ports("80") == [80]


def test_parse_ports_list():
    assert parse_ports("21,22,80,443") == [21, 22, 80, 443]


def test_parse_ports_range():
    assert parse_ports("80-82") == [80, 81, 82]


def test_parse_ports_combined():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]


def test_parse_ports_deduplication():
    assert parse_ports("80,80-82,81") == [80, 81, 82]


def test_parse_ports_default():
    # If no spec or top_ports is given, default to top 100 ports
    ports = parse_ports(None, None)
    assert len(ports) == 100
    assert 80 in ports
    assert 443 in ports
    assert 22 in ports


def test_parse_ports_top_100():
    ports = parse_ports(top_ports=100)
    assert ports == sorted(list(set(TOP_100_PORTS)))
    assert len(ports) == 100


def test_parse_ports_top_1000():
    ports = parse_ports(top_ports=1000)
    assert len(ports) == 1000
    assert 80 in ports


def test_parse_ports_invalid_top_ports():
    with pytest.raises(ValueError, match="Invalid --top-ports value"):
        parse_ports(top_ports=50)


def test_parse_ports_invalid_syntax():
    with pytest.raises(ValueError):
        parse_ports("abc")
    with pytest.raises(ValueError):
        parse_ports("80-abc")
    with pytest.raises(ValueError):
        parse_ports("80-")


def test_parse_ports_out_of_bounds():
    with pytest.raises(ValueError, match="out of bounds"):
        parse_ports("0")
    with pytest.raises(ValueError, match="out of bounds"):
        parse_ports("70000")
    with pytest.raises(ValueError, match="out of bounds"):
        parse_ports("100-70000")


def test_parse_ports_inverted_range():
    with pytest.raises(ValueError, match="start.*must be <= end"):
        parse_ports("100-80")


def test_parse_targets_single_ipv4():
    targets = list(parse_targets("192.168.1.10"))
    assert targets == ["192.168.1.10"]


def test_parse_targets_single_ipv6():
    targets = list(parse_targets("::1"))
    assert targets == ["::1"]


def test_parse_targets_cidr_expansion_slash30():
    # /30 network must yield exactly 4 IP addresses
    targets = list(parse_targets("192.168.1.0/30"))
    assert targets == ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_parse_targets_cidr_slash32():
    targets = list(parse_targets("10.0.0.1/32"))
    assert targets == ["10.0.0.1"]


def test_parse_targets_comma_separated():
    targets = list(parse_targets("192.168.1.1, 192.168.1.2"))
    assert targets == ["192.168.1.1", "192.168.1.2"]


def test_parse_targets_file():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("# Comment line\n")
        f.write("192.168.1.1\n")
        f.write("\n")
        f.write("10.0.0.0/31\n")
        file_path = f.name

    try:
        targets = list(parse_targets(file_path))
        assert targets == ["192.168.1.1", "10.0.0.0", "10.0.0.1"]
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


def test_parse_targets_hostname_resolution():
    targets = list(parse_targets("localhost"))
    assert "127.0.0.1" in targets or "::1" in targets


def test_parse_targets_unresolvable_hostname():
    targets = list(parse_targets("nonexistent-domain-xyz-404.local"))
    assert targets == []


def test_generate_targets_iterator():
    targets = list(generate_targets("192.168.1.0/31", ports_spec="80,443"))
    assert len(targets) == 4
    assert Target("192.168.1.0", 80) in targets
    assert Target("192.168.1.0", 443) in targets
    assert Target("192.168.1.1", 80) in targets
    assert Target("192.168.1.1", 443) in targets
