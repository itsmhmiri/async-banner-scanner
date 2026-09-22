"""Unit and integration tests for UDP scanning and banner grabbing."""

import asyncio
import socket
from typing import Optional

import pytest

from async_banner_scanner.banner import (
    fingerprint_udp_banner,
    get_udp_probe,
)
from async_banner_scanner.cli import build_parser, main
from async_banner_scanner.models import PortStatus, Target, TransportProtocol
from async_banner_scanner.scanner import scan_target
from async_banner_scanner.target_parser import generate_targets, parse_ports


def test_udp_probe_generation():
    """Verify protocol-specific UDP probes are generated accurately."""
    p_dns = get_udp_probe(53)
    assert b"google" in p_dns
    assert p_dns.startswith(b"\x13\x37")

    p_ntp = get_udp_probe(123)
    assert len(p_ntp) == 48
    assert p_ntp[0] == 0x1B

    p_snmp = get_udp_probe(161)
    assert b"public" in p_snmp

    p_netbios = get_udp_probe(137)
    assert b"CKAAAAA" in p_netbios

    p_ssdp = get_udp_probe(1900)
    assert b"M-SEARCH * HTTP/1.1" in p_ssdp

    p_sip = get_udp_probe(5060)
    assert b"OPTIONS sip:" in p_sip

    p_mssql = get_udp_probe(1434)
    assert p_mssql == b"\x02"

    p_tftp = get_udp_probe(69)
    assert b"octet" in p_tftp

    p_mdns = get_udp_probe(5353)
    assert b"_dns-sd" in p_mdns

    p_generic = get_udp_probe(9999)
    assert p_generic == b"\r\n\r\n"


def test_fingerprint_udp_dns():
    """Verify DNS response parsing and classification."""
    # Standard DNS response with NoError (flags = 0x8180)
    dns_resp = b"\x13\x37\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00"
    banner, service, ver = fingerprint_udp_banner(dns_resp, port=53)
    assert "DNS Response" in banner
    assert service == "domain"
    assert ver == "NoError"


def test_fingerprint_udp_ntp():
    """Verify NTP response parsing and classification."""
    # NTPv4 response, server mode 4, stratum 2
    ntp_resp = bytearray(48)
    ntp_resp[0] = 0x24  # LI=0, VN=4, Mode=4
    ntp_resp[1] = 2     # Stratum 2
    banner, service, ver = fingerprint_udp_banner(bytes(ntp_resp), port=123)
    assert "NTP" in banner
    assert service == "ntp"
    assert "NTPv4" in ver
    assert "Stratum 2" in ver


def test_fingerprint_udp_snmp():
    """Verify SNMP response parsing."""
    snmp_resp = (
        b"\x30\x29\x02\x01\x00\x04\x06public\xa2\x1c\x02\x04\x13\x37\x42\x00"
        b"\x04\x0aLinux 5.15"
    )
    banner, service, ver = fingerprint_udp_banner(snmp_resp, port=161)
    assert service == "snmp"
    assert "Linux 5.15" in banner


def test_fingerprint_udp_netbios():
    """Verify NetBIOS response parsing."""
    nb_resp = bytearray(80)
    nb_resp[2:4] = b"\x84\x00"
    nb_resp[56:66] = b"WORKGROUP "
    banner, service, ver = fingerprint_udp_banner(bytes(nb_resp), port=137)
    assert service == "netbios-ns"
    assert "WORKGROUP" in banner


def test_fingerprint_udp_sip():
    """Verify SIP response parsing."""
    sip_resp = b"SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.0\r\n\r\n"
    banner, service, ver = fingerprint_udp_banner(sip_resp, port=5060)
    assert service == "sip"
    assert ver == "Asterisk PBX 18.0"


def test_fingerprint_udp_empty():
    """Verify handling of empty UDP payload."""
    banner, service, ver = fingerprint_udp_banner(b"", port=53)
    assert banner is None
    assert service == "domain"
    assert ver is None


class MockDNSDatagramProtocol(asyncio.DatagramProtocol):
    """Echo DNS response on incoming datagram."""

    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Respond with DNS NoError response echoing transaction ID
        tx_id = data[:2] if len(data) >= 2 else b"\x13\x37"
        resp = tx_id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00"
        self.transport.sendto(resp, addr)


@pytest.mark.asyncio
async def test_scan_mock_udp_dns(monkeypatch):
    """Integration test: scan mock DNS server over UDP."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MockDNSDatagramProtocol(),
        local_addr=("127.0.0.1", 0),
    )
    port = transport.get_extra_info("sockname")[1]

    # Direct probe to send DNS query payload
    monkeypatch.setattr("async_banner_scanner.scanner.get_udp_probe", lambda p, host="127.0.0.1": get_udp_probe(53))

    try:
        target = Target(host="127.0.0.1", port=port, protocol=TransportProtocol.UDP)
        res = await scan_target(target, timeout=1.0, grab_banner_flag=True)

        assert res.status == PortStatus.OPEN
        assert res.protocol == TransportProtocol.UDP
        assert res.port == port
        assert res.latency_ms is not None
        assert res.latency_ms > 0
        assert "DNS Response" in (res.banner_raw or "")
        assert res.service_name == "domain"
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_scan_udp_closed_port():
    """Integration test: scan closed UDP port on localhost."""
    # Find unused port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    free_port = sock.getsockname()[1]
    sock.close()

    target = Target(host="127.0.0.1", port=free_port, protocol=TransportProtocol.UDP)
    res = await scan_target(target, timeout=0.3, grab_banner_flag=True)

    # On Linux loopback, ICMP port unreachable returns CLOSED immediately
    assert res.status in (PortStatus.CLOSED, PortStatus.OPEN_FILTERED)
    assert res.protocol == TransportProtocol.UDP


def test_cli_parser_udp_options():
    """Test CLI parsing with -u and --protocol."""
    parser = build_parser()

    args_u = parser.parse_args(["-t", "127.0.0.1", "-u"])
    assert args_u.udp is True
    assert args_u.protocol is None

    args_proto_udp = parser.parse_args(["-t", "127.0.0.1", "--protocol", "udp"])
    assert args_proto_udp.protocol == "udp"

    args_proto_all = parser.parse_args(["-t", "127.0.0.1", "--protocol", "all"])
    assert args_proto_all.protocol == "all"


def test_target_parser_udp_top_ports():
    """Verify target parser defaults to TOP_100_UDP_PORTS for UDP."""
    ports_udp = parse_ports(ports_spec=None, top_ports=None, protocol=TransportProtocol.UDP)
    assert len(ports_udp) == 100
    assert 53 in ports_udp
    assert 123 in ports_udp
    assert 161 in ports_udp

    targets_all = list(
        generate_targets(
            target_spec="127.0.0.1",
            ports_spec="53,80",
            protocols=(TransportProtocol.TCP, TransportProtocol.UDP),
        )
    )
    assert len(targets_all) == 4
    protocols = {t.protocol for t in targets_all}
    assert protocols == {TransportProtocol.TCP, TransportProtocol.UDP}


def test_cli_execution_udp():
    """Test CLI execution scanning UDP target."""
    ret = main(["-t", "127.0.0.1", "-p", "53", "-u", "-c", "1", "--timeout", "0.3"])
    assert ret == 0


def test_cli_execution_protocol_all():
    """Test CLI execution scanning both TCP and UDP targets."""
    ret = main(["-t", "127.0.0.1", "-p", "53", "--protocol", "all", "-c", "1", "--timeout", "0.3"])
    assert ret == 0
