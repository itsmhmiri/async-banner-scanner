"""Integration and mock network tests for asynchronous scanner and banner engine."""

import asyncio
import pytest

from async_banner_scanner.models import PortStatus, Target
from async_banner_scanner.scanner import run_scanner, scan_target


@pytest.fixture
async def mock_ftp_server():
    """Start an ephemeral mock FTP server that yields a 220 banner upon connection."""
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        writer.write(b"220 (vsFTPd 3.0.3)\r\n")
        await writer.drain()
        # Keep connection open briefly then close
        await asyncio.sleep(0.1)
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield ("127.0.0.1", port)

    server.close()
    await server.wait_closed()


@pytest.fixture
async def mock_http_server():
    """Start an ephemeral mock HTTP server responding to HEAD requests."""
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        while True:
            data = await reader.read(1024)
            if not data:
                break
            if b"HEAD" in data or b"GET" in data:
                writer.write(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                break
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield ("127.0.0.1", port)

    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_scan_mock_ftp(mock_ftp_server):
    host, port = mock_ftp_server
    target = Target(host, port)

    result = await scan_target(target, timeout=1.0, grab_banner_flag=True)

    assert result.status == PortStatus.OPEN
    assert result.latency_ms is not None
    assert result.latency_ms > 0
    assert result.service_name == "ftp"
    assert result.service_version == "vsFTPd 3.0.3"
    assert "vsFTPd 3.0.3" in (result.banner_raw or "")


@pytest.mark.asyncio
async def test_scan_mock_http(mock_http_server):
    host, port = mock_http_server
    target = Target(host, port)

    result = await scan_target(target, timeout=1.0, grab_banner_flag=True)

    assert result.status == PortStatus.OPEN
    assert result.latency_ms is not None
    assert result.service_name == "http"
    assert "Apache/2.4.52" in (result.service_version or "")


@pytest.mark.asyncio
async def test_scan_no_banner(mock_ftp_server):
    host, port = mock_ftp_server
    target = Target(host, port)

    result = await scan_target(target, timeout=1.0, grab_banner_flag=False)

    assert result.status == PortStatus.OPEN
    assert result.banner_raw is None


@pytest.mark.asyncio
async def test_scan_closed_port():
    # An ephemeral port that was opened and immediately closed
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    closed_port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    result = await scan_target(Target("127.0.0.1", closed_port), timeout=0.3)
    assert result.status == PortStatus.CLOSED
    assert result.latency_ms is None


@pytest.mark.asyncio
async def test_run_scanner_batch(mock_ftp_server):
    host, open_port = mock_ftp_server

    # Pick a port guaranteed to be closed
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    closed_port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    targets = [
        Target(host, open_port),
        Target(host, closed_port),
    ]

    callback_results = []
    results = await run_scanner(
        targets=targets,
        concurrency=10,
        timeout=1.0,
        grab_banner=True,
        on_result=lambda r: callback_results.append(r),
    )

    assert len(results) == 2
    assert len(callback_results) == 2

    statuses = {r.port: r.status for r in results}
    assert statuses[open_port] == PortStatus.OPEN
    assert statuses[closed_port] == PortStatus.CLOSED
