"""Asynchronous TCP connect scanner engine and worker management."""

from __future__ import annotations

import asyncio
import errno
import logging
import time
from typing import Any, Awaitable, Callable, Iterable, List, Optional, Union

from async_banner_scanner.banner import fingerprint_banner, grab_banner
from async_banner_scanner.models import PortStatus, ScanResult, Target

logger = logging.getLogger(__name__)


def check_fd_limits(concurrency: int) -> int:
    """Validate and log warnings regarding OS file descriptor limits (RLIMIT_NOFILE).

    Args:
        concurrency: The requested number of concurrent scan workers.

    Returns:
        Recommended concurrency after checking system limits.
    """
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        needed = concurrency + 50
        if soft < needed:
            logger.warning(
                f"Operating system file descriptor limit (soft={soft}) may be too low for "
                f"requested concurrency ({concurrency}). Consider increasing with 'ulimit -n {needed}'."
            )
            # If soft limit is strictly less than concurrency, we recommend clamping or warning
            if soft < concurrency:
                adjusted = max(10, soft - 50)
                logger.warning(f"Clamping concurrency to {adjusted} to prevent socket exhaustion.")
                return adjusted
    except (ImportError, AttributeError, ValueError, OSError):
        # Non-POSIX or resource module not available
        pass
    return concurrency


async def scan_target(
    target: Target,
    timeout: float = 1.5,
    grab_banner_flag: bool = True,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> ScanResult:
    """Scan an individual Target (host, port) using asynchronous TCP connect.

    Args:
        target: Target host and port to scan.
        timeout: Socket connection and banner timeout in seconds.
        grab_banner_flag: Whether to perform active banner grabbing on open ports.
        semaphore: Optional asyncio semaphore for concurrency bounding.

    Returns:
        ScanResult populated with port status, latency, and banner info.
    """
    if semaphore is not None:
        async with semaphore:
            return await _execute_tcp_probe(target, timeout, grab_banner_flag)
    return await _execute_tcp_probe(target, timeout, grab_banner_flag)


async def _execute_tcp_probe(
    target: Target,
    timeout: float,
    grab_banner_flag: bool,
) -> ScanResult:
    """Internal implementation of TCP connect and banner extraction."""
    t_start = time.perf_counter()
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None

    try:
        connect_coro = asyncio.open_connection(target.host, target.port)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
        latency_ms = (time.perf_counter() - t_start) * 1000.0
    except (ConnectionRefusedError, ConnectionResetError):
        return ScanResult(
            host=target.host,
            port=target.port,
            status=PortStatus.CLOSED,
            latency_ms=None,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return ScanResult(
            host=target.host,
            port=target.port,
            status=PortStatus.FILTERED,
            latency_ms=None,
        )
    except OSError as err:
        # Check specific OS socket errno codes
        if err.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
            return ScanResult(
                host=target.host,
                port=target.port,
                status=PortStatus.CLOSED,
                latency_ms=None,
            )
        elif err.errno in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            return ScanResult(
                host=target.host,
                port=target.port,
                status=PortStatus.FILTERED,
                latency_ms=None,
            )
        # Any other socket or network level error -> FILTERED
        return ScanResult(
            host=target.host,
            port=target.port,
            status=PortStatus.FILTERED,
            latency_ms=None,
        )

    # Port is OPEN: Proceed to banner grabbing
    banner_raw: Optional[str] = None
    service_name: Optional[str] = "unknown"
    service_version: Optional[str] = None

    try:
        if grab_banner_flag and reader and writer:
            banner_raw, service_name, service_version = await grab_banner(
                reader=reader,
                writer=writer,
                host=target.host,
                port=target.port,
                timeout=timeout,
            )
        else:
            service_name, service_version = fingerprint_banner(None, port=target.port)
    except Exception as err:
        logger.debug(f"Banner grabbing error on {target}: {err}")
        service_name, service_version = fingerprint_banner(None, port=target.port)
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return ScanResult(
        host=target.host,
        port=target.port,
        status=PortStatus.OPEN,
        latency_ms=latency_ms,
        banner_raw=banner_raw,
        service_name=service_name,
        service_version=service_version,
    )


async def run_scanner(
    targets: Iterable[Target],
    concurrency: int = 200,
    timeout: float = 1.5,
    grab_banner: bool = True,
    on_result: Optional[Callable[[ScanResult], Union[None, Awaitable[None]]]] = None,
) -> List[ScanResult]:
    """Execute asynchronous scanning across targets with bounded concurrency.

    Args:
        targets: Iterable of Target objects.
        concurrency: Max concurrent worker tasks.
        timeout: Per-target connection and banner timeout in seconds.
        grab_banner: Flag to enable active service banner extraction.
        on_result: Optional callback invoked immediately whenever a target scan completes.

    Returns:
        List of all ScanResult objects.
    """
    concurrency = check_fd_limits(concurrency)
    semaphore = asyncio.Semaphore(concurrency)
    results: List[ScanResult] = []

    queue: asyncio.Queue[Optional[Target]] = asyncio.Queue(maxsize=concurrency * 2)

    async def worker() -> None:
        while True:
            target = await queue.get()
            if target is None:
                queue.task_done()
                break
            try:
                res = await scan_target(
                    target=target,
                    timeout=timeout,
                    grab_banner_flag=grab_banner,
                    semaphore=semaphore,
                )
                results.append(res)
                if on_result:
                    callback_res = on_result(res)
                    if asyncio.iscoroutine(callback_res):
                        await callback_res
            except Exception as err:
                logger.error(f"Unexpected error scanning {target}: {err}")
            finally:
                queue.task_done()

    # Start worker tasks
    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]

    # Feeder: stream targets into queue
    async def feeder() -> None:
        for t in targets:
            await queue.put(t)
        # Send sentinel None to signal workers to terminate
        for _ in range(concurrency):
            await queue.put(None)

    feeder_task = asyncio.create_task(feeder())

    try:
        await feeder_task
        await queue.join()
        await asyncio.gather(*workers)
    except asyncio.CancelledError:
        feeder_task.cancel()
        for w in workers:
            w.cancel()
        raise

    return results
