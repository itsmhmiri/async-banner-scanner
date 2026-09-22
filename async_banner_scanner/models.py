"""Data models and type definitions for Async Banner Scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional
import datetime


class TransportProtocol(str, Enum):
    """Network transport layer protocol."""

    TCP = "tcp"
    UDP = "udp"


class PortStatus(str, Enum):
    """Network port scan outcome status."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"  # Connection timed out or host/network unreachable
    OPEN_FILTERED = "OPEN|FILTERED"  # Common in UDP when no response or ICMP error is received


@dataclass(frozen=True)
class Target:
    """Individual scan destination defined by host address, port, and transport protocol."""

    host: str
    port: int
    protocol: TransportProtocol = TransportProtocol.TCP

    def __str__(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol.value}"


@dataclass
class ScanResult:
    """Structured result of a single host and port scan probing attempt."""

    host: str
    port: int
    status: PortStatus
    protocol: TransportProtocol = TransportProtocol.TCP
    latency_ms: Optional[float] = None
    banner_raw: Optional[str] = None
    service_name: Optional[str] = "unknown"
    service_version: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize scan result to a dictionary suitable for JSON / tabular exports."""
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol.value,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "banner_raw": self.banner_raw.strip() if self.banner_raw else None,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "timestamp": self.timestamp,
        }
