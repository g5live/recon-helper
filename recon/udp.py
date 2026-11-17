"""Bounded UDP probes with outcome labels based on observed evidence."""
from __future__ import annotations
import asyncio
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import errno
import ipaddress
import logging
import math
import secrets
import socket
import time
from typing import Literal

from recon.scanner import ProbePacer, expand_targets, resolve_target

LOGGER = logging.getLogger(__name__)
UDP_HINTS = {53: "DNS", 69: "TFTP", 123: "NTP", 161: "SNMP", 500: "IKE"}
UdpStatus = Literal["open", "closed", "open|filtered", "error"]

@dataclass(frozen=True, slots=True)
class UdpFinding:
    port: int
    status: UdpStatus
    service_hint: str
    evidence: str
    response_bytes: int | None = None
    latency_ms: float | None = None

@dataclass(frozen=True, slots=True)
class UdpHost:
    target: str
    address: str | None
    results: tuple[UdpFinding, ...]
    error: str | None
    complete: bool

@dataclass(frozen=True, slots=True)
class UdpReport:
    requested_targets: tuple[str, ...]
    ports: tuple[int, ...]
    started_at: str
    duration_ms: float
    hosts: tuple[UdpHost, ...]
    interrupted: bool
    probe_rate: float | None
    protocol: str = "udp"
    engine: str = "async"

@dataclass(slots=True)
class _Progress:
    target: str
    address: str | None = None
    error: str | None = None
    results: dict[int, UdpFinding] = field(default_factory=dict)
    def snapshot(self, count: int) -> UdpHost:
        return UdpHost(
            self.target, self.address, tuple(self.results[port] for port in sorted(self.results)),
            self.error, self.error is not None or len(self.results) == count,)

def _payload(port: int) -> bytes:
    if port == 53:
        # DNS query: root NS, class IN, one question, recursion not requested.
        return secrets.token_bytes(2) + bytes.fromhex("0000 0001 0000 0000 0000 00 0002 0001")
    return b"\x00"

async def probe_udp(address: str, port: int, timeout: float) -> UdpFinding:
    """Use a connected datagram socket to restrict responses to the selected peer."""
    hint = UDP_HINTS.get(port, "Unknown")
    started = time.perf_counter()
    loop = asyncio.get_running_loop()
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    def finding(status: UdpStatus, evidence: str, response_bytes: int | None = None) -> UdpFinding:
        return UdpFinding(port, status, hint, evidence, response_bytes, round((time.perf_counter() - started) * 1000, 2))
    sent = False
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.setblocking(False)
            async with asyncio.timeout(timeout):
                await loop.sock_connect(connection, (address, port))
                await loop.sock_sendall(connection, _payload(port))
                sent = True
                data = await loop.sock_recv(connection, 65535)
                return finding("open", "datagram received from the selected peer", len(data))
    except TimeoutError:
        if sent:
            return finding("open|filtered", "no reply before timeout; the service may ignore this probe")
        return finding("error", "UDP probe could not be sent before timeout")
    except OSError as error:
        if sent and (isinstance(error, ConnectionRefusedError) or error.errno == errno.ECONNREFUSED):
            return finding("closed", "the OS reported port unreachable/refused")
        return finding("error", f"UDP socket error: {error}")

async def scan_udp(
    targets: list[str] | tuple[str, ...], *,
    ports: tuple[int, ...],
    timeout: float = 0.75,
    concurrency: int = 100,
    max_hosts: int = 256,
    probe_rate: float | None = None,
    preserve_on_cancel: bool = False,
) -> UdpReport:
    if not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("UDP requires explicit integer ports between 1 and 65535")
    if concurrency < 1 or max_hosts < 1:
        raise ValueError("concurrency and max hosts must be at least 1")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("UDP timeout must be finite and greater than zero")
    if probe_rate is not None and (not math.isfinite(probe_rate) or probe_rate <= 0):
        raise ValueError("probe rate must be finite and greater than zero")

    selected = tuple(sorted(set(ports)))
    states = [_Progress(target) for target in expand_targets(targets, max_hosts=max_hosts)]
    started_at = datetime.now(UTC).isoformat()
    started = time.perf_counter()
    pacer = ProbePacer(probe_rate)
    semaphore = asyncio.Semaphore(concurrency)

    async def resolve(state: _Progress) -> None:
        async with semaphore:
            try:
                state.address = await resolve_target(state.target)
            except OSError:
                state.error = "resolution failed"

    # All workers share one iterator; only concurrency probes are in flight.
    async def worker(jobs: Iterator[tuple[_Progress, str, int]]) -> None:
        for state, address, port in jobs:
            await pacer.wait()
            result = await probe_udp(address, port, timeout)
            state.results[port] = result

    interrupted = False
    try:
        await asyncio.gather(*(resolve(state) for state in states))
        count = sum(state.address is not None for state in states) * len(selected)
        jobs = ((state, address, port) for state in states
                if (address := state.address) is not None for port in selected)
        await asyncio.gather(*(worker(jobs) for _ in range(min(concurrency, count))))
    except asyncio.CancelledError:
        if not preserve_on_cancel:
            raise
        interrupted = True
        LOGGER.warning("UDP scan interrupted; preserving observed findings")
    return UdpReport(
        tuple(targets), selected, started_at, round((time.perf_counter() - started) * 1000, 2),
        tuple(state.snapshot(len(selected)) for state in states), interrupted, probe_rate,)
