"""Structured CIDR expansion, resolution, and bounded TCP scanning."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import ipaddress
import logging
import socket
import time
from urllib.parse import urlsplit

from recon.protocols import (
    TCP_SERVICES,
    probe_payload,
    readable_banner,
    service_name,
    socket_probe,
)

LOGGER = logging.getLogger(__name__)


class TargetError(ValueError):
    """Target input is empty, invalid, or exceeds a deliberate safety limit."""


@dataclass(frozen=True, slots=True)
class PortFinding:
    port: int
    service: str
    latency_ms: float
    banner: str | None = None


@dataclass(frozen=True, slots=True)
class HostScan:
    target: str
    address: str | None
    open_ports: tuple[PortFinding, ...]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ScanReport:
    requested_targets: tuple[str, ...]
    engine: str
    ports: tuple[int, ...]
    started_at: str
    duration_ms: float
    hosts: tuple[HostScan, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def normalise_target(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise TargetError("target cannot be empty")
    if "://" in candidate:
        hostname = urlsplit(candidate).hostname
        if not hostname:
            raise TargetError(f"no hostname found in target: {value!r}")
        return hostname
    return candidate.rstrip("/")


def expand_targets(values: list[str] | tuple[str, ...], max_hosts: int = 256) -> tuple[str, ...]:
    expanded: list[str] = []
    seen: set[str] = set()
    for raw in values:
        candidate = raw.strip()
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            targets = (normalise_target(candidate),)
        else:
            targets = tuple(str(address) for address in network.hosts())
            if network.num_addresses == 1:
                targets = (str(network.network_address),)

        for target in targets:
            if target not in seen:
                seen.add(target)
                expanded.append(target)
            if len(expanded) > max_hosts:
                raise TargetError(
                    f"target exceeds --max-hosts={max_hosts}; narrow the CIDR or raise the limit deliberately"
                )
    if not expanded:
        raise TargetError("no usable targets supplied")
    return tuple(expanded)


async def resolve_target(target: str) -> str:
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    results = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    addresses = [entry[4][0] for entry in results]
    if not addresses:
        raise socket.gaierror(f"no address returned for {target}")
    return next((address for address in addresses if ":" not in address), addresses[0])


async def _async_probe(
    target: str,
    address: str,
    port: int,
    timeout: float,
    banner_timeout: float,
) -> tuple[float, str | None]:
    started = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
    latency_ms = (time.perf_counter() - started) * 1000
    try:
        payload = probe_payload(port, target)
        if payload:
            writer.write(payload)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), banner_timeout)
        except TimeoutError:
            data = b""
        return latency_ms, readable_banner(data)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def scan_port(
    target: str,
    address: str,
    port: int,
    *,
    engine: str,
    timeout: float,
    banner_timeout: float,
    semaphore: asyncio.Semaphore,
) -> PortFinding | None:
    async with semaphore:
        try:
            if engine == "async":
                latency_ms, banner = await _async_probe(target, address, port, timeout, banner_timeout)
            elif engine == "socket":
                latency_ms, banner = await asyncio.to_thread(
                    socket_probe, address, target, port, timeout, banner_timeout
                )
            else:
                raise ValueError(f"unsupported engine: {engine}")
        except (ConnectionError, OSError, TimeoutError):
            LOGGER.debug("closed or filtered: %s:%s", address, port)
            return None

    LOGGER.info("open: %s (%s) %s/tcp", target, address, port)
    return PortFinding(port, service_name(port), round(latency_ms, 2), banner)


async def scan_host(
    target: str,
    ports: tuple[int, ...],
    *,
    engine: str,
    timeout: float,
    banner_timeout: float,
    semaphore: asyncio.Semaphore,
) -> HostScan:
    try:
        address = await resolve_target(target)
    except socket.gaierror as error:
        LOGGER.warning("could not resolve %s: %s", target, error)
        return HostScan(target, None, (), "resolution failed")

    findings = await asyncio.gather(
        *(scan_port(
            target,
            address,
            port,
            engine=engine,
            timeout=timeout,
            banner_timeout=banner_timeout,
            semaphore=semaphore,
        ) for port in ports)
    )
    open_ports = tuple(sorted((finding for finding in findings if finding), key=lambda item: item.port))
    return HostScan(target, address, open_ports)


async def scan(
    targets: list[str] | tuple[str, ...],
    *,
    ports: tuple[int, ...] = tuple(TCP_SERVICES),
    engine: str = "async",
    timeout: float = 0.75,
    banner_timeout: float = 0.35,
    concurrency: int = 100,
    max_hosts: int = 256,
) -> ScanReport:
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if timeout <= 0 or banner_timeout <= 0:
        raise ValueError("timeouts must be greater than zero")

    expanded = expand_targets(targets, max_hosts=max_hosts)
    clean_ports = tuple(sorted(set(ports)))
    if not clean_ports or any(port < 1 or port > 65535 for port in clean_ports):
        raise ValueError("ports must be between 1 and 65535")

    LOGGER.info("starting %s scan: %s target(s), %s port(s)", engine, len(expanded), len(clean_ports))
    started_at = datetime.now(UTC).isoformat()
    started = time.perf_counter()
    semaphore = asyncio.Semaphore(concurrency)
    hosts = await asyncio.gather(
        *(scan_host(
            target,
            clean_ports,
            engine=engine,
            timeout=timeout,
            banner_timeout=banner_timeout,
            semaphore=semaphore,
        ) for target in expanded)
    )
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    LOGGER.info("scan complete in %.2f ms", duration_ms)
    return ScanReport(tuple(targets), engine, clean_ports, started_at, duration_ms, tuple(hosts))
