"""Structured CIDR expansion, resolution, and bounded TCP scanning."""
from __future__ import annotations
import asyncio
import ipaddress
import logging
import math
import socket
import time
from requests import RequestException
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from collections.abc import Callable
from urllib.parse import urlsplit
from recon.web import WebFinding, inspect_url
from recon.protocols import TCP_SERVICES, detect_banner_service, probe_payload, readable_banner, service_name, socket_probe, web_url
from recon.tls import TLSFinding, inspect_tls
from typing import Literal
LOGGER = logging.getLogger(__name__)

class TargetError(ValueError):
    """Target input is empty, invalid, or exceeds a deliberate safety limit."""

@dataclass(frozen=True, slots=True)
class PortFinding:
    port: int
    service: str
    latency_ms: float
    banner: str | None = None
    url: str | None = None
    web: WebFinding | None = None
    detected_service: str | None = None
    tls: TLSFinding | None = None
    inspection_complete: bool = True

@dataclass(frozen=True, slots=True)
class TcpAttempt:
    port: int
    outcome: Literal["open", "refused", "timeout", "error"]
    evidence: str

@dataclass(frozen=True, slots=True)
class HostScan:
    target: str
    address: str | None
    open_ports: tuple[PortFinding, ...]
    error: str | None = None
    checked_ports: tuple[int, ...] = ()
    complete: bool = True
    tcp_attempts: tuple[TcpAttempt, ...] = ()

@dataclass(frozen=True, slots=True)
class ScanReport:
    requested_targets: tuple[str, ...]
    engine: str
    ports: tuple[int, ...]
    started_at: str
    duration_ms: float
    hosts: tuple[HostScan, ...]
    interrupted: bool = False
    probe_rate: float | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

class ProbePacer:
    """Space TCP probe dispatches globally; do not accumulate burst credits."""
    def __init__(self, rate: float | None):
        self.interval = 1.0 / rate if rate is not None else 0.0
        self.next_start = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        if not self.interval:
            return
        async with self.lock:
            loop = asyncio.get_running_loop()
            delay = self.next_start - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self.next_start = loop.time() + self.interval

@dataclass(slots=True)
class HostProgress:
    target: str
    address: str | None = None
    findings: dict[int, PortFinding] = field(default_factory=dict)
    checked: set[int] = field(default_factory=set)
    error: str | None = None
    complete: bool = False
    attempts: dict[int, TcpAttempt] = field(default_factory=dict)

    def snapshot(self) -> HostScan:
        return HostScan(
            self.target,
            self.address,
            tuple(self.findings[port] for port in sorted(self.findings)),
            self.error,
            tuple(sorted(self.checked)),
            self.complete,
            tcp_attempts=tuple(self.attempts[port] for port in sorted(self.attempts)),)

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
            targets = (str(address) for address in network.hosts())
            if network.num_addresses == 1:
                targets = (str(network.network_address),)
        for target in targets:
            if target not in seen:
                seen.add(target)
                expanded.append(target)
            if len(expanded) > max_hosts:
                raise TargetError(
                    f"target exceeds --max-hosts={max_hosts}; narrow the CIDR or raise the limit deliberately")
    if not expanded:
        raise TargetError("no usable targets supplied")
    return tuple(expanded)

async def resolve_target(target: str) -> str | int:
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
    on_connected: Callable[[float], None] | None = None,
) -> tuple[float, str | None]:
    started = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
    latency_ms = (time.perf_counter() - started) * 1000
    try:
        if on_connected is not None:
            on_connected(latency_ms)
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
    inspect_http: bool = False,
    http_timeout: float = 5.0,
    inspect_tls_enabled: bool = False,
    tls_timeout: float = 3.0,
    tls_ports: tuple[int, ...] = (443, 8443),
    smtp_starttls_ports: tuple[int, ...] = (),
    pacer: ProbePacer | None = None,
    state: HostProgress | None = None,
) -> PortFinding | None:
    connected_latency: float | None = None
    def connected(latency: float) -> None:
        nonlocal connected_latency
        connected_latency = latency
        if state is not None:
            state.attempts[port] = TcpAttempt(port, "open", "TCP connection succeeded")
            state.checked.add(port)
            state.findings[port] = PortFinding(
                port, service_name(port), round(latency, 2),
                url=web_url(target, port), inspection_complete=False)

    async with semaphore:
        if pacer is not None:
            await pacer.wait()
        try:
            if engine == "async":
                latency_ms, banner = await _async_probe(target, address, port, timeout, banner_timeout, on_connected=connected)
            elif engine == "socket":
                loop = asyncio.get_running_loop()
                latency_ms, banner = await asyncio.to_thread(
                    socket_probe, address, target, port, timeout, banner_timeout,
                    on_connected=lambda latency: loop.call_soon_threadsafe(connected, latency),)
            else:
                raise ValueError(f"unsupported engine: {engine}")
        except OSError as error:
            if connected_latency is not None:
                LOGGER.debug("banner probe failed after connection: %s:%s", address, port)
                latency_ms, banner = connected_latency, None
            else:
                if state is not None:
                    state.checked.add(port)
                    if isinstance(error, ConnectionRefusedError):
                        attempt = TcpAttempt(port, "refused", "TCP connection refused")
                    elif isinstance(error, TimeoutError):
                        attempt = TcpAttempt(port, "timeout", "TCP connection timed out")
                    else:
                        attempt = TcpAttempt(port, "error", f"TCP connection error: {error}")
                    state.attempts[port] = attempt
                return None

    LOGGER.info("open: %s (%s) %s/tcp", target, address, port)
    endpoint = web_url(target, port)
    base = PortFinding(port, service_name(port), round(latency_ms, 2),
                       banner=banner, detected_service=detect_banner_service(banner),
                       url=endpoint, inspection_complete=False)
    if state is not None:
        state.checked.add(port)
        state.attempts.setdefault(
            port, TcpAttempt(port, "open", "TCP connection succeeded"),)
        state.findings[port] = base
    web = None
    if inspect_http and endpoint:
        try:
            async with semaphore:
                web = await asyncio.to_thread(inspect_url, endpoint, http_timeout)
        except RequestException as error:
            LOGGER.warning("HTTP inspection failed for %s: %s", endpoint, error)
    if state is not None and web is not None:
        state.findings[port] = replace(base, web=web)
    tls = None
    if port in smtp_starttls_ports or (inspect_tls_enabled and port in tls_ports):
        tls_options = {"smtp_starttls": True} if port in smtp_starttls_ports else {}
        async with semaphore:
            tls = await asyncio.to_thread(
                inspect_tls, target, address, port, tls_timeout, **tls_options,)
    finding = PortFinding(
        port=port,
        service=service_name(port),
        latency_ms=round(latency_ms, 2),
        banner=banner,
        detected_service=detect_banner_service(banner),
        url=endpoint,
        web=web,
        tls=tls,)
    if state is not None:
        state.findings[port] = finding
    return finding

async def scan_host(
    target: str,
    ports: tuple[int, ...],
    *,
    engine: str,
    timeout: float,
    banner_timeout: float,
    semaphore: asyncio.Semaphore,
    inspect_http: bool,
    http_timeout: float,
    inspect_tls_enabled: bool = False,
    tls_timeout: float = 3.0,
    tls_ports: tuple[int, ...] = (443, 8443),
    smtp_starttls_ports: tuple[int, ...] = (),
    pacer: ProbePacer | None = None,
    state: HostProgress | None = None,
) -> HostScan:
    if state is None:
        state = HostProgress(target)
    try:
        address = await resolve_target(target)
        state.address = address
    except socket.gaierror as error:
        LOGGER.warning("could not resolve %s: %s", target, error)
        state.error = "resolution failed"
        state.complete = True
        return state.snapshot()

    await asyncio.gather(
        *(scan_port(
            target,
            address,
            port,
            engine=engine, timeout=timeout, banner_timeout=banner_timeout,
            semaphore=semaphore, inspect_http=inspect_http,
            http_timeout=http_timeout, inspect_tls_enabled=inspect_tls_enabled,
            tls_timeout=tls_timeout, tls_ports=tls_ports,
            smtp_starttls_ports=smtp_starttls_ports,
            pacer=pacer, state=state,
        ) for port in ports)
    )
    state.complete = True
    return state.snapshot()

async def scan(
    targets: list[str] | tuple[str, ...], *,
    ports: tuple[int, ...] = tuple(TCP_SERVICES),
    engine: str = "async",
    timeout: float = 0.75,
    banner_timeout: float = 0.35,
    inspect_http: bool = False,
    http_timeout: float = 5.0,
    inspect_tls_enabled: bool = False,
    tls_timeout: float = 3.0,
    tls_ports: tuple[int, ...] = (443, 8443),
    smtp_starttls_ports: tuple[int, ...] = (),
    concurrency: int = 100,
    max_hosts: int = 256,
    probe_rate: float | None = None,
    preserve_on_cancel: bool = False,
) -> ScanReport:
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1")
    if engine not in ("async", "socket"):
        raise ValueError("unsupported engine")
    if probe_rate is not None and (not math.isfinite(probe_rate) or probe_rate <= 0):
        raise ValueError("probe rate must be finite and greater than zero")
    if any(not math.isfinite(value) or value <= 0 for value in (
            timeout, banner_timeout, http_timeout, tls_timeout,)):
        raise ValueError("timeouts must be greater than zero")
    if not tls_ports or any(type(port) is not int or not 1 <= port <= 65535
        for port in tls_ports):
        raise ValueError("TLS ports must be integers between 1 and 65535")
    clean_tls_ports = tuple(sorted(set(tls_ports)))
    if any(type(port) is not int or not 1 <= port <= 65535 for port in smtp_starttls_ports):
        raise ValueError("SMTP STARTTLS ports must be integers between 1 and 65535")
    clean_smtp_ports = tuple(sorted(set(smtp_starttls_ports)))
    if inspect_tls_enabled and set(clean_tls_ports).intersection(clean_smtp_ports):
        raise ValueError("direct TLS and SMTP STARTTLS ports must not overlap")
    expanded = expand_targets(targets, max_hosts=max_hosts)
    clean_ports = tuple(sorted(set(ports)))
    if not clean_ports or any(port < 1 or port > 65535 for port in clean_ports):
        raise ValueError("ports must be between 1 and 65535")
    LOGGER.info("starting %s scan: %s target(s), %s port(s)", engine, len(expanded), len(clean_ports))
    started_at = datetime.now(UTC).isoformat()
    started = time.perf_counter()
    semaphore = asyncio.Semaphore(concurrency)
    pacer = ProbePacer(probe_rate)
    states = [HostProgress(target) for target in expanded]
    tasks = [asyncio.create_task(scan_host(
        state.target, clean_ports, engine=engine, timeout=timeout,
        banner_timeout=banner_timeout, semaphore=semaphore,
        inspect_http=inspect_http, http_timeout=http_timeout,
        inspect_tls_enabled=inspect_tls_enabled, tls_timeout=tls_timeout,
        tls_ports=clean_tls_ports, smtp_starttls_ports=clean_smtp_ports, pacer=pacer, state=state,
    )) for state in states]
    interrupted = False
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if not preserve_on_cancel:
            raise
        interrupted = True
        LOGGER.warning("scan interrupted; preserving observed findings")
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    LOGGER.info("scan %s in %.2f ms", "interrupted" if interrupted else "complete", duration_ms)
    return ScanReport(tuple(targets), engine, clean_ports, started_at, duration_ms,
                      tuple(state.snapshot() for state in states), interrupted, probe_rate)
