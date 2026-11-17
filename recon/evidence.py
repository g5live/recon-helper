"""Read saved scans into a common format for comparison."""

import json
from dataclasses import dataclass
from pathlib import Path
from datetime import UTC, datetime
from xml.etree import ElementTree as ET

@dataclass(frozen=True, slots=True)
class PortObservation:
    target: str
    address: str | None
    protocol: str
    port: int
    outcome: str
    evidence: str | None = None
    tls: dict[str, object] | None = None
    service: str | None = None
    service_method: str | None = None

@dataclass(frozen=True, slots=True)
class SavedScan:
    source: str
    started_at: str | None
    requested_targets: tuple[str, ...]
    requested_ports: tuple[int, ...]
    interrupted: bool | None
    observations: tuple[PortObservation, ...]

"""Read a Recon Helper JSON export without making network requests."""
def load_recon_json(path: Path) -> SavedScan:
    data = json.loads(path.read_text(encoding="utf-8"))
    protocol = data.get("protocol", "tcp")
    if protocol not in ("tcp", "udp"):
        raise ValueError(f"Unsupported report protocol: {protocol}")

    observations = []
    for host in data["hosts"]:
        target = host["target"]
        address = host.get("address")
        if protocol == "udp":
            for result in host["results"]:
                observations.append(PortObservation(
                    target=target,
                    address=address,
                    protocol=protocol,
                    port=result["port"],
                    outcome=result["status"],
                    evidence=result.get("evidence"),))
            continue

        open_ports = {finding["port"]: finding for finding in host["open_ports"]}
        attempts = {attempt["port"]: attempt for attempt in host.get("tcp_attempts", ())}
        for port in sorted(open_ports.keys() | attempts.keys()):
            finding = open_ports.get(port, {})
            attempt = attempts.get(port, {})
            observations.append(PortObservation(
                target, address, protocol, port,
                attempt["outcome"] if attempt else "open",
                attempt.get("evidence"),
                finding.get("tls"),))

    return SavedScan(
        source="recon-helper",
        started_at=data.get("started_at"),
        requested_targets=tuple(data.get("requested_targets", ())),
        requested_ports=tuple(data.get("ports", ())),
        interrupted=data.get("interrupted"),
        observations=tuple(observations),)

"""Read explicit TCP and UDP observations from an Nmap XML export."""
def load_nmap_xml(path: Path) -> SavedScan:
    root = ET.parse(path).getroot()
    if root.tag != "nmaprun":
        raise ValueError("Expected an Nmap XML report")

    observations = []
    for host in root.findall("host"):
        address = next((
            entry.get("addr")
            for entry in host.findall("address")
            if entry.get("addrtype") in ("ipv4", "ipv6") and entry.get("addr")
        ), None)
        if address is None:
            continue
        for entry in host.findall("./ports/port"):
            protocol = entry.get("protocol")
            state = entry.find("state")
            if protocol not in ("tcp", "udp") or state is None:
                continue

            service = entry.find("service")
            observations.append(PortObservation(
                target=address,
                address=address,
                protocol=protocol,
                port=int(entry.attrib["portid"]),
                outcome=state.attrib["state"],
                evidence=state.get("reason"),
                service=service.get("name") if service is not None else None,
                service_method=service.get("method") if service is not None else None,))

    start = root.get("start")
    finished = root.find("./runstats/finished")
    return SavedScan(
        source="nmap",
        started_at=datetime.fromtimestamp(int(start), UTC).isoformat() if start else None,
        requested_targets=(),
        requested_ports=(),
        interrupted=False if finished is not None and finished.get("exit") == "success" else None,
        observations=tuple(observations),)