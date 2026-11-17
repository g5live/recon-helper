"""Compare explicit endpoint observations from two saved scans."""

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Literal
from recon.evidence import PortObservation, SavedScan

Endpoint = tuple[str, str, int]
DeltaKind = Literal[
    "baseline-only", "retest-only", "outcome-changed", "same-outcome",]

@dataclass(frozen=True, slots=True)
class EndpointDelta:
    endpoint: Endpoint
    kind: DeltaKind
    before: PortObservation | None
    after: PortObservation | None
    tls_changes: tuple[str, ...] = ()

def _by_endpoint(scan: SavedScan) -> dict[Endpoint, PortObservation]:
    indexed: dict[Endpoint, PortObservation] = {}
    for observation in scan.observations:
        if observation.address is None:
            raise ValueError(f"No IP address recorded for {observation.target}")
        key = (
            str(ip_address(observation.address)),
            observation.protocol,
            observation.port,)
        if key in indexed:
            raise ValueError(f"Multiple observations for endpoint {key}")
        indexed[key] = observation
    return indexed

def _compare_tls(
    before: PortObservation | None,
    after: PortObservation | None,
) -> tuple[str, ...]:
    if before is None or after is None:
        return ()
    if before.outcome != "open" or after.outcome != "open":
        return ()
    old_tls = before.tls
    new_tls = after.tls
    if old_tls is None or new_tls is None:
        return ()
    if before.target.casefold() != after.target.casefold():
        return ()
    old_mode = old_tls.get("mode")
    if old_mode is None or old_mode != new_tls.get("mode"):
        return ()
    changes = []
    old_verified = old_tls.get("certificate_verified")
    new_verified = new_tls.get("certificate_verified")
    if isinstance(old_verified, bool) and isinstance(new_verified, bool):
        if old_verified != new_verified:
            changes.append("verification result changed")
    old_hash = old_tls.get("certificate_sha256")
    new_hash = new_tls.get("certificate_sha256")
    if old_hash and new_hash and old_hash != new_hash:
        changes.append("certificate fingerprint changed")
    return tuple(changes)

def compare_scans(baseline: SavedScan, retest: SavedScan) -> tuple[EndpointDelta, ...]:
    before = _by_endpoint(baseline)
    after = _by_endpoint(retest)
    changes = []
    for key in sorted(before.keys() | after.keys()):
        old = before.get(key)
        new = after.get(key)
        kind: DeltaKind
        if old is None:
            kind = "retest-only"
        elif new is None:
            kind = "baseline-only"
        elif old.outcome != new.outcome:
            kind = "outcome-changed"
        else:
            kind = "same-outcome"
        changes.append(EndpointDelta(
            key, kind, old, new,
            tls_changes=_compare_tls(old, new),))
    return tuple(changes)