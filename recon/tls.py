"""Opt-in TLS inspection and structured findings."""
from __future__ import annotations
from dataclasses import dataclass
from typing import TypedDict, cast
from datetime import UTC, datetime
import socket
import ssl
import math

CertificateName = tuple[tuple[tuple[str, str], ...], ...]
class CertificateDetails(TypedDict, total=False):
    subject: CertificateName
    issuer: CertificateName
    subjectAltName: tuple[tuple[str, str], ...]
    notBefore: str
    notAfter: str

@dataclass(frozen=True, slots=True)
class TLSFinding:
    version: str | None = None
    cipher: str | None = None
    certificate_verified: bool = False
    subject: str | None = None
    issuer: str | None = None
    san_hostnames: tuple[str, ...] = ()
    valid_from: str | None = None
    valid_until: str | None = None
    error: str | None = None
    days_remaining: int | None = None
    verification_code: int | None = None
    verification_message: str | None = None
    san_ip_addresses: tuple[str, ...] = ()

def format_certificate_name(
    name: CertificateName,) -> str | None:
    parts = [
        f"{key}={value}"
        for group in name
        for key, value in group]
    return ", ".join(parts) or None

def certificate_days_remaining(
    valid_until: str | None,
    *,
    now: datetime | None = None,
) -> int | None:
    """Return whole days until expiry, or None if the date is unavailable."""
    if not valid_until:
        return None
    try:
        expiry_timestamp = ssl.cert_time_to_seconds(valid_until)
    except (ValueError, OverflowError):
        return None
    current_time = now if now is not None else datetime.now(UTC)
    seconds_remaining = expiry_timestamp - current_time.timestamp()
    return math.floor(seconds_remaining / 86400)

def inspect_tls(
    hostname: str,
    address: str,
    port: int,
    timeout: float = 3.0,
) -> TLSFinding:
    if timeout <= 0:
        raise ValueError("TLS timeout must be greater than zero")
    context = ssl.create_default_context()
    try:
        with socket.create_connection(
            (address, port),
            timeout=timeout,
        ) as connection:
            with context.wrap_socket(
                connection,
                server_hostname=hostname,
            ) as tls_connection:
                cipher = tls_connection.cipher()
                certificate = cast(
                    CertificateDetails,
                    tls_connection.getpeercert() or {},)
                san_hostnames = tuple(value
                    for kind, value in certificate.get(
                        "subjectAltName", ())
                    if kind == "DNS")
                san_ip_addresses = tuple(value
                    for kind, value in certificate.get(
                        "subjectAltName", ())
                    if kind == "IP Address")
                return TLSFinding(
                    version=tls_connection.version(),
                    cipher=cipher[0] if cipher else None,
                    certificate_verified=True,
                    subject=format_certificate_name(
                        certificate.get("subject", ())),
                    issuer=format_certificate_name(
                        certificate.get("issuer", ())),
                    san_hostnames=san_hostnames,
                    san_ip_addresses=san_ip_addresses,
                    valid_from=certificate.get("notBefore"),
                    valid_until=certificate.get("notAfter"),
                    days_remaining=certificate_days_remaining(
                        certificate.get("notAfter")),)
    except ssl.SSLCertVerificationError as error:
        return TLSFinding(
            error=f"certificate verification failed: {error}",
            verification_code=getattr(error, "verify_code", None),
            verification_message=getattr(error, "verify_message", None),)
    except OSError as error:
        return TLSFinding(
            error=f"TLS connection failed: {error}")

