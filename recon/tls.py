"""Opt-in TLS inspection and structured findings."""
from __future__ import annotations
from dataclasses import dataclass
from typing import TypedDict, cast
from datetime import UTC, datetime
import socket
import ssl
import math
import time
import hashlib

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
    certificate_sha256: str | None = None
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
    mode: str = "direct"

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

def _read_smtp_reply(connection: socket.socket, deadline: float) -> tuple[int, list[bytes]]:
    """Read a bounded SMTP reply without buffering beyond the TLS boundary."""
    code = None
    lines = []
    for _ in range(32):
        line = bytearray()
        while len(line) < 512:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("SMTP negotiation timed out")
            connection.settimeout(remaining)
            byte = connection.recv(1)
            if not byte:
                raise OSError("SMTP server closed the connection")
            line.extend(byte)
            if line.endswith(b"\r\n"):
                break
        else:
            raise OSError("SMTP reply line exceeded 512 bytes")
        reply = bytes(line[:-2])
        if len(reply) < 3 or not reply[:3].isdigit() or reply[3:4] not in (b"", b" ", b"-"):
            raise OSError("invalid SMTP reply")
        current = int(reply[:3])
        if code is not None and current != code:
            raise OSError("inconsistent SMTP reply codes")
        code = current
        lines.append(reply[4:])
        if reply[3:4] != b"-":
            return code, lines
    raise OSError("SMTP reply exceeded 32 lines")

def _smtp_starttls(connection: socket.socket, timeout: float) -> None:
    deadline = time.monotonic() + timeout

    def send(command: bytes) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SMTP negotiation timed out")
        connection.settimeout(remaining)
        connection.sendall(command)

    greeting, _ = _read_smtp_reply(connection, deadline)
    if greeting != 220:
        raise OSError(f"SMTP greeting returned {greeting}; expected 220")
    local = connection.getsockname()[0].split("%", 1)[0]
    literal = f"IPv6:{local}" if ":" in local else local
    send(f"EHLO [{literal}]\r\n".encode("ascii"))
    status, lines = _read_smtp_reply(connection, deadline)
    if status != 250:
        raise OSError(f"SMTP EHLO returned {status}; expected 250")
    if not any(line.strip().upper() == b"STARTTLS" for line in lines[1:]):
        raise OSError("SMTP server did not advertise STARTTLS")
    send(b"STARTTLS\r\n")
    status, _ = _read_smtp_reply(connection, deadline)
    if status != 220:
        raise OSError(f"SMTP STARTTLS returned {status}; expected 220")
    connection.settimeout(timeout)

def inspect_tls(
    hostname: str,
    address: str,
    port: int,
    timeout: float = 3.0,
    *,
    smtp_starttls: bool = False,
) -> TLSFinding:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("TLS timeout must be greater than zero")
    context = ssl.create_default_context()
    mode = "smtp-starttls" if smtp_starttls else "direct"
    try:
        with socket.create_connection((address, port), timeout=timeout) as connection:
            if smtp_starttls:
                try:
                    _smtp_starttls(connection, timeout)
                except OSError as error:
                    return TLSFinding(
                        error=f"SMTP STARTTLS negotiation failed: {error}",
                        mode=mode,)
            with context.wrap_socket(connection, server_hostname=hostname) as tls_connection:
                cipher = tls_connection.cipher()
                certificate = cast(CertificateDetails, tls_connection.getpeercert() or {})
                certificate_der = tls_connection.getpeercert(binary_form=True)
                names = certificate.get("subjectAltName", ())
                return TLSFinding(
                    version=tls_connection.version(),
                    cipher=cipher[0] if cipher else None,
                    certificate_verified=True,
                    subject=format_certificate_name(certificate.get("subject", ())),
                    issuer=format_certificate_name(certificate.get("issuer", ())),
                    san_hostnames=tuple(value for kind, value in names if kind == "DNS"),
                    san_ip_addresses=tuple(value for kind, value in names if kind == "IP Address"),
                    valid_from=certificate.get("notBefore"),
                    valid_until=certificate.get("notAfter"),
                    days_remaining=certificate_days_remaining(certificate.get("notAfter")),
                    mode=mode,
                    certificate_sha256=(
                        hashlib.sha256(certificate_der).hexdigest()
                        if certificate_der is not None
                        else None),)

    except ssl.SSLCertVerificationError as error:
        return TLSFinding(
            error=f"certificate verification failed: {error}",
            verification_code=getattr(error, "verify_code", None),
            verification_message=getattr(error, "verify_message", None),
            mode=mode,)
    except OSError as error:
        return TLSFinding(error=f"TLS connection failed: {error}", mode=mode)
