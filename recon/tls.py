"""Opt-in TLS inspection and structured findings."""
from __future__ import annotations
from dataclasses import dataclass
from typing import TypedDict, cast
import socket
import ssl

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

def format_certificate_name(
    name: CertificateName,) -> str | None:
    parts = [
        f"{key}={value}"
        for group in name
        for key, value in group
    ]
    return ", ".join(parts) or None

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
                    tls_connection.getpeercert() or {},
                )
                san_hostnames = tuple(
                    value
                    for kind, value in certificate.get(
                        "subjectAltName", ()
                    )
                    if kind == "DNS"
                )
                return TLSFinding(
                    version=tls_connection.version(),
                    cipher=cipher[0] if cipher else None,
                    certificate_verified=True,
                    subject=format_certificate_name(
                        certificate.get("subject", ())
                    ),
                    issuer=format_certificate_name(
                        certificate.get("issuer", ())
                    ),
                    san_hostnames=san_hostnames,
                    valid_from=certificate.get("notBefore"),
                    valid_until=certificate.get("notAfter"),
                )
    except ssl.SSLCertVerificationError as error:
        return TLSFinding(
            error=f"certificate verification failed: {error}"
        )
    except OSError as error:
        return TLSFinding(
            error=f"TLS connection failed: {error}"
        )

