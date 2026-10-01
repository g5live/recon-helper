"""TCP service metadata and connection helpers."""
from __future__ import annotations

import socket
import time

TCP_SERVICES = {
    21: "Type: FTP (control)",
    22: "Type: SSH",
    23: "Type: Telnet",
    25: "Type: SMTP",
    53: "Type: DNS",
    80: "Type: HTTP",
    110: "Type: POP3",
    143: "Type: IMAP",
    443: "Type: HTTPS",
    445: "Type: SMB",
    465: "Type: SMTPS",
    587: "Type: SMTP (Submissions)",
    853: "Type: DNS over TLS",
    989: "Type: FTPS (Data)",
    990: "Type: FTPS (Control)",
    3389: "Type: RDP",
    8080: "Type: HTTP (Server)",
    8443: "Type: HTTPS (Server)",
}
ENUMERATION_INFO = {
    21: {
        "service": "FTP",
        "tools": ["ftp", "nmap"],
        "checks": ["Banner/version", "Anonymous login", "Authentication", "Accessible files"]
    },

    22: {
        "service": "SSH",
        "tools": ["ssh", "nmap", "Hydra"],
        "checks": ["Banner/version", "Authentication methods", "Credentials"]
    },

    23: {
        "service": "Telnet",
        "tools": ["telnet", "nmap"],
        "checks": ["Banner/version", "Authentication", "Clear-text communication"]
    },

    25: {
        "service": "SMTP",
        "tools": ["nmap", "nc"],
        "checks": ["Banner/version", "Mail server information", "Supported SMTP commands"]
    },

    53: {
        "service": "DNS",
        "tools": ["dig", "nslookup", "nmap"],
        "checks": ["DNS records", "Nameservers", "Hostnames", "Zone transfer configuration"]
    },

    67: {
        "service": "DHCP Server",
        "tools": ["nmap", "Scapy"],
        "checks": ["DHCP server", "Lease information", "Network configuration"]
    },

    68: {
        "service": "DHCP Client",
        "tools": ["Scapy"],
        "checks": ["DHCP client traffic", "Assigned network configuration"]
    },

    69: {
        "service": "TFTP",
        "tools": ["tftp", "nmap"],
        "checks": ["Accessible files", "Configuration files", "Read/write access"]
    },

    80: {
        "service": "HTTP",
        "tools": ["Browser", "Burp Suite", "Gobuster", "nmap"],
        "checks": ["Headers", "Technologies", "Directories", "robots.txt", "Sitemap"]
    },

    110: {
        "service": "POP3",
        "tools": ["nc", "nmap"],
        "checks": ["Banner/version", "Authentication", "Capabilities"]
    },

    143: {
        "service": "IMAP",
        "tools": ["nc", "nmap"],
        "checks": ["Banner/version", "Authentication", "Capabilities"]
    },

    161: {
        "service": "SNMP",
        "tools": ["snmpwalk", "snmpget", "nmap"],
        "checks": ["SNMP version", "Exposed system information", "Community configuration"]
    },

    162: {
        "service": "SNMP Trap",
        "tools": ["nmap", "tcpdump", "Wireshark"],
        "checks": ["SNMP trap traffic", "Trap source", "Exposed system information"]
    },

    443: {
        "service": "HTTPS",
        "tools": ["Browser", "Burp Suite", "Gobuster", "nmap"],
        "checks": ["TLS certificate", "Headers", "Technologies", "Directories", "robots.txt"]
    },

    445: {
        "service": "SMB",
        "tools": ["smbclient", "nmap"],
        "checks": ["Shares", "Access permissions", "SMB version", "Host information"]
    },

    465: {
        "service": "SMTPS",
        "tools": ["openssl", "nmap"],
        "checks": ["TLS certificate", "SMTP banner", "Authentication", "Capabilities"]
    },

    587: {
        "service": "SMTP Submission",
        "tools": ["openssl", "nmap"],
        "checks": ["SMTP banner", "STARTTLS", "Authentication methods", "Capabilities"]
    },

    853: {
        "service": "DNS over TLS",
        "tools": ["openssl", "dig"],
        "checks": ["TLS certificate", "DNS service", "Encrypted DNS configuration"]
    },

    989: {
        "service": "FTPS Data",
        "tools": ["openssl", "nmap"],
        "checks": ["TLS configuration", "FTP service information"]
    },

    990: {
        "service": "FTPS Control",
        "tools": ["openssl", "ftp", "nmap"],
        "checks": ["TLS certificate", "Banner/version", "Authentication", "Accessible files"]
    },

    3389: {
        "service": "RDP",
        "tools": ["nmap", "xfreerdp"],
        "checks": ["RDP availability", "TLS certificate", "Authentication requirements", "Host information"]
    },

    8080: {
        "service": "HTTP Alternate",
        "tools": ["Browser", "Burp Suite", "Gobuster", "nmap"],
        "checks": ["Web application", "Headers", "Technologies", "Directories"]
    },

    8443: {
        "service": "HTTPS Alternate",
        "tools": ["Browser", "Burp Suite", "Gobuster", "nmap"],
        "checks": ["Web application", "TLS certificate", "Headers", "Technologies", "Directories"]
    }
}
PORT_PRIORITY = {
    80: 1,
    443: 1,
    8080: 1,
    8443: 1,

    21: 2,
    22: 2,
    23: 2,
    445: 2,
    989: 2,
    990: 2,
    3389: 2,

    25: 3,
    53: 3,
    110: 3,
    143: 3,
    465: 3,
    587: 3,
    853: 3,

}
PRIORITY_LABELS = {
    1: "HIGH PRIORITY - WEB ENUMERATION",
    2: "MEDIUM PRIORITY - REMOTE ACCESS",
    3: "LOW PRIORITY - EMAIL / DNS",
    4: "FURTHER EXPLORATION",
}


def service_name(port: int) -> str:
    """Return a readable service name without the legacy ``Type:`` prefix."""
    return TCP_SERVICES.get(port, "Type: Unknown").removeprefix("Type: ")

def web_url(hostname: str, port: int) -> str | None:
    schemes = {
        80: "http",
        443: "https",
        8080: "http",
        8443: "https",
    }

    scheme = schemes.get(port)
    if scheme is None:
        return None

    if port in {80, 443}:
        return f"{scheme}://{hostname}"

    return f"{scheme}://{hostname}:{port}"

def probe_payload(port: int, hostname: str) -> bytes:
    """Return a small application probe for protocols that expect the client first."""
    if port in {80, 8080}:
        return (
            f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\n"
            "User-Agent: recon-helper/0.2\r\nConnection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
    return b""


def readable_banner(data: bytes) -> str | None:
    if not data:
        return None
    readable = sum(byte in range(32, 127) or byte in (9, 10, 13) for byte in data)
    if readable / len(data) < 0.85:
        return f"binary/protocol response ({len(data)} bytes)"
    text = data.decode(errors="replace").strip().replace("\r", "")
    return " | ".join(line.strip() for line in text.splitlines() if line.strip())[:500]


def socket_probe(
    address: str,
    hostname: str,
    port: int,
    timeout: float,
    banner_timeout: float,
) -> tuple[float, str | None]:
    """Use blocking ``socket.connect()`` for the optional threaded scan engine."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    started = time.perf_counter()
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((address, port))
        latency_ms = (time.perf_counter() - started) * 1000
        payload = probe_payload(port, hostname)
        if payload:
            sock.sendall(payload)
        sock.settimeout(banner_timeout)
        try:
            banner = readable_banner(sock.recv(1024))
        except (socket.timeout, OSError):
            banner = None
    return latency_ms, banner
