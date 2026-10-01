"""Temporary interactive workflow retained while enumeration advice is migrated."""

import socket
from urllib.parse import urlsplit

import requests

from recon.output import render_web_details
from recon.protocols import (
    ENUMERATION_INFO,
    PORT_PRIORITY,
    PRIORITY_LABELS,
    TCP_SERVICES,
    web_url,
)
from recon.web import WebFinding, inspect_url


def grab_banner(ip_address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip_address, port))
            data = sock.recv(1024)
            if not data:
                return None

            readable_bytes = sum(
                byte in range(32, 127) or byte in (9, 10, 13) for byte in data
            )
            if readable_bytes / len(data) >= 0.85:
                return data.decode(errors="replace").strip()
            return f"binary/protocol response received ({len(data)} bytes)"
    except (socket.timeout, OSError):
        return None


def scan_tcp_ports(ip_address):
    open_ports = []
    print("\n--- CHECKING TCP PORTS ---")
    for port, service in TCP_SERVICES.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
            print(f"{port}/tcp open - {service}")
            banner = grab_banner(ip_address, port)
            if banner:
                print(f"banner: {banner}")

    if not open_ports:
        print("No TCP ports responded (closed, filtered, or not in scan list).")
    return open_ports


def resolve_target(hostname):
    print("\n--- RESOLVING TARGET ---")
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        print("[-] Could not resolve target")
        return None
    print(f"Target: {hostname}")
    print(f"IP address: {ip_address}")
    return ip_address


def choose_web_url(hostname, open_ports):
    for port in (443, 8443, 80, 8080):
        if port in open_ports:
            return web_url(hostname, port)
    return None


def robots_summary(web: WebFinding | None) -> str | None:
    if not web or not web.robots:
        return None
    if web.robots.error:
        return "robots.txt check failed"
    if not web.robots.present:
        return "robots.txt not found"
    if web.robots.disallowed_paths:
        return "Disallow: " + ", ".join(web.robots.disallowed_paths)
    return "robots.txt present; no non-empty Disallow paths observed"


def enumeration_info(open_ports, robots_info):
    print("\n--- ENUMERATION PRIORITY ---")
    print(" use as guide for next steps in recon ")
    for priority, label in PRIORITY_LABELS.items():
        print(f"\n--- {label} ---")
        found = False
        for port in open_ports:
            if PORT_PRIORITY.get(port) == priority and port in ENUMERATION_INFO:
                found = True
                info = ENUMERATION_INFO[port]
                print(f"\nPort {port} - {info['service']}")
                print("Tools:", ", ".join(info["tools"]))
                print("Check:", ", ".join(info["checks"]))
                if port in {80, 443, 8080, 8443} and robots_info:
                    print("Robots:", robots_info)
        if not found:
            print("None Found")


def main():
    print("\n--- RUNNING RECON.PY ---")
    target_url = input("enter target host or URL: ").strip()
    if "://" not in target_url:
        target_url = "http://" + target_url

    hostname = urlsplit(target_url).hostname
    if hostname is None:
        print("[-] No valid hostname found")
        return

    ip_address = resolve_target(hostname)
    if ip_address is None:
        return

    open_ports = scan_tcp_ports(ip_address)
    endpoint = choose_web_url(hostname, open_ports)
    web = None

    print("\n--- STRUCTURED HTTP EVIDENCE ---")
    if endpoint is None:
        print("no HTTP/HTTPS service detected - skipping web checks")
    else:
        try:
            web = inspect_url(endpoint)
        except requests.RequestException as error:
            print(f"http request failed: {error}")
        else:
            for line in render_web_details(web, indent=""):
                print(line)

    enumeration_info(open_ports, robots_summary(web))
    print("\n--- RECON LOG END ---")


if __name__ == "__main__":
    main()
