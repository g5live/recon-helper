import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlsplit

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
}

def grab_banner(ip_address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip_address, port))

            data = sock.recv(1024)

            if not data:
                return None

            readable_bytes = sum(
                byte in range(32, 127) or byte in (9, 10, 13)
                for byte in data
            )

            readable_ratio = readable_bytes / len(data)

            if readable_ratio >= 0.85:
                return data.decode(errors="replace").strip()

            return f"binary/protocol response received ({len(data)} bytes)"

    except (socket.timeout, OSError):
        return None

def scan_common_ports(ip_address):
    open_ports = []

    print("\n--- CHECKING COMMON PORTS ---")

    for port, service in COMMON_PORTS.items():
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
        print(
            "No common TCP ports responded "
            "(closed, filtered, or not in scan list)."
        )

    return open_ports

def resolve_target(hostname):

    print("\n--- RESOLVING TARGET ---")

    try:
        ip_address = socket.gethostbyname(hostname)

        print(f"Target: {hostname}")
        print(f"IP address: {ip_address}")

        return ip_address

    except socket.gaierror:
        print("[-] Could not resolve target")
        return None

def choose_web_url(hostname, open_ports):
    if 443 in open_ports:
        return f"https://{hostname}"

    if 80 in open_ports:
        return f"http://{hostname}"

    return None

def check_http(web_url):
    print("\n--- TARGET HTTP(S) ---")

    if web_url is None:
        print("no HTTP/HTTPS service detected - skipping web checks")
        return None, None

    try:
        response = requests.get(web_url, timeout=10)

        print(f"http status: {response.status_code}")

        if response.status_code == 429:
            print("warning: rate limited / security checkpoint response")

        print(f"server: {response.headers.get('Server', 'not disclosed')}")
        print(f"content type: {response.headers.get('Content-Type', 'not disclosed')}")
        print(f"powered by: {response.headers.get('X-Powered-By', 'not disclosed')}")
        print(f"response size: {len(response.content)} bytes")
        print(f"response time: {response.elapsed.total_seconds():.3f} seconds")

        soup = BeautifulSoup(response.text, "html.parser")

        page_title = (
            soup.title.string.strip()
            if soup.title and soup.title.string
            else "not found"
        )

        print(f"page title: {page_title}")

        return response, soup

    except requests.RequestException as error:
        print(f"http request failed: {error}")
        return None, None

def check_technology(response, soup):
    print("\n--- TECHNOLOGY HINTS ---")

    if response is None or soup is None:
        print("no HTTP/HTTPS service detected - skipping web checks")
        return

    tech_hints = []

    powered_by = response.headers.get("X-Powered-By")

    if powered_by:
        tech_hints.append(f"X-Powered-By: {powered_by}")

    generator = soup.find("meta", attrs={"name": "generator"})

    if generator and generator.get("content"):
        tech_hints.append(f"Generator: {generator.get('content')}")

    if "wp-content" in response.text.lower():
        tech_hints.append("WordPress-style wp-content path detected")

    if tech_hints:
        for hint in tech_hints:
            print(hint)
    else:
        print("No obvious technology hints detected")

    print(f"final URL: {response.url}")
    print(f"redirects followed: {len(response.history)}")

def check_security_headers(response):
    print("\n--- SECURITY INFO ---")

    if response is None:
        print("no HTTP/HTTPS service detected - skipping web checks")
        return

    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    for header in security_headers:
        value = response.headers.get(header)

        if value:
            print(f"{header}: present")
        else:
            print(f"{header}: not present")

def check_robots(web_url, response):
    print("\n--- CHECKING ROBOTS.TXT ---")

    if web_url is None or response is None:
        print("no HTTP/HTTPS service detected - skipping web checks")
        return

    try:
        robots_url = f"{web_url}/robots.txt"
        robots_response = requests.get(robots_url, timeout=10)

        print(f"robots.txt status: {robots_response.status_code}")

        if robots_response.status_code == 200:
            robots_lines = robots_response.text.splitlines()

            for line in robots_lines:
                if line.lower().startswith(("disallow:", "sitemap:")):
                    print(line.strip())

    except requests.RequestException as robot_error:
        print(f"robots.txt request failed: {robot_error}")

def main():
    print("\n--- RUNNING RECON.PY ---")

    target_url = input("enter target host or URL: ").strip()

    if "://" not in target_url:
        target_url = "http://" + target_url

    parsed_url = urlsplit(target_url)
    hostname = parsed_url.hostname

    if hostname is None:
        print("[-] No valid hostname found")
        return

    ip_address = resolve_target(hostname)

    if ip_address is None:
        return

    open_ports = scan_common_ports(ip_address)

    web_url = choose_web_url(hostname, open_ports)

    response, soup = check_http(web_url)

    check_technology(response, soup)

    check_security_headers(response)

    check_robots(web_url, response)

    print("\n--- RECON LOG END ---")


if __name__ == "__main__":
    main()