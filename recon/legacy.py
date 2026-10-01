import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlsplit

COMMON_PORTS = {
    21: "Type: FTP (control)",
    22: "Type: SSH",
    23: "Type: Telnet",
    25: "Type: SMTP",
    53: "Type: DNS",
    67: "Type: DHCP (Server)",
    68: "Type: DHCP (Client)",
    69: "Type: FTP (control)",
    80: "Type: HTTP",
    110: "Type: POP3",
    143: "Type: IMAP",
    161: "Type: SNMP",
    162: "Type: SNMP (Trap)",
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
    578: 3,
    853: 3,

    67: 4,
    68: 4,
    69: 4,
    123: 4,
    161: 4,
    162: 4,

}

PRIORITY_LABELS = {
    1: "HIGH PRIORITY - WEB ENUMERATION",
    2: "MEDIUM PRIORITY - REMOTE ACCESS",
    3: "LOW PRIORITY - EMAIL / DNS",
    4: "FURTHER EXPLORATION",
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

def enumeration_info(open_ports, robots_info):
    print("\n--- ENUMERATION PRIORITY ---")
    print(" use as guide for next steps in recon ")

    for priority, label in PRIORITY_LABELS.items():
        print(f"\n--- {label} ---")

        found = False

        for port in open_ports:
            if PORT_PRIORITY.get(port) == priority:
                if port in ENUMERATION_INFO:
                    found = True
                    info = ENUMERATION_INFO[port]

                    print(f"\nPort {port} - {info['service']}")
                    print("Tools:", ", ".join(info["tools"]))
                    print("Check:", ", ".join(info["checks"]))

                    if port in [80, 443, 8080, 8443] and robots_info:
                        print("Robots:", robots_info)

        if not found:
            print("None Found")

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

    if not web_url:
        return None

    robots_url = f"{web_url.rstrip('/')}/robots.txt"

    try:
        robots_response = requests.get(robots_url, timeout=10)
        print(f"robots.txt status: {robots_response.status_code}")

        if robots_response.status_code == 200:
            return "robots.txt present - review disallowed paths"

        return "robots.txt not found"

    except requests.RequestException:
        return "robots.txt check failed"

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

    robots_info = check_robots(web_url, response)

    enumeration_info(open_ports, robots_info)

    print("\n--- RECON LOG END ---")


if __name__ == "__main__":
    main()