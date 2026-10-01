"""Structured HTTP inspection for discovered web endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup


USER_AGENT = {"User-Agent": "recon-helper/0.3"}
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


@dataclass(frozen=True, slots=True)
class HeaderFinding:
    name: str
    applicable: bool
    present: bool
    value: str | None


@dataclass(frozen=True, slots=True)
class RobotsFinding:
    url: str
    status: int | None
    present: bool
    disallowed_paths: tuple[str, ...]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class TechnologyHint:
    source: str
    evidence: str


@dataclass(frozen=True, slots=True)
class WebFinding:
    status: int
    final_url: str
    title: str | None
    server: str | None
    content_type: str | None
    powered_by: str | None
    response_size: int
    response_time_ms: float
    redirects: int
    technology_hints: tuple[TechnologyHint, ...] = ()
    security_headers: tuple[HeaderFinding, ...] = ()
    robots: RobotsFinding | None = None


def assess_security_headers(
    headers: requests.structures.CaseInsensitiveDict[str] | dict[str, str],
    final_url: str,
) -> tuple[HeaderFinding, ...]:
    """Record header evidence without treating absence as proof of a vulnerability."""
    is_https = urlsplit(final_url).scheme.lower() == "https"
    findings = []
    for name in SECURITY_HEADERS:
        applicable = name != "Strict-Transport-Security" or is_https
        value = headers.get(name) if applicable else None
        findings.append(HeaderFinding(name, applicable, bool(value), value))
    return tuple(findings)


def detect_technology(
    headers: requests.structures.CaseInsensitiveDict[str] | dict[str, str],
    page_text: str,
    soup: BeautifulSoup,
) -> tuple[TechnologyHint, ...]:
    """Return evidence-led hints without claiming a definitive fingerprint."""
    hints = []
    powered_by = headers.get("X-Powered-By")
    if powered_by:
        hints.append(TechnologyHint("X-Powered-By header", powered_by))

    generator = soup.find("meta", attrs={"name": "generator"})
    if generator:
        content = generator.get("content")
        if isinstance(content, str) and content.strip():
            hints.append(TechnologyHint("meta generator", content.strip()))

    if "wp-content" in page_text.lower():
        hints.append(
            TechnologyHint("HTML path", "WordPress-style wp-content path detected")
        )

    return tuple(hints)


def inspect_robots(base_url: str, timeout: float) -> RobotsFinding:
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        response = requests.get(robots_url, timeout=timeout, headers=USER_AGENT)
    except requests.RequestException as error:
        return RobotsFinding(robots_url, None, False, (), str(error))

    disallowed_paths = []
    if response.status_code == 200:
        for raw_line in response.text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            name, separator, value = line.partition(":")
            if separator and name.strip().lower() == "disallow":
                path = value.strip()
                if path:
                    disallowed_paths.append(path)

    return RobotsFinding(
        url=robots_url,
        status=response.status_code,
        present=response.status_code == 200,
        disallowed_paths=tuple(disallowed_paths),
    )


def inspect_url(url: str, timeout: float = 10.0) -> WebFinding:
    response = requests.get(url, timeout=timeout, headers=USER_AGENT)
    soup = BeautifulSoup(response.text, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else None

    return WebFinding(
        status=response.status_code,
        final_url=response.url,
        title=title,
        server=response.headers.get("Server"),
        content_type=response.headers.get("Content-Type"),
        powered_by=response.headers.get("X-Powered-By"),
        response_size=len(response.content),
        response_time_ms=round(response.elapsed.total_seconds() * 1000, 2),
        redirects=len(response.history),
        technology_hints=detect_technology(response.headers, response.text, soup),
        security_headers=assess_security_headers(response.headers, response.url),
        robots=inspect_robots(response.url, timeout),
    )
