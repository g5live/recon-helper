"""Structured HTTP inspection for discovered web endpoints."""
from __future__ import annotations
from dataclasses import dataclass
import requests
from bs4 import BeautifulSoup

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

def inspect_url(url: str, timeout: float = 10.0) -> WebFinding:
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": "recon-helper/0.3"},
    )

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
    )