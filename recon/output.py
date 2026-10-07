"""Render structured scan results without coupling scanning to ``print()``."""
from __future__ import annotations
import json
from typing import TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from recon.scanner import ScanReport
    from recon.web import WebFinding

def render_json(report: ScanReport) -> str:
    """Serialize the scan report to a formatted JSON string."""
    return json.dumps(report.to_dict(), indent=2)

def render_web_details(web: WebFinding, indent: str = "    ") -> list[str]:
    """Render canonical HTTP evidence for text and legacy views."""
    lines = [
        f"{indent}http: {web.status} | title: {web.title or '-'}",
        f"{indent}final url: {web.final_url}",
        (
            f"{indent}server: {web.server or '-'} | "
            f"content type: {web.content_type or '-'}"
        ),
    ]
    if web.powered_by:
        lines.append(f"{indent}powered by: {web.powered_by}")
    lines.append(
        f"{indent}response: {web.response_size} bytes in "
        f"{web.response_time_ms:.2f} ms | redirects: {web.redirects}"
    )
    if web.technology_hints:
        hints = "; ".join(
            f"{hint.source}: {hint.evidence}" for hint in web.technology_hints
        )
        lines.append(f"{indent}technology hints: {hints}")
    present_headers = [
        header.name
        for header in web.security_headers
        if header.applicable and header.present
    ]
    missing_headers = [
        header.name
        for header in web.security_headers
        if header.applicable and not header.present
    ]
    lines.append(
        f"{indent}security headers present: "
        + (", ".join(present_headers) if present_headers else "none observed")
    )
    lines.append(
        f"{indent}security headers missing: "
        + (", ".join(missing_headers) if missing_headers else "none observed")
    )
    if web.robots:
        status = web.robots.status if web.robots.status is not None else "request failed"
        lines.append(f"{indent}robots.txt: {status} | {web.robots.url}")
        if web.robots.disallowed_paths:
            lines.append(
                f"{indent}robots disallow: "
                + ", ".join(web.robots.disallowed_paths)
            )
        if web.robots.error:
            lines.append(f"{indent}robots error: {web.robots.error}")
    return lines

def render_text(report: ScanReport) -> str:
    """Render human-readable text output with nested finding details."""
    lines: list[str] = [
        "RECON HELPER",
        f"engine: {report.engine}",
        (
            f"targets: {len(report.hosts)} | "
            f"ports per target: {len(report.ports)} | "
            f"duration: {report.duration_ms} ms"
        ),
    ]
    for host in report.hosts:
        lines.extend(("", f"{host.target} ({host.address or 'unresolved'})"))
        if host.error:
            lines.append(f"  error: {host.error}")
        elif not host.open_ports:
            lines.append("  no selected TCP ports responded")
        else:
            for finding in host.open_ports:
                lines.append(
                    f"  {finding.port}/tcp open  hint: {finding.service}  "
                    f"{finding.latency_ms:.2f} ms"
                )
                if finding.detected_service:
                    lines.append(
                        f"    banner identifies: {finding.detected_service}"
                    )
                if getattr(finding, "url", None):
                    lines.append(f"    url: {finding.url}")
                if finding.web:
                    lines.extend(render_web_details(finding.web))
                if finding.banner:
                    lines.append(f"    banner: {finding.banner}")
    return "\n".join(lines)

def render_table(report: ScanReport) -> str:
    headings = (
        "TARGET", "ADDRESS", "PORT", "HINT",
        "DETECTED", "LATENCY", "HTTP", "URL",
    )
    rows = [
        (
            host.target,
            host.address or "-",
            str(finding.port),
            finding.service,
            finding.detected_service or "-",
            f"{finding.latency_ms:.2f} ms",
            str(finding.web.status) if finding.web else "-",
            getattr(finding, "url", None) or "-",
        )
        for host in report.hosts
        for finding in host.open_ports
    ]
    if not rows:
        return "No selected TCP ports responded."
    widths = [
        max(len(headings[index]), *(len(row[index]) for row in rows))
        for index in range(len(headings))
    ]

    def format_row(row_values: tuple[str, ...]) -> str:
        return "  ".join(
            value.ljust(widths[index]) for index, value in enumerate(row_values)
        )

    return "\n".join(
        (
            format_row(headings),
            format_row(tuple("-" * width for width in widths)),
            *(format_row(row) for row in rows),
        )
    )

def render(report: ScanReport, output_format: str) -> str:
    """Format selector supporting text, json, and table views."""
    formatters = {
        "json": render_json,
        "table": render_table,
        "text": render_text,
    }
    formatter = formatters.get(output_format.lower(), render_text)
    return formatter(report)

def write_report(
    report: ScanReport,
    path: Path,
    output_format: str,
) -> None:
    """Save a report without overwriting an existing file."""
    content = render(report, output_format) + "\n"
    with path.open("x", encoding="utf-8") as output_file:
        output_file.write(content)