"""Render structured scan results without coupling scanning to ``print()``."""
from __future__ import annotations
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recon.scanner import ScanReport

def render_json(report: ScanReport) -> str:
    """Serialize the scan report to a formatted JSON string."""
    return json.dumps(report.to_dict(), indent=2)

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
                    f"  {finding.port}/tcp open  {finding.service}  "
                    f"{finding.latency_ms:.2f} ms"
                )
                if getattr(finding, "url", None):
                    lines.append(f"    url: {finding.url}")
                if finding.banner:
                    lines.append(f"    banner: {finding.banner}")

    return "\n".join(lines)

def render_table(report: ScanReport) -> str:
    headings = ("TARGET", "ADDRESS", "PORT", "SERVICE", "LATENCY", "URL")
    rows = [
        (
            host.target,
            host.address or "-",
            str(finding.port),
            finding.service,
            f"{finding.latency_ms:.2f} ms",
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