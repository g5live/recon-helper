"""Render structured scan results without coupling scanning to ``print()``."""

from __future__ import annotations

import json

from recon.scanner import ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def render_text(report: ScanReport) -> str:
    lines = [
        "RECON HELPER",
        f"engine: {report.engine}",
        f"targets: {len(report.hosts)} | ports per target: {len(report.ports)} | duration: {report.duration_ms} ms",
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
                    f"  {finding.port}/tcp open  {finding.service}  {finding.latency_ms:.2f} ms"
                )
                if finding.banner:
                    lines.append(f"    banner: {finding.banner}")
    return "\n".join(lines)


def render_table(report: ScanReport) -> str:
    headings = ("TARGET", "ADDRESS", "PORT", "SERVICE", "LATENCY")
    rows = [
        (host.target, host.address or "-", str(finding.port), finding.service, f"{finding.latency_ms:.2f} ms")
        for host in report.hosts
        for finding in host.open_ports
    ]
    if not rows:
        return "No selected TCP ports responded."
    widths = [max(len(headings[index]), *(len(row[index]) for row in rows)) for index in range(len(headings))]
    format_row = lambda row: "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
    return "\n".join((format_row(headings), format_row(tuple("-" * width for width in widths)), *(format_row(row) for row in rows)))


def render(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "table":
        return render_table(report)
    return render_text(report)
