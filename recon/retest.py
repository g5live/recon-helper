"""Turn recorded scan differences into a short retest note."""

from recon.compare import EndpointDelta
from recon.evidence import SavedScan

def render_retest_summary(
    baseline: SavedScan,
    retest: SavedScan,
    deltas: tuple[EndpointDelta, ...],
) -> str:
    lines = [
        "# Retest summary",
        "",
        f"- Baseline: {baseline.source} ({baseline.started_at or 'time not recorded'})",
        f"- Retest: {retest.source} ({retest.started_at or 'time not recorded'})",
        "- Scan scope and network vantage point have not been independently verified.",]
    if baseline.interrupted is True or retest.interrupted is True:
        lines.append("- At least one scan was interrupted; its observations are partial.")
    lines.extend(("", "## Changes and gaps", ""))
    entries = []
    for delta in deltas:
        address, protocol, port = delta.endpoint
        endpoint = f"`{address}` on `{port}/{protocol}`"
        before, after = delta.before, delta.after
        if before is None and after is not None:
            entries.append(
                f"- {endpoint}: recorded as `{after.outcome}` in the retest. "
                "No baseline observation is available.")
        elif after is None:
            reason = (
                "The port was outside the retest’s recorded port selection."
                if retest.requested_ports and port not in retest.requested_ports
                else "No retest observation was recorded.")
            entries.append(f"- {endpoint}: status not reassessed. {reason}")
        elif before.outcome != after.outcome:
            entries.append(
                f"- {endpoint}: the baseline recorded `{before.outcome}`; "
                f"the retest recorded `{after.outcome}`.")
        if after is not None and "certificate fingerprint changed" in delta.tls_changes:
            verified = (after.tls or {}).get("certificate_verified") is True
            detail = " The retest certificate verified successfully." if verified else ""
            entries.append(f"- {endpoint}: the TLS certificate changed.{detail}")
        if "verification result changed" in delta.tls_changes:
            entries.append(f"- {endpoint}: the TLS verification result changed.")

    lines.extend(entries or ["- No changes or evidence gaps were identified in the recorded observations."])
    return "\n".join(lines)