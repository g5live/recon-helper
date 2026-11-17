# Recon Helper roadmap

Recon Helper helps a tester turn scan results into a clear next action or a retest note. Use Nmap for broad discovery. Import its results, then use Recon Helper for targeted follow-up on selected in-scope services, such as TLS identity or SMTP STARTTLS. Keep each check tied to the evidence it produced so a retest can explain what changed and what still needs checking. Prioritise features that deepen verification or shorten the path from observation to a defensible retest note.

## 1. Compare scans and report a retest

- Record an outcome for each TCP connection attempt. Keep refusal, timeout, other errors and untested ports distinct. Preserve the existing open findings and partial reports.
- Import Recon Helper JSON and Nmap XML into a common format. Keep the source, scope, protocol, scan settings, time, completion status and any known vantage point. Preserve original evidence and distinguish service hints from probe results.
- Add a local `compare` command. Start with port outcomes and TLS changes. Flag unequal scope or unknown coverage instead of treating missing findings as fixed.
- Generate a short, editable retest summary linked to the evidence. Start with Markdown or printable HTML; add PDF when there is a report worth exporting.

Done means a lab retest can distinguish a changed certificate, a refused connection and a port that was never retested.

## 2. Triage leads and review evidence

- Match observed product and version evidence to candidate advisories. Show the match reason, version or configuration gaps, and a suggested verification step. Do not run exploits automatically.
- Add a local review view for comparing runs, keeping notes and marking findings as reviewed. Consider shared workspaces only after the local workflow is useful on real engagements.

## 3. Map the attack surface

Link observed names, IPs, ports, services and certificates. Show where each relationship came from, when it was last seen and what changed between runs. Keep discovered leads distinct from authorised scope. Start with imported data before adding discovery integrations.

## 4. Add a cloud vantage point

Only add a collector if testing from an external network solves a real problem. Keep the collector opt-in, tied to an authorised scope, and clearly label its results with the vantage point. Local comparison and reporting should still work offline.

## 5. Add optional LLM summaries

Use an LLM to suggest wording from reviewed, selected evidence. Keep comparison, finding status and report facts deterministic. Show what data would leave the machine and require review before sharing generated text.

See [release readiness](RELEASE_READINESS.md) for work needed to package and publish the existing tool.
