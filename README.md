![G5LIVE — Build · Understand · Apply](assets/brand/g5live.svg)

# Recon Helper

A Python tool I'm building to support my cybersecurity and pentesting learning. It checks selected TCP or UDP ports, gathers service clues and helps me decide what to investigate next.

**Build · Understand · Apply:** build something useful, understand what the results mean, then apply that knowledge in a lab.

Only use it on systems you own or have permission to test. An open port is a starting point for investigation, not proof of a vulnerability.

## Get started

Requires **Python 3.11 or newer**.

```bash
git clone https://github.com/g5live/recon-helper.git
cd recon-helper
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Run `python recon.py` for target and port prompts, or pass your choices directly. In PyCharm, run `recon.py` using the project's virtual environment. Type `q` at the target prompt to quit.

```bash
# Check selected ports and show a table
python recon.py 127.0.0.1 --ports 22,80,443 --format table --probe-rate 2 -oA table.txt

# Read targets from a file and save JSON
python recon.py -iL targets.txt --preset web -oJ results.json

# Add HTTP and TLS inspection on an authorised lab target
python recon.py lab.example --preset web --http --tls

# Add explanations and inspect TLS certificates
python recon.py localhost --ports 8443 --tls --explain

# Check SMTP STARTTLS on an authorised mail service
python recon.py 127.0.0.1 --ports 2525 --smtp-starttls-ports 2525

# Send UDP probes on explicitly selected ports
python recon.py 127.0.0.1 --udp --ports 53,123 --format table
```

The installed `recon-helper` command accepts the same options. Use `python recon.py --help` for the full list.

## Choose targets, ports and output

| Choice | How it works |
|---|---|
| Targets | IP addresses, hostnames, URLs or CIDR ranges; URLs supply the hostname, while ports are selected separately |
| Target files | `-iL targets.txt` / `--target-file`; one target per line, with blanks and full-line `#` comments ignored |
| Combined targets | CLI and file entries are combined, duplicates removed and CIDRs expanded as needed |
| Host limit | Default: 256 unique expanded targets across all inputs; change deliberately with `--max-hosts` |
| Custom ports | `--ports 22,80,8000-8010` |
| Presets | `--preset web`: 80, 443, 8080, 8443; `--preset remote`: 22, 23, 3389 |
| Probe pacing | `--probe-rate 2`: dispatch at most two TCP or UDP probes per second across all hosts; separate from `--concurrency` |
| Terminal output | `--format text`, `table` or `json` |
| File export | `-oJ results.json`, `-oT results.txt` or `-oA table.txt`; independent of terminal format |

Use either custom ports or a preset. With neither, the tool uses its default port set. Presets are small convenience lists and do not enable HTTP or TLS inspection.

Exports create new files only; existing files are never overwritten and parent directories must exist. If saving fails, terminal findings remain available.

## Read the results

**Port hints and banners:** `HINT` / `service` is the usual service associated with that port. `DETECTED` / `detected_service` records supported banner evidence: SSH identification lines or `220` greetings explicitly naming FTP. Generic greetings remain unidentified. The captured banner is kept alongside the result; advertised software and versions still need checking.

**HTTP (`--http`):** adds requests to collect status, redirects, page title, selected headers, security-header observations and `robots.txt` paths. Technology clues are observations to follow up, not verified product identification.

**TLS:** `--tls` starts TLS directly on open ports 443 and 8443 by default. Set `--tls-ports` to replace that list. For SMTP, use `--smtp-starttls-ports` to opt into the SMTP greeting and STARTTLS upgrade on the selected open TCP ports. Neither option adds ports to the scan. If both modes are enabled, their lists must not overlap.

Both modes verify certificate trust, validity and target identity. They report the TLS version, cipher, certificate names and expiry on success. Verification errors leave the open TCP finding in the report. SMTP inspection sends no mail or credentials.

**UDP (`--udp`):** requires explicit `--ports`. A reply from the selected endpoint is `open`; a port refusal reported by the OS is `closed`; silence after a sent probe is `open|filtered`. Other socket failures are reported separately. UDP results and service hints do not prove what application is listening.

**Explanations (`--explain`):** adds plain-English guidance to text output and text exports: what a finding means, what remains unknown and what to check next. HTTP and TLS guidance can both appear for the same port. Tables and JSON retain their usual format.

Text and JSON show detailed findings; the table gives a compact view. Logs go to stderr, or a file with `--log-file recon.log`, separately from result output.

## Current limits

- UDP uses a DNS query on port 53 and a one-byte probe elsewhere. Many services ignore a generic probe. UDP runs separately from TCP; `--top-ports` is not implemented.
- SSH/FTP banner recognition is limited and does not authenticate the service. FTP banners that omit the word FTP can be missed.
- STARTTLS is SMTP only. Unverified certificate details are not collected.
- Probe pacing covers transport probes only; optional HTTP/TLS connections, HTTP redirects and packets are outside this limit.
- Ctrl+C preserves observations available when cancellation finishes. Running socket/HTTP/TLS threads may need their timeouts to finish; a second Ctrl+C can force exit before export.

Press **Ctrl+C once** to stop and display/export a clearly marked partial report using your selected output options. Unfinished checks are never reported as confirmed negative findings. `CHECKS: pending` means an open port was observed but further inspection did not finish. See [run controls and partial reports](docs/RUN_CONTROLS.md).

Exit codes: **0** completed or normal prompt exit; **1** export failed; **2** invalid input; **130** interrupted with Ctrl+C.

## Compare scans and write a retest note

Use Nmap for broad discovery, then use Recon Helper to follow up on selected services in your authorised scope. Save the follow-up as JSON so you can compare it with a later run.

```bash
python recon.py 127.0.0.1 --ports 9443 --tls --tls-ports 9443 -oJ baseline.json
# After the change, repeat the check with the same target and options.
python recon.py 127.0.0.1 --ports 9443 --tls --tls-ports 9443 -oJ retest.json
python recon.py compare baseline.json retest.json
python recon.py compare baseline.json retest.json --summary
```

`compare` accepts Recon Helper JSON and Nmap XML (`-oX`) and does not send probes. `--summary` prints a short Markdown retest note. A missing observation does not mean a port closed or a finding was fixed. For certificate comparisons, use two Recon Helper reports with fingerprints from the same target name or IP and TLS mode.

## Next steps

Next: capture more scan context so retest reports can flag differences in scope and network vantage point. See the [roadmap](docs/ROADMAP.md) and [release checklist](docs/RELEASE_READINESS.md).

## Development and tests

The main flow is **input → scan → findings → output**. The code separates CLI handling, scanning, protocol clues, HTTP/TLS inspection and formatting so each part can be understood and tested.

```bash
python -m unittest discover -s tests -v
```

Tests cover transport outcomes, TLS verification, and interrupted reports as well as parsing and exports.

Part of the G5LIVE app family. See the [brand guide](assets/brand/BRAND.md) and [release-readiness notes](docs/RELEASE_READINESS.md).
