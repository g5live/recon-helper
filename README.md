![G5LIVE — Build · Understand · Apply](assets/brand/g5live.svg)

# Recon Helper

A Python tool I'm building to support my cybersecurity and pentesting learning. It checks selected TCP ports, gathers service clues and helps me decide what to investigate next.

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

# Inspect TLS on a custom lab port
python recon.py localhost --ports 9443 --tls --tls-ports 9443
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
| TCP pacing | `--probe-rate 2`: dispatch at most two TCP probes per second across all hosts; separate from `--concurrency` |
| Terminal output | `--format text`, `table` or `json` |
| File export | `-oJ results.json`, `-oT results.txt` or `-oA table.txt`; independent of terminal format |

Use either custom ports or a preset. With neither, the tool uses its default port set. Presets are small convenience lists and do not enable HTTP or TLS inspection.

Exports create new files only; existing files are never overwritten and parent directories must exist. If saving fails, terminal findings remain available.

## Read the results

**Port hints and banners:** `HINT` / `service` is the usual service associated with that port. `DETECTED` / `detected_service` records supported banner evidence: SSH identification lines or `220` greetings explicitly naming FTP. Generic greetings remain unidentified. The captured banner is kept alongside the result; advertised software and versions still need checking.

**HTTP (`--http`):** adds requests to collect status, redirects, page title, selected headers, security-header observations and `robots.txt` paths. Technology clues are observations to follow up, not verified product identification.

**TLS (`--tls`):** checks TLS on selected open ports, using 443 and 8443 by default. Use `--tls-ports` to replace that selection, for example `--tls-ports 443,8443,9443`. This does not add ports to the TCP scan: include them in `--ports` or select a suitable preset. TLS inspection still requires `--tls`.

Records TLS version, cipher and certificate details when verification succeeds, including the number of whole days remaining before expiry.

Verification checks certificate trust, validity and whether the certificate matches the target hostname or IP address. Failures are recorded without discarding the open-port finding. Certificate dates may be unavailable when verification fails.

**Explanations (`--explain`):** adds plain-English guidance to text output and text exports: what a finding means, what remains unknown and what to check next. HTTP and TLS guidance can both appear for the same port. Tables and JSON retain their usual format.

Text and JSON show detailed findings; the table gives a compact view. Logs go to stderr, or a file with `--log-file recon.log`, separately from result output.

## Current limits

- TCP only. UDP and `--top-ports` are not implemented.
- SSH/FTP banner recognition is limited and does not authenticate the service. FTP banners that omit the word FTP can be missed.
- TLS inspection attempts a direct TLS connection on selected ports. STARTTLS and unverified certificate details remain pending.
- Probe pacing covers TCP dispatches only; optional HTTP/TLS connections, HTTP redirects and packets are outside this limit.
- Ctrl+C preserves observations available when cancellation finishes. Running socket/HTTP/TLS threads may need their timeouts to finish; a second Ctrl+C can force exit before export.

Press **Ctrl+C once** to stop and display/export a clearly marked partial report using your selected output options. Unfinished checks are never reported as confirmed negative findings. `CHECKS: pending` means an open port was observed but further inspection did not finish. See [run controls and partial reports](docs/RUN_CONTROLS.md).

Exit codes: **0** completed or normal prompt exit; **1** export failed; **2** invalid input; **130** interrupted with Ctrl+C.

## Next steps

- Broaden service checks and TLS coverage.
- Add sourced top-port selections.
- Build UDP scanning as a separate engine.
- Expand edge-case tests and prepare releases: changelog, licence, contribution guidance, CI and clean installation checks.

## Development and tests

The main flow is **input → scan → findings → output**. The code separates CLI handling, scanning, protocol clues, HTTP/TLS inspection and formatting so each part can be understood and tested.

```bash
python -m unittest discover -s tests -v
```

The current checkpoint is **63 passing tests**. Local HTTPS checks also confirmed both rejection of an untrusted self-signed certificate and successful verification when that certificate was explicitly trusted for the command.

Part of the G5LIVE app family. See the [brand guide](assets/brand/BRAND.md) and [release-readiness notes](docs/RELEASE_READINESS.md).
