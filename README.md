![G5LIVE — Build · Understand · Apply](assets/brand/g5live.svg)

# Recon Helper

Recon Helper is a learning-focused Python command-line project for authorised TCP reconnaissance. It accepts hostnames, URLs, individual addresses and bounded CIDR networks, then returns structured evidence rather than treating an open port as a vulnerability.

### Target files

Use `-iL` or `--target-file` to read targets from a UTF-8 file:
```bash
python recon.py -iL targets.txt --ports 22,80,443
```

Place one target per line. Blank lines and lines beginning with `#`
are ignored. Targets can be IP addresses, hostnames, URLs or CIDRs.

Command-line targets can be combined with file targets:

```bash
python recon.py localhost -iL targets.txt --ports 22,80
```

Both sources use the same normalisation, deduplication and CIDR
expansion logic. The default limit is 256 unique expanded targets
across both sources; change it deliberately with `--max-hosts`.

CIDRs expand incrementally so oversized ranges are rejected without
first collecting every address.

Unreadable files, or files containing no targets when no command-line
targets are supplied, return exit code 2 without starting a scan.

### Port presets

Select a small named TCP port set:
```bash
python recon.py localhost --preset web
python recon.py localhost --preset remote
```

- `web`: 80, 443, 8080, 8443
- `remote`: 22, 23, 3389

Presets select ports only; HTTP inspection still requires `--http`.
These sets are not exhaustive, and port numbers do not confirm service identity.

Use either `--preset` or `--ports`; supplying both is rejected.
Without either option, the existing default port set is used.

## Current Features

- Native hostname, URL, IP and CIDR input
- CIDR expansion guard with `--max-hosts`
- Bounded asynchronous scanning with `asyncio.open_connection()`
- Optional threaded `socket.connect()` engine for comparison
- Selectable ports and ranges
- Structured result objects
- Text, table and JSON output
- Opt-in HTTP inspection with status, redirects, title and response metadata
- Context-aware security-header observations and structured `robots.txt` paths
- Evidence-led technology hints from headers, generator metadata and HTML paths
- Standard-library logging to stderr and optional log files
- Graceful `SIGINT`/`Ctrl+C` exit status
- Mocked unit tests that do not scan live targets
- Original web-enrichment workflow retained temporarily behind `--legacy`

## Install

```bash
git clone https://github.com/g5live/recon-helper.git
cd recon-helper
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Only run reconnaissance against systems you own or have explicit permission to test.

## Examples

Interactive single-target scan:

```bash
recon-helper
```

Specific ports with table output:

```bash
recon-helper 192.0.2.10 --ports 22,80,443 --format table
```

Bounded lab network with JSON output:

```bash
recon-helper 192.0.2.0/29 --ports 22,80,443 --format json
```

Inspect discovered web services and preserve the evidence as JSON:

```bash
recon-helper 192.0.2.10 --ports 80,443,8080,8443 --http --format json
```

Compare the blocking socket implementation, safely dispatched through worker threads:

```bash
recon-helper 192.0.2.10 --engine socket --ports 22,80
```

Write operational logs separately from findings:

```bash
recon-helper 192.0.2.10 --log-level INFO --log-file recon.log --format json
```

Run the original interactive HTTP/technology checks:

```bash
recon-helper --legacy
```

Press `Ctrl+C` to send `SIGINT`; Recon Helper cancels the run and returns shell status `130`.

## Structure

```text
recon-helper/
├── recon/
│   ├── __init__.py
│   ├── cli.py         # Arguments, logging, SIGINT and entry point
│   ├── scanner.py     # CIDR expansion and socket/async scanning
│   ├── protocols.py   # Service metadata, probes and banner handling
│   ├── web.py         # Structured HTTP inspection
│   ├── output.py      # Text, table and JSON renderers
│   └── legacy.py      # Temporary interactive enumeration workflow
├── tests/
│   └── test_scanner.py
├── pyproject.toml
└── README.md
```

The boundaries are deliberate:

```text
input → scanner → structured result → output renderer
           │
           └─ operational logging to stderr/file
```

This keeps machine-readable JSON free from progress messages and allows tests to verify decisions without scraping terminal text.

## Test

```bash
python -m unittest discover -v
```

Tests use `unittest.mock` to replace network connections and HTTP responses. They verify CIDR expansion, safety limits, port parsing, both engines, HTTP inspection, renderers, JSON structure and SIGINT handling without touching external systems.

## Current Limits and Next Stage

- TCP only; UDP services require a separate scanner and protocol-specific logic.
- Service names are port-based hints and still need validation.
- TLS certificate inspection is not yet implemented.
- HTTP inspection is deliberately opt-in with `--http` because it sends additional requests to discovered services.
- Technology hints are observations that require confirmation; they are not definitive product or version identification.

## Planned Roadmap

1. Target and port ingestion
   - -iL targets.txt
   - --top-ports 100
   - Named presets such as --preset web and --preset remote
   - Combine files, CIDRs, hostnames, and CLI targets safely
2. Service validation
   - Distinguish port-based service hints from confirmed protocols
   - Add bounded protocol-specific probes
   - Record hinted_service, detected_service, and supporting evidence
   - Improve SSH and FTP banner interpretation
3. TLS inspection
   - Certificate subject and issuer
   - SAN hostnames
   - Validity period and expiry
   - TLS version and cipher observations
   - Clear handling of self-signed lab certificates
4. Rate and interruption controls
   - Requests-per-second or connection-delay limits
   - Preserve completed findings when interrupted
   - Render or save partial results after Ctrl+C
   - Keep concurrency and rate limiting as separate controls
5. Direct file export
   - -oJ results.json
   - -oT results.txt
   - Optional table export
   - Safe overwrite behaviour and useful exit codes
6. UDP scanning
   - Separate UDP engine
   - Protocol-specific probes for DNS, SNMP, NTP, and TFTP
   - Distinguish open, closed, and open|filtered
   - Conservative defaults because UDP scanning behaves differently from TCP
7. Test expansion
   - Parser edge cases and invalid inputs
   - Timeouts, partial interruption, rate limiting, TLS, and file exports
   - Output-schema regression tests
   - pytest adoption if its fixtures and parameterisation add value; the current unittest suite is already valid
8. Public release preparation
   - Versioning and changelog
   - Licence and contribution guidance
   - CI test workflow
   - Installation and usage examples
   - Supported Python versions
   - Clear authorised-use scope
   - Build and installation testing in a clean environment
## Shared brand and release preparation

Part of the G5LIVE app family. See the [shared brand guide](assets/brand/BRAND.md) and [project-specific release-readiness review](docs/RELEASE_READINESS.md) for proposed functionality and public-release preparation.

## Guided terminal start

Run the main file without arguments:

```bash
cd ~/Projects/Pycharm/recon-helper
.venv/bin/python recon.py
```

Enter your target IP, hostname, URL or CIDR at the Target address(es) prompt. Multiple targets can be separated with spaces. Press Enter at the ports prompt for the default common ports, or supply a list such as 22,80,443. Type q at the target prompt to exit.

In PyCharm, run `recon.py` with no script parameters and use the project `.venv/bin/python` interpreter. Click in the Run console to type your answers. Ctrl+C cancels input. Existing argument-based usage and `--help` remain available.
