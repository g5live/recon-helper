# Recon Helper

Recon Helper is a learning-focused Python command-line project for authorised TCP reconnaissance. It accepts hostnames, URLs, individual addresses and bounded CIDR networks, then returns structured evidence rather than treating an open port as a vulnerability.

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
