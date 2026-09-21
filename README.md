# Recon Helper

Recon Helper is a developing Python command-line project that combines early reconnaissance checks into one readable workflow. I built it to reinforce networking, HTTP and Python concepts by turning separate observations into a structured starting point for enumeration.

It is a learning project and workflow aid, not a replacement for established tools such as Nmap, Burp Suite or dedicated OSINT utilities.

## Current Features

- Hostname and URL normalisation
- DNS resolution
- Common TCP port scanning
- Basic banner collection
- HTTP response and redirect details
- Page-title and technology hints
- Security-header observations
- `robots.txt` checks
- Service-led enumeration guidance
- Priority grouping for follow-up work

## Quick Start

Requirements:

- Python 3.10 or later
- The packages listed in `requirements.txt`

Create an isolated environment and install the dependencies:

```bash
git clone https://github.com/g5live/recon-helper.git
cd recon-helper
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python recon.py
```

Enter a hostname or URL when prompted:

```text
enter target host or URL: example.com
```

Only run reconnaissance against systems you own or have explicit permission to test.

## Workflow

```text
Normalise target input
        ↓
Resolve hostname
        ↓
Check common TCP ports
        ↓
Collect available banners
        ↓
Select an available web service
        ↓
Inspect the HTTP response
        ↓
Report technology and security observations
        ↓
Check robots.txt
        ↓
Prioritise enumeration by discovered services
```

The output is intended to support the next decision, not make that decision automatically.

> An open port is a lead, not a vulnerability. A missing security header is an observation, not proof that an application can be exploited.

For example, an unresponsive port may be closed, filtered or outside the limited scan list. A technology hint may also be incomplete or misleading, so important findings should be confirmed with a purpose-built tool.

## What the Stages Teach

- **Input handling** — separating hostnames, URLs and schemes before testing.
- **DNS and ports** — connecting names, addresses, services and likely attack surface.
- **HTTP inspection** — understanding status codes, redirects, headers and response metadata.
- **Enumeration choices** — choosing a next step from evidence instead of running every tool by habit.
- **Python development** — practising functions, error handling, third-party packages and readable terminal output.

## Current Limitations

- Scans a small, predefined group of TCP ports and does not test UDP.
- Banner collection and technology identification are deliberately basic.
- Service priority is static rather than evidence- or risk-based.
- DNS and OSINT enrichment are limited.
- Results are not a vulnerability assessment and still require manual validation.

## Project Files

```text
recon-helper/
├── recon.py          # Main interactive workflow
├── requirements.txt  # Python dependencies
├── README.md
└── .gitignore
```

## Development Direction

Planned areas for incremental development include:

- Evidence-based prioritisation
- Better DNS and OSINT enrichment
- TLS and certificate information
- Sitemap discovery
- Improved technology detection
- A clearer final findings summary
- Automated tests for the core checks

The focus is to understand and explain each addition, keeping the project proportionate to its purpose as a bridge between Python study and practical security methodology.
