# Recon Helper

A developing Python command-line project created to reinforce my understanding of networking, HTTP and basic reconnaissance methodology.

The project combines a small set of common checks into one readable workflow. It is a learning tool rather than a replacement for established reconnaissance utilities.

## Current Features

- Hostname / URL normalisation
- DNS resolution
- Common TCP port scanning
- Banner grabbing
- HTTP response details
- Page title detection
- Redirect tracking
- Technology hints
- Security header checks
- robots.txt checks
- Enumeration information
- Priority grouping

## Requirements

- Python 3.10 or later
- Dependencies listed in `requirements.txt`

Create and activate a virtual environment, then install the dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

```bash
python recon.py
```

Enter a hostname or URL when prompted. Example:

```text
enter target host or URL: example.com
```

Only run reconnaissance against systems you own or have explicit permission to test.

## How It Works

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

The results are observations that require interpretation. For example, an unresponsive port may be closed, filtered or omitted from the scan list, while a missing HTTP header does not by itself prove that an application is vulnerable.

## Current Limitations

- Static port priority
- Limited OSINT enrichment
- Common-port scan only
- Technology detection is basic
- Priority is not yet evidence-aware

## Development Direction

Future development may include:

- Evidence-based prioritisation
- Better DNS / OSINT enrichment
- TLS / certificate information
- Sitemap parsing
- Improved technology detection
- Cleaner final summary

The development focus is on understanding each addition and keeping the code clear, explainable and proportionate to the project's learning purpose.
