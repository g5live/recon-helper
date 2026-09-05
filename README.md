# Recon Helper

A developing Python command-line project created to reinforce my understanding of networking, HTTP and basic reconnaissance methodology.

The project combines a small set of common checks into one readable workflow. It is a learning tool rather than a replacement for established reconnaissance utilities.

## Current Features

- Accepts a hostname or URL and normalises the input
- Resolves the target hostname to an IPv4 address
- Checks a defined set of common TCP ports
- Attempts basic banner collection from responsive services
- Selects HTTP or HTTPS when a common web port is detected
- Reports HTTP status, selected response headers, size and response time
- Displays the final URL and number of redirects followed
- Extracts basic technology hints from headers and HTML
- Checks the presence of common security headers
- Reviews selected `robots.txt` directives

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
Select an available web service
        ↓
Inspect the HTTP response
        ↓
Report technology and security observations
```

The results are observations that require interpretation. For example, an unresponsive port may be closed, filtered or omitted from the scan list, while a missing HTTP header does not by itself prove that an application is vulnerable.

## Current Limitations

- Uses IPv4 hostname resolution
- Checks only the ports defined in `COMMON_PORTS`
- Runs checks sequentially
- Performs lightweight banner collection rather than protocol-specific interrogation
- Checks web services only when TCP ports 80 or 443 respond
- Does not currently provide command-line arguments or persistent report output

## Development Direction

Future development may include:

- Command-line arguments and help output
- Configurable ports and timeouts
- Structured result objects and report output
- Improved error reporting
- Tests for input normalisation and response handling
- IPv6-aware resolution

The development focus is on understanding each addition and keeping the code clear, explainable and proportionate to the project's learning purpose.
