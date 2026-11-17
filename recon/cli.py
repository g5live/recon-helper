"""Argument parsing, logging, SIGINT handling, and command-line entry point."""
from __future__ import annotations
import argparse
import asyncio
import logging
import sys
from pathlib import Path
from recon.legacy import main as legacy_main
from recon.output import render, write_report
from recon.scanner import TargetError, scan
from recon.udp import scan_udp
from xml.etree.ElementTree import ParseError
from recon.compare import compare_scans
from recon.evidence import SavedScan, load_nmap_xml, load_recon_json
from recon.retest import render_retest_summary

PORT_PRESETS: dict[str, tuple[int, ...]] = {
    "web": (80, 443, 8080, 8443),
    "remote": (22, 23, 3389),}

def parse_ports(value: str) -> tuple[int, ...]:
    ports: set[int] = set()
    try:
        for item in value.split(","):
            part = item.strip()
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
    except ValueError as error:
        raise argparse.ArgumentTypeError("ports must look like 22,80,8000-8010") from error
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    return tuple(sorted(ports))

def read_target_file(path: Path) -> list[str]:
    targets: list[str] = []
    try:
        with path.open(encoding="utf-8") as target_file:
            for line in target_file:
                target = line.strip()
                if not target or target.startswith("#"):
                    continue
                targets.append(target)
    except (OSError, UnicodeError) as error:
        raise TargetError(
            f"cannot read target file {path}: {error}"
        ) from error
    return targets

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="G5LIVE Recon Helper — gather useful clues from TCP and UDP services",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog,
            max_help_position=36,
            width=100,),)
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.75,
        metavar="SECONDS",
        help="how long to wait for a TCP connection or UDP response (default: 0.75 seconds)",)
    parser.add_argument("targets", nargs="*", help="hostname, URL, IP address, or CIDR network")
    parser.add_argument(
        "-iL",
        "--target-file",
        type=Path,
        help="read targets from a file, one per line",)
    port_selection = parser.add_mutually_exclusive_group()
    port_selection.add_argument(
        "--ports",
        type=parse_ports,
        help="comma-separated ports and ranges",)
    port_selection.add_argument(
        "--preset",
        choices=PORT_PRESETS,
        help="select a named port set",)
    parser.add_argument("--udp", action="store_true", help="scan UDP only; requires explicit --ports")
    parser.add_argument("--engine", choices=("async", "socket"), default="async")
    parser.add_argument("--format", choices=("text", "table", "json"), default="text")
    parser.add_argument(
        "--explain",
        action="store_true",
        help="add plain-English guidance to text output and text exports",)
    file_output = parser.add_mutually_exclusive_group()
    file_output.add_argument(
        "-oJ",
        "--output-json",
        type=Path,
        metavar="FILE",
        help="save JSON results to a new file",)
    file_output.add_argument(
        "-oT",
        "--output-text",
        type=Path,
        help="save text results to a new file",)
    file_output.add_argument(
        "-oA", "--output-table", type=Path,
        help="save a compact table to a new file",)
    parser.add_argument(
        "--probe-rate", type=float,
        help="maximum TCP or UDP probe dispatches per second across all hosts (not HTTP/TLS request rate)",)
    parser.add_argument("--banner-timeout", type=float, default=0.35)
    parser.add_argument(
        "--http",
        action="store_true",
        help="inspect discovered HTTP services",)
    parser.add_argument(
        "--tls",
        action="store_true",
        help="check TLS and certificate details on selected open ports",)
    parser.add_argument(
        "--tls-ports",
        type=parse_ports,
        default=(443, 8443),
        metavar="PORTS",
        help="ports eligible for TLS inspection with --tls (default: 443,8443)",)
    parser.add_argument(
        "--smtp-starttls-ports", type=parse_ports, metavar="PORTS", default=(),
        help="request SMTP STARTTLS on selected open TCP ports (no --tls needed)",)
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=5.0,
        help="HTTP request timeout in seconds",)
    parser.add_argument(
        "--tls-timeout",
        type=float,
        default=3.0,
        help="TLS socket-operation timeout in seconds", )
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--max-hosts", type=int, default=256)
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="WARNING")
    parser.add_argument("--log-file", type=Path)
    parser.add_argument("--legacy", action="store_true", help="run the original interactive web workflow")
    return parser

def configure_logging(level: str, log_file: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,)

def load_saved_scan(path: Path) -> SavedScan:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return load_recon_json(path)
    if suffix == ".xml":
        return load_nmap_xml(path)
    raise ValueError(f"Expected a .json or .xml scan file: {path}")

def compare_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="recon-helper compare",
        description="Compare two saved scans without sending probes.",)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("retest", type=Path)
    parser.add_argument("--summary", action="store_true", help="print a Markdown retest summary",)
    args = parser.parse_args(arguments)
    try:
        baseline = load_saved_scan(args.baseline)
        retest = load_saved_scan(args.retest)
        deltas = compare_scans(baseline, retest)
    except (OSError, ValueError, ParseError, KeyError, TypeError, OverflowError) as error:
        print(f"Cannot compare scans: {error}", file=sys.stderr)
        return 2
    if args.summary:
        print(render_retest_summary(baseline, retest, deltas))
        return 0
    print(f"Baseline: {args.baseline} ({baseline.source})")
    print(f"Retest:   {args.retest} ({retest.source})")
    print("These are recorded outcomes. Scope and vantage point have not been verified.")
    for label, scan in (("Baseline", baseline), ("Retest", retest)):
        if scan.interrupted is True:
            print(f"{label} was interrupted; its observations are partial.")
    if not deltas:
        print("Neither file contains explicit port observations.")
    for delta in deltas:
        address, protocol, port = delta.endpoint
        before = delta.before.outcome if delta.before else "not observed"
        after = delta.after.outcome if delta.after else "not observed"
        print(f"{address} {port}/{protocol}: {before} -> {after} ({delta.kind})")
        for tls_change in delta.tls_changes:
            print(f"  TLS: {tls_change}")
    return 0

def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["compare"]:
        return compare_main(arguments[1:])
    args = build_parser().parse_args(arguments)
    if args.udp:
        if args.ports is None:
            print("Error: --udp requires explicit --ports.", file=sys.stderr)
            return 2
        if args.legacy or args.engine != "async" or args.http or args.tls or args.smtp_starttls_ports:
            print("Error: --udp cannot be combined with TCP/legacy inspection options or the socket engine.", file=sys.stderr)
            return 2
    if args.legacy:
        legacy_main()
        return 0

    targets = list(args.targets)
    if args.target_file is not None:
        try:
            file_targets = read_target_file(args.target_file)
        except TargetError as error:
            print(f"Error: {error}", file=sys.stderr)
            return 2
        targets.extend(file_targets)
        if not targets:
            print("Error: no usable targets supplied.", file=sys.stderr)
            return 2
    if not targets:
        try:
            print('\nG5LIVE Recon Helper — start here', file=sys.stderr)
            print('Enter an IP address, hostname, URL or CIDR. Separate multiple targets with spaces.', file=sys.stderr)
            print('Example: 127.0.0.1    Type q to exit.', file=sys.stderr)
            while not targets:
                entered = input('Target address(es): ').strip()
                if entered.lower() in ('q', 'quit', 'exit'):
                    return 0
                targets = entered.split()
                if not targets:
                    print('Please enter at least one target.', file=sys.stderr)
            if not arguments:
                while True:
                    entered_ports = input('Ports (Enter for the default common ports; e.g. 22,80,443): ').strip()
                    if not entered_ports:
                        break
                    try:
                        args.ports = parse_ports(entered_ports)
                        break
                    except argparse.ArgumentTypeError as error:
                        print(str(error), file=sys.stderr)
        except EOFError:
            print('Input ended. Run with --help for command-line usage.', file=sys.stderr)
            return 0
        except KeyboardInterrupt:
            print('\nCancelled.', file=sys.stderr)
            return 130

    configure_logging(args.log_level, args.log_file)
    options = {
        "engine": args.engine,
        "timeout": args.timeout,
        "banner_timeout": args.banner_timeout,
        "inspect_http": args.http,
        "http_timeout": args.http_timeout,
        "inspect_tls_enabled": args.tls,
        "tls_timeout": args.tls_timeout,
        "tls_ports": args.tls_ports,
        "smtp_starttls_ports": args.smtp_starttls_ports,
        "concurrency": args.concurrency,
        "max_hosts": args.max_hosts,
        "probe_rate": args.probe_rate,
        "preserve_on_cancel": True,}
    if args.ports is not None:
        options["ports"] = args.ports
    elif args.preset is not None:
        options["ports"] = PORT_PRESETS[args.preset]
    try:
        if args.udp:
            report = asyncio.run(scan_udp(
                targets, ports=args.ports, timeout=args.timeout,
                concurrency=args.concurrency, max_hosts=args.max_hosts,
                probe_rate=args.probe_rate, preserve_on_cancel=True,))
        else:
            report = asyncio.run(scan(targets, **options))
    except KeyboardInterrupt:
        logging.getLogger(__name__).warning("scan interrupted by SIGINT")
        return 130
    except (TargetError, ValueError) as error:
        logging.getLogger(__name__).error("%s", error)
        return 2
    sys.stdout.write(render(report, args.format, explain=args.explain) + "\n")
    try:
        if args.output_json is not None: write_report(report, args.output_json, "json")
        elif args.output_text is not None: write_report(report, args.output_text, "text", explain=args.explain,)
        elif args.output_table is not None: write_report(report, args.output_table, "table")
    except OSError as error:
        logging.getLogger(__name__).error("could not save report: %s", error)
        return 130 if report.interrupted else 1
    return 130 if report.interrupted else 0

if __name__ == "__main__":
    raise SystemExit(main())
