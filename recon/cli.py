"""Argument parsing, logging, SIGINT handling, and command-line entry point."""
from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
import sys

from recon.legacy import main as legacy_main
from recon.output import render
from recon.scanner import TargetError, scan

def parse_ports(value: str) -> tuple[int, ...]:
    ports: set[int] = set()
    try:
        for item in value.split(","):
            part = item.strip()
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start > end:
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
    parser = argparse.ArgumentParser(description="G5LIVE Recon Helper — evidence-led TCP reconnaissance")
    parser.add_argument("targets", nargs="*", help="hostname, URL, IP address, or CIDR network")
    parser.add_argument(
        "-iL",
        "--target-file",
        type=Path,
        help="read targets from a file, one per line",
    )
    parser.add_argument("--ports", type=parse_ports, help="comma-separated ports and ranges")
    parser.add_argument("--engine", choices=("async", "socket"), default="async")
    parser.add_argument("--format", choices=("text", "table", "json"), default="text")
    parser.add_argument("--timeout", type=float, default=0.75)
    parser.add_argument("--banner-timeout", type=float, default=0.35)
    parser.add_argument(
        "--http",
        action="store_true",
        help="inspect discovered HTTP services",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=5.0,
        help="HTTP request timeout in seconds",
    )
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
        force=True,
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(arguments)
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
        "concurrency": args.concurrency,
        "max_hosts": args.max_hosts,
    }
    if args.ports is not None:
        options["ports"] = args.ports

    try:
        report = asyncio.run(scan(targets, **options))
    except KeyboardInterrupt:
        logging.getLogger(__name__).warning("scan interrupted by SIGINT")
        return 130
    except (TargetError, ValueError) as error:
        logging.getLogger(__name__).error("%s", error)
        return 2

    sys.stdout.write(render(report, args.format) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
