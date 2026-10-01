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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence-led TCP reconnaissance helper")
    parser.add_argument("targets", nargs="*", help="hostname, URL, IP address, or CIDR network")
    parser.add_argument("--ports", type=parse_ports, help="comma-separated ports and ranges")
    parser.add_argument("--engine", choices=("async", "socket"), default="async")
    parser.add_argument("--format", choices=("text", "table", "json"), default="text")
    parser.add_argument("--timeout", type=float, default=0.75)
    parser.add_argument("--banner-timeout", type=float, default=0.35)
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
    args = build_parser().parse_args(argv)
    if args.legacy:
        legacy_main()
        return 0

    targets = args.targets
    if not targets:
        entered = input("target host, URL, IP or CIDR: ").strip()
        targets = [entered]

    configure_logging(args.log_level, args.log_file)
    options = {
        "engine": args.engine,
        "timeout": args.timeout,
        "banner_timeout": args.banner_timeout,
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
