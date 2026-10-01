"""Command-line entry point."""

from recon.legacy import main as legacy_main


def main() -> int:
    legacy_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())