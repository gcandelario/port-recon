"""
Command-line interface for the port scanner.

Entry point: `portscanner` (configured in setup.py console_scripts).
"""

import sys
from pathlib import Path

from rich.console import Console

from .core import PortScanner, ScanMode
from .reporter import Reporter

_err = Console(stderr=True, highlight=False)


def build_parser():
    """Build and return the argument parser."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="portscanner",
        description=(
            "A professional Python TCP port scanner with service detection, "
            "banner grabbing, and multiple output formats."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  portscanner scanme.nmap.org
  portscanner 192.168.1.1 -p 22,80,443,8000-9000
  portscanner 10.0.0.1 --top-100 -t 2 --threads 200
  portscanner example.com --full -o results.json
  portscanner example.com -p 1-1000 --format csv -o results.csv --show-closed
        """,
    )

    # Target
    parser.add_argument("host", help="Target hostname or IP address")

    # Port selection (mutually exclusive group)
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports",
        metavar="PORTS",
        help=(
            "Port specification: single (80), range (1-1024), "
            "or comma-separated (22,80,443,8000-8080). Default: 1-1024"
        ),
        default="1-1024",
    )
    port_group.add_argument(
        "--top-100",
        action="store_true",
        help="Scan the top 100 most common ports",
    )
    port_group.add_argument(
        "--full",
        action="store_true",
        help="Scan all 65535 ports (slow)",
    )

    # Scan tuning
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Per-port connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        metavar="N",
        help="Number of concurrent scanning threads (default: 100)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing (faster)",
    )

    # Output
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        metavar="FORMAT",
        help="Export format when -o is used: json or csv (default: json)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save results to FILE in the chosen --format",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Include closed/filtered ports in the terminal table",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Suppress the live progress bar",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    return parser


def main() -> int:
    """
    CLI entry point.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = build_parser()
    args = parser.parse_args()

    # --- Validate arguments ---
    if args.timeout <= 0:
        _err.print("[red]Error:[/red] --timeout must be greater than 0.")
        return 1
    if args.threads < 1 or args.threads > 2000:
        _err.print("[red]Error:[/red] --threads must be between 1 and 2000.")
        return 1

    # --- Determine scan mode and port list ---
    if args.top_100:
        mode = ScanMode.TOP_100
    elif args.full:
        mode = ScanMode.FULL_RANGE
    else:
        mode = ScanMode.TCP_CONNECT

    try:
        ports = PortScanner.build_port_list(
            mode=mode,
            port_range=args.ports if mode == ScanMode.TCP_CONNECT else None,
        )
    except ValueError as exc:
        _err.print(f"[red]Error:[/red] Invalid port specification — {exc}")
        return 1

    # --- Run scan ---
    scanner = PortScanner(
        host=args.host,
        timeout=args.timeout,
        threads=args.threads,
        grab_banners=not args.no_banner,
    )

    try:
        summary = scanner.scan(ports, show_progress=not args.no_progress)
    except RuntimeError as exc:
        _err.print(f"[red]Error:[/red] {exc}")
        return 1
    except KeyboardInterrupt:
        _err.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return 130

    # --- Report ---
    output_path = Path(args.output) if args.output else None
    reporter = Reporter(
        summary=summary,
        output_path=output_path,
        output_format=args.format,
        show_closed=args.show_closed,
    )
    reporter.print_table()
    if output_path:
        reporter.export()

    return 0


if __name__ == "__main__":
    sys.exit(main())
