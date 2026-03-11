"""
Output formatting and export for scan results.

Supports rich colored terminal tables, JSON, and CSV output formats.
"""

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .core import ScanResult, ScanSummary


# Single console instance used throughout so colour/width are consistent
_console = Console(highlight=False)
_err_console = Console(stderr=True, highlight=False)


class Reporter:
    """
    Renders scan results to the terminal and optionally writes export files.

    Args:
        summary: Completed ScanSummary to render.
        output_path: Optional file path for JSON or CSV export.
        output_format: 'json' or 'csv' (only used when output_path is given).
        show_closed: Include closed/filtered ports in the terminal table.
    """

    def __init__(
        self,
        summary: ScanSummary,
        output_path: Optional[Path] = None,
        output_format: str = "json",
        show_closed: bool = False,
    ) -> None:
        self.summary = summary
        self.output_path = output_path
        self.output_format = output_format.lower()
        self.show_closed = show_closed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def print_table(self) -> None:
        """Print a rich-formatted results table to stdout."""
        _console.print()
        _console.print(self._build_header_panel())
        _console.print()
        _console.print(self._build_results_table())
        _console.print()
        _console.print(self._build_summary_panel())
        _console.print()

    def export(self) -> None:
        """Write results to the configured output file (JSON or CSV)."""
        if self.output_path is None:
            return
        if self.output_format == "json":
            self._export_json()
        elif self.output_format == "csv":
            self._export_csv()
        else:
            _err_console.print(
                f"[yellow]Warning:[/yellow] Unknown format '{self.output_format}', skipping export."
            )

    # ------------------------------------------------------------------
    # Terminal rendering helpers
    # ------------------------------------------------------------------

    def _build_header_panel(self) -> Panel:
        s = self.summary
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        content = (
            f"[bold cyan]Target:[/bold cyan]    {s.target_host} ([italic]{s.target_ip}[/italic])\n"
            f"[bold cyan]Ports:[/bold cyan]     {s.total_ports:,} scanned\n"
            f"[bold cyan]Duration:[/bold cyan]  {s.scan_duration_s:.2f}s\n"
            f"[bold cyan]Timestamp:[/bold cyan] {ts}"
        )
        return Panel(content, title="[bold white]PortScanner[/bold white]", border_style="cyan")

    def _build_results_table(self) -> Table:
        show_all = self.show_closed
        rows = self.summary.results if show_all else self.summary.open_results

        table = Table(
            box=box.ROUNDED,
            border_style="bright_black",
            header_style="bold white",
            show_lines=False,
            expand=False,
        )
        table.add_column("PORT", style="bold", justify="right", min_width=6)
        table.add_column("STATE", justify="center", min_width=10)
        table.add_column("SERVICE", min_width=18)
        table.add_column("LATENCY", justify="right", min_width=10)
        table.add_column("BANNER", min_width=30, max_width=60)

        for r in rows:
            table.add_row(
                str(r.port),
                self._state_badge(r.state),
                r.service,
                f"{r.latency_ms:.1f} ms",
                Text(r.banner or "—", style="dim"),
            )

        if not rows:
            table.add_row(
                "—", "—", "No open ports found", "—", "—"
            )
        return table

    def _build_summary_panel(self) -> Panel:
        s = self.summary
        rate = s.total_ports / s.scan_duration_s if s.scan_duration_s else 0
        content = (
            f"[bold green]  Open[/bold green]      {s.open_count:>6,}\n"
            f"[bold red]  Closed[/bold red]    {s.closed_count:>6,}\n"
            f"[bold yellow]  Filtered[/bold yellow]  {s.filtered_count:>6,}\n"
            f"[dim]  Rate       {rate:>6,.0f} ports/s[/dim]"
        )
        return Panel(content, title="[bold white]Summary[/bold white]", border_style="cyan")

    @staticmethod
    def _state_badge(state: str) -> Text:
        styles = {
            "open":     ("OPEN",     "bold green"),
            "closed":   ("CLOSED",   "bold red"),
            "filtered": ("FILTERED", "bold yellow"),
        }
        label, style = styles.get(state, (state.upper(), "white"))
        return Text(label, style=style)

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def _export_json(self) -> None:
        s = self.summary
        data = {
            "meta": {
                "target_host": s.target_host,
                "target_ip": s.target_ip,
                "total_ports": s.total_ports,
                "scan_duration_s": s.scan_duration_s,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "open": s.open_count,
                "closed": s.closed_count,
                "filtered": s.filtered_count,
            },
            "results": [
                {
                    "port": r.port,
                    "state": r.state,
                    "service": r.service,
                    "banner": r.banner,
                    "latency_ms": r.latency_ms,
                }
                for r in s.results
            ],
        }
        path = self.output_path
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _console.print(f"[green]JSON report saved:[/green] {path}")

    def _export_csv(self) -> None:
        path = self.output_path
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["port", "state", "service", "latency_ms", "banner"],
            )
            writer.writeheader()
            for r in self.summary.results:
                writer.writerow(
                    {
                        "port": r.port,
                        "state": r.state,
                        "service": r.service,
                        "latency_ms": r.latency_ms,
                        "banner": r.banner,
                    }
                )
        _console.print(f"[green]CSV report saved:[/green] {path}")
