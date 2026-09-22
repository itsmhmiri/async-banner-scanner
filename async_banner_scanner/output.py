"""Output formatting, terminal reporting (Rich), JSON, and CSV export utilities."""

from __future__ import annotations

import csv
import json
import os
from typing import Optional, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from async_banner_scanner.models import PortStatus, ScanResult


def create_progress_bar(console: Optional[Console] = None) -> Progress:
    """Create a configured Rich Progress instance for scan tracking.

    Args:
        console: Optional existing Rich Console instance.

    Returns:
        Configured Progress object.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def export_json(results: Sequence[ScanResult], file_path: str) -> None:
    """Export scan results to a formatted JSON file.

    Args:
        results: Sequence of ScanResult instances.
        file_path: Destination file path.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    data = [res.to_dict() for res in results]
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_csv(results: Sequence[ScanResult], file_path: str) -> None:
    """Export scan results to a standard CSV file with headers.

    Args:
        results: Sequence of ScanResult instances.
        file_path: Destination file path.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    fieldnames = [
        "host",
        "port",
        "protocol",
        "status",
        "latency_ms",
        "service_name",
        "service_version",
        "banner_raw",
        "timestamp",
    ]

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for res in results:
            writer.writerow(res.to_dict())


def print_results_table(
    results: Sequence[ScanResult],
    console: Optional[Console] = None,
    show_all: bool = False,
    duration_sec: Optional[float] = None,
) -> None:
    """Render a styled Rich terminal table displaying port scan results.

    Args:
        results: Sequence of ScanResult objects.
        console: Optional Rich Console.
        show_all: If True, include CLOSED and FILTERED ports in the table.
                  If False, only OPEN ports are rendered in the table.
        duration_sec: Total scan runtime in seconds for summary display.
    """
    if console is None:
        console = Console()

    table = Table(
        title="[bold blue]Scan Results[/bold blue]",
        header_style="bold magenta",
        show_lines=False,
        expand=False,
    )

    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Latency (ms)", justify="right", style="magenta")
    table.add_column("Service", style="bold blue")
    table.add_column("Banner / Version", style="green", overflow="fold")

    # Filter rows to display
    display_results = [r for r in results if show_all or r.status == PortStatus.OPEN]

    for res in display_results:
        # Style status column
        if res.status == PortStatus.OPEN:
            status_styled = "[bold green]OPEN[/bold green]"
        elif res.status == PortStatus.CLOSED:
            status_styled = "[red]CLOSED[/red]"
        elif res.status == PortStatus.OPEN_FILTERED:
            status_styled = "[dim yellow]OPEN|FILTERED[/dim yellow]"
        else:
            status_styled = "[yellow]FILTERED[/yellow]"

        latency_str = f"{res.latency_ms:.2f}" if res.latency_ms is not None else "-"
        service_str = res.service_name or "unknown"

        # Format banner or version
        if res.service_version and res.banner_raw:
            banner_ver = f"{res.service_version} ({res.banner_raw[:60]}...)" if len(res.banner_raw) > 60 else f"{res.service_version} ({res.banner_raw})"
        elif res.service_version:
            banner_ver = res.service_version
        elif res.banner_raw:
            banner_ver = res.banner_raw[:80] + ("..." if len(res.banner_raw) > 80 else "")
        else:
            banner_ver = "-"

        port_display = f"{res.port}/{res.protocol.value}" if hasattr(res, "protocol") and res.protocol else str(res.port)

        table.add_row(
            res.host,
            port_display,
            status_styled,
            latency_str,
            service_str,
            banner_ver,
        )

    console.print()
    if display_results:
        console.print(table)
    else:
        console.print("[dim]No open ports discovered.[/dim]")

    # Print summary panel
    total_count = len(results)
    open_count = sum(1 for r in results if r.status == PortStatus.OPEN)
    closed_count = sum(1 for r in results if r.status == PortStatus.CLOSED)
    filtered_count = sum(1 for r in results if r.status == PortStatus.FILTERED)
    open_filtered_count = sum(1 for r in results if r.status == PortStatus.OPEN_FILTERED)

    duration_str = f" in {duration_sec:.2f}s" if duration_sec is not None else ""
    summary_text = (
        f"[bold]Total Probes:[/bold] {total_count}{duration_str} | "
        f"[bold green]Open:[/bold green] {open_count} | "
        f"[bold red]Closed:[/bold red] {closed_count} | "
        f"[bold yellow]Filtered:[/bold yellow] {filtered_count}"
    )
    if open_filtered_count > 0:
        summary_text += f" | [bold dim yellow]Open|Filtered:[/bold dim yellow] {open_filtered_count}"

    console.print(Panel(summary_text, title="[bold]Scan Summary[/bold]", border_style="blue", expand=False))
