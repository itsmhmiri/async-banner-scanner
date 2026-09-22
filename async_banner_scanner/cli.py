"""Command-Line Interface (CLI) parser and execution entrypoint for Async Banner Scanner."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time
from typing import List, Optional

from rich.console import Console

from async_banner_scanner import __version__
from async_banner_scanner.models import ScanResult, TransportProtocol
from async_banner_scanner.output import (
    create_progress_bar,
    export_csv,
    export_json,
    print_results_table,
)
from async_banner_scanner.scanner import run_scanner
from async_banner_scanner.target_parser import generate_targets

import shutil

console = Console(force_terminal=True, width=shutil.get_terminal_size((100, 24)).columns)


def build_parser() -> argparse.ArgumentParser:
    """Construct and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="async-scanner",
        description="Asynchronous TCP/UDP Port and Service Banner Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        required=True,
        help="Target IP, FQDN, CIDR (e.g. 192.168.1.0/24), or file path",
    )
    parser.add_argument(
        "-p",
        "--ports",
        dest="ports",
        default=None,
        help="Port list (e.g. 21,22,80) or range (e.g. 1-1024)",
    )
    parser.add_argument(
        "--top-ports",
        dest="top_ports",
        type=int,
        choices=[100, 1000],
        default=None,
        help="Scan top N most common ports (100 or 1000)",
    )
    parser.add_argument(
        "-u",
        "--udp",
        dest="udp",
        action="store_true",
        help="Scan UDP ports instead of TCP",
    )
    parser.add_argument(
        "--protocol",
        dest="protocol",
        choices=["tcp", "udp", "all"],
        default=None,
        help="Transport protocol to scan: tcp, udp, or all (default: tcp)",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        dest="concurrency",
        type=int,
        default=200,
        help="Max concurrent asynchronous workers (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=1.5,
        help="Connection timeout in seconds (default: 1.5)",
    )

    # Banner grabbing options
    banner_group = parser.add_mutually_exclusive_group()
    banner_group.add_argument(
        "--no-banner",
        dest="grab_banner",
        action="store_false",
        help="Skip active banner grabbing (pure port scan)",
    )
    banner_group.add_argument(
        "--grab-banner",
        dest="grab_banner",
        action="store_true",
        help="Explicitly enable active banner grabbing (default)",
    )
    parser.set_defaults(grab_banner=True)

    # Export formats
    parser.add_argument(
        "-oJ",
        "--json",
        dest="output_json",
        metavar="FILE",
        default=None,
        help="Export results to JSON file",
    )
    parser.add_argument(
        "-oC",
        "--csv",
        dest="output_csv",
        metavar="FILE",
        default=None,
        help="Export results to CSV file",
    )

    # Verbosity & Version
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose diagnostic logging and display all port statuses",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def setup_logging(verbose: bool) -> None:
    """Configure standard logging level and formatting."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


async def async_main(args: argparse.Namespace) -> int:
    """Execute asynchronous scanning workflow based on parsed arguments."""
    console.width = shutil.get_terminal_size((100, 24)).columns

    # Determine transport protocols to scan
    if args.protocol == "all":
        protocols = (TransportProtocol.TCP, TransportProtocol.UDP)
    elif args.protocol == "udp" or args.udp:
        protocols = (TransportProtocol.UDP,)
    else:
        protocols = (TransportProtocol.TCP,)

    # 1. Parse targets and ports
    try:
        targets = list(
            generate_targets(
                target_spec=args.target,
                ports_spec=args.ports,
                top_ports=args.top_ports,
                protocols=protocols,
            )
        )
    except Exception as err:
        console.print(f"[bold red]Error parsing targets/ports:[/bold red] {err}")
        return 1

    if not targets:
        console.print("[bold yellow]No valid targets resolved. Please check your target specification.[/bold yellow]")
        return 1

    proto_label = "/".join(p.value.upper() for p in protocols)
    console.print(
        f"[bold blue]Async Banner Scanner v{__version__}[/bold blue] | "
        f"Protocol: [cyan]{proto_label}[/cyan] | "
        f"Queued [cyan]{len(targets)}[/cyan] target probes | "
        f"Concurrency: [cyan]{args.concurrency}[/cyan] | "
        f"Timeout: [cyan]{args.timeout}s[/cyan]"
    )

    # 2. Run scan with live progress bar
    results: List[ScanResult] = []
    t_start = time.perf_counter()

    with create_progress_bar(console=console) as progress:
        task_id = progress.add_task("Scanning ports...", total=len(targets))

        def on_result(res: ScanResult) -> None:
            results.append(res)
            progress.update(task_id, advance=1)

        try:
            await run_scanner(
                targets=targets,
                concurrency=args.concurrency,
                timeout=args.timeout,
                grab_banner=args.grab_banner,
                on_result=on_result,
            )
        except asyncio.CancelledError:
            console.print("\n[yellow]Scan interrupted. Processing partial results...[/yellow]")

    duration = time.perf_counter() - t_start

    # 3. Output results table
    print_results_table(
        results=results,
        console=console,
        show_all=args.verbose,
        duration_sec=duration,
    )

    # 4. File exports
    if args.output_json:
        try:
            export_json(results, args.output_json)
            console.print(f"[green]✔[/green] Exported JSON results to [bold]{args.output_json}[/bold]")
        except Exception as err:
            console.print(f"[bold red]Failed to export JSON:[/bold red] {err}")

    if args.output_csv:
        try:
            export_csv(results, args.output_csv)
            console.print(f"[green]✔[/green] Exported CSV results to [bold]{args.output_csv}[/bold]")
        except Exception as err:
            console.print(f"[bold red]Failed to export CSV:[/bold red] {err}")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint handling argument parsing and graceful interruption."""
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose)

    # Handle graceful termination on SIGINT (Ctrl+C)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    main_task = loop.create_task(async_main(args))

    def handle_sigint() -> None:
        if not main_task.done():
            main_task.cancel()

    try:
        loop.add_signal_handler(signal.SIGINT, handle_sigint)
    except (NotImplementedError, RuntimeError):
        # Fallback for environments where add_signal_handler is unsupported
        pass

    try:
        return loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan aborted by user.[/yellow]")
        return 130
    finally:
        loop.close()


if __name__ == "__main__":
    sys.exit(main())
