"""
cli.py — aport command-line interface entry point.

Usage:
  aport list         [--proto tcp|udp|all] [--state listen|established|all] [--verbose] [--json]
  aport port <PORT>  [--json]
  aport watch        [--interval N] [--proto tcp|udp|all] [--state listen|established|all]
  aport top          [--limit N]
  aport services     [--port PORT]
"""

from __future__ import annotations

import sys
import time
import os

# Force UTF-8 output on Windows terminals.
# Guarded so it never crashes in environments without a .buffer
# attribute (IDLE, pythonw, GUI-hosted terminals).
if sys.platform == "win32":
    import io
    for _stream_name in ("stdout", "stderr"):
        _stream = getattr(sys, _stream_name, None)
        if _stream is None:
            continue
        # Prefer reconfigure() — available on Python 3.7+ TextIOWrapper
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            # Fallback: wrap the underlying buffer if it exists
            _buf = getattr(_stream, "buffer", None)
            if _buf is not None:
                try:
                    setattr(sys, _stream_name,
                            io.TextIOWrapper(_buf, encoding="utf-8", errors="replace"))
                except Exception:
                    pass  # give up gracefully; don't crash the process
    for _tmp in ("_stream_name", "_stream", "_buf"):
        try:
            del globals()[_tmp]
        except KeyError:
            pass
    del _tmp

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich import box

from apprt.scanner import PortScanner
from apprt import display

console = Console(force_terminal=True)


# ── helpers ───────────────────────────────────────────────────────────────────

def _need_admin_hint() -> None:
    """Emit a tip about running as Administrator on Windows."""
    import platform
    if platform.system() == "Windows":
        console.print(
            "[dim yellow][TIP] Run as Administrator for full port/process visibility.[/]"
        )


def _spinner_scan(scanner: PortScanner) -> dict:
    """Run scan with a spinner."""
    with console.status("[bold bright_cyan]Scanning ports...[/]", spinner="dots12"):
        snap = scanner.snapshot()
    return snap


# ── root group ────────────────────────────────────────────────────────────────

@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option("1.0.0", "-V", "--version", message="apprt %(version)s")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """
    \b
    +-------------------------------------------+
    |   apprt - Advanced Port Inspector CLI     |
    |   Lists open ports & per-port activity    |
    +-------------------------------------------+

    Run 'apprt list' to see all open ports.
    Run 'apprt --help' for all commands.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ── list command ──────────────────────────────────────────────────────────────

@cli.command("list")
@click.option("--proto",   default="all",  type=click.Choice(["tcp", "udp", "all"], case_sensitive=False),
              show_default=True, help="Filter by protocol.")
@click.option("--state",   default="all",  type=click.Choice(["listen", "established", "all"], case_sensitive=False),
              show_default=True, help="Filter by connection state.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show per-port process info and connection details.")
@click.option("--json",    "as_json", is_flag=True, default=False,
              help="Output raw JSON.")
def cmd_list(proto: str, state: str, verbose: bool, as_json: bool) -> None:
    """List all open ports with process and activity information."""
    _need_admin_hint()
    scanner = PortScanner(proto_filter=proto, state_filter=state)
    snap    = _spinner_scan(scanner)

    if as_json:
        display.render_json(snap)
    else:
        display.render_overview(snap, verbose=verbose)


# ── port command ──────────────────────────────────────────────────────────────

@cli.command("port")
@click.argument("port_num", metavar="PORT", type=int)
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON.")
def cmd_port(port_num: int, as_json: bool) -> None:
    """Show detailed info for a specific PORT number."""
    _need_admin_hint()
    scanner = PortScanner()
    snap    = _spinner_scan(scanner)

    if as_json:
        import dataclasses, json
        ports = [p for p in snap["ports"] if p.port == port_num]
        snap_copy = dict(snap)
        snap_copy["ports"] = [dataclasses.asdict(p) for p in ports]
        console.print_json(json.dumps(snap_copy, indent=2))
    else:
        display.render_port_detail(snap, port_num)


# ── watch command ─────────────────────────────────────────────────────────────

@cli.command("watch")
@click.option("--interval", "-i", default=2, type=float, show_default=True,
              help="Refresh interval in seconds.")
@click.option("--proto",   default="all",
              type=click.Choice(["tcp", "udp", "all"], case_sensitive=False),
              show_default=True)
@click.option("--state",   default="all",
              type=click.Choice(["listen", "established", "all"], case_sensitive=False),
              show_default=True)
def cmd_watch(interval: float, proto: str, state: str) -> None:
    """Live-refresh port table (press Ctrl-C to exit)."""
    _need_admin_hint()
    scanner = PortScanner(proto_filter=proto, state_filter=state)
    console.print("[dim]Press [bold]Ctrl-C[/] to stop.[/dim]\n")

    try:
        with Live(console=console, refresh_per_second=1, screen=False) as live:
            while True:
                snap  = scanner.snapshot()
                table = display.render_watch(snap)
                live.update(table)
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Watch stopped.[/]")


# ── top command ───────────────────────────────────────────────────────────────

@cli.command("top")
@click.option("--limit", "-n", default=10, type=int, show_default=True,
              help="Number of ports to show (sorted by connection count).")
def cmd_top(limit: int) -> None:
    """Show top ports ranked by number of active connections."""
    _need_admin_hint()
    scanner = PortScanner()
    snap    = _spinner_scan(scanner)
    ports   = snap["ports"]

    # Sort by connection count descending
    ports_sorted = sorted(ports, key=lambda p: len(p.connections), reverse=True)[:limit]

    table = Table(
        title=f"[bold bright_green]TOP {limit} Ports by Connection Count[/]",
        box=box.SQUARE,
        border_style="green",
        header_style="bold bright_yellow on grey11",
        show_lines=True,
        expand=True,
    )
    table.add_column("Rank",        justify="right",  width=5)
    table.add_column("Port",        justify="right",  width=7)
    table.add_column("Proto",       justify="center", width=7)
    table.add_column("Service",     width=12)
    table.add_column("State",       justify="center", width=14)
    table.add_column("Connections", justify="right",  width=12)
    table.add_column("PID",         justify="right",  width=7)
    table.add_column("Process",     width=22)
    table.add_column("CPU%",        justify="right",  width=6)
    table.add_column("MEM (MB)",    justify="right",  width=10)

    for i, p in enumerate(ports_sorted, 1):
        table.add_row(
            str(i),
            str(p.port),
            display._proto_text(p.proto),
            p.service,
            display._state_text(p.state),
            str(len(p.connections)),
            str(p.pid) if p.pid else "-",
            p.process_name[:22],
            f"{p.process_cpu_percent:.1f}",
            f"{p.process_memory_mb:.1f}",
        )

    console.print()
    console.print(table)
    console.print()


# ── services command ──────────────────────────────────────────────────────────

@cli.command("services")
@click.option("--port", "-p", default=None, type=int,
              help="Resolve service name for a specific port.")
def cmd_services(port: int | None) -> None:
    """Look up well-known service names for open ports."""
    _need_admin_hint()
    scanner = PortScanner()
    snap    = _spinner_scan(scanner)
    ports   = snap["ports"]

    if port is not None:
        ports = [p for p in ports if p.port == port]

    table = Table(
        title="[bold bright_green]Port -> Service Name Map[/]",
        box=box.SQUARE,
        border_style="green",
        header_style="bold bright_yellow on grey11",
        expand=False,
    )
    table.add_column("Port",    justify="right", width=7)
    table.add_column("Proto",   justify="center", width=7)
    table.add_column("Service", style="bright_yellow", width=20)
    table.add_column("State",   justify="center", width=14)

    for p in ports:
        table.add_row(str(p.port), display._proto_text(p.proto), p.service, display._state_text(p.state))

    console.print()
    console.print(table)
    console.print()


# ── monitor command ───────────────────────────────────────────────────────────

@cli.command("monitor")
@click.option("--interval", "-i", default=2.0, type=float, show_default=True,
              help="Refresh interval in seconds.")
@click.option("--limit", "-n", default=25, type=int, show_default=True,
              help="Max number of processes to display.")
@click.option("--sort", "-s", default="cpu",
              type=click.Choice(["cpu", "mem", "pid", "name", "conn"], case_sensitive=False),
              show_default=True, help="Column to sort processes by.")
@click.option("--filter", "-f", "filter_name", default="", show_default=False,
              help="Only show processes whose name contains this string.")
def cmd_monitor(interval: float, limit: int, sort: str, filter_name: str) -> None:
    """Live system + process monitor dashboard (htop-style).

    \b
    Panels:
      - System header : CPU bars per-core, RAM, Swap, uptime
      - Process table : sorted by CPU/MEM/PID/NAME/CONN with disk I/O rates
      - Network I/O   : per-NIC send/recv rates + totals
      - Disk I/O      : per-disk read/write rates + totals
      - Top ports     : ports ranked by active connection count
    """
    from apprt.monitor import run_monitor
    run_monitor(interval=interval, limit=limit, sort_by=sort, filter_name=filter_name)


# ── action commands ───────────────────────────────────────────────────────────

@cli.command("kill")
@click.argument("port", type=int)
@click.option("--force", "-f", is_flag=True, help="Force kill without confirmation.")
def cmd_kill(port: int, force: bool) -> None:
    """Kill the process listening on the specified port."""
    _need_admin_hint()
    from apprt.actions import kill_port
    kill_port(port, force=force)

@cli.command("transfer")
@click.argument("port", type=int)
def cmd_transfer(port: int) -> None:
    """Move the process on PORT to a random free port (original port stays open).

    Finds an unoccupied random port, re-launches (or reconfigures) the
    process that currently owns PORT so it binds on the new port, then
    displays a side-by-side before/after comparison of both ports.
    The original process and port are NOT killed.
    """
    _need_admin_hint()
    from aport.actions import transfer_port
    transfer_port(port)


# ── shell command ─────────────────────────────────────────────────────────────

@cli.command("shell")
def cmd_shell() -> None:
    """Interactive REPL shell -- colourful dashboard with typed commands."""
    from aport.shell import run_shell
    run_shell()


# ── clear / cls commands ──────────────────────────────────────────────────────

def _clear_terminal() -> None:
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")

@cli.command("clear")
def cmd_clear() -> None:
    """Clear the terminal screen."""
    _clear_terminal()

@cli.command("cls")
def cmd_cls() -> None:
    """Clear the terminal screen (alias for clear)."""
    _clear_terminal()


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    cli()


if __name__ == "__main__":
    main()

