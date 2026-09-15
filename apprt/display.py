"""
display.py — Rich-powered terminal rendering for aport.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.padding import Padding
from rich import print as rprint

if TYPE_CHECKING:
    from aport.scanner import PortInfo, Connection

console = Console(force_terminal=True)

# ── Color helpers ─────────────────────────────────────────────────────────────

_STATE_COLORS = {
    "LISTENING":    "bright_green",
    "ESTABLISHED":  "cyan",
    "TIME_WAIT":    "yellow",
    "CLOSE_WAIT":   "dark_orange",
    "SYN_SENT":     "magenta",
    "SYN_RECV":     "bright_magenta",
    "FIN_WAIT1":    "red",
    "FIN_WAIT2":    "bright_red",
    "LAST_ACK":     "red1",
    "CLOSING":      "red3",
    "CLOSED":       "grey50",
    "–":            "grey46",
}

_PROTO_COLORS = {
    "TCP":  "bright_green",
    "UDP":  "yellow",
    "TCP6": "green",
    "UDP6": "gold3",
}


def _state_text(state: str) -> Text:
    color = _STATE_COLORS.get(state, "white")
    return Text(state, style=f"bold {color}")


def _proto_text(proto: str) -> Text:
    color = _PROTO_COLORS.get(proto, "white")
    return Text(proto, style=f"bold {color}")


def _bytes_human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ── Tables ────────────────────────────────────────────────────────────────────

def make_main_table(ports: list[PortInfo]) -> Table:
    """Build the main summary table of open ports."""
    table = Table(
        title="[bold bright_green]>> Open Ports -- System Overview[/]",
        box=box.SQUARE,
        border_style="green",
        header_style="bold bright_yellow on grey11",
        show_lines=True,
        expand=True,
    )

    table.add_column("Port",        style="bold white",        justify="right", width=7)
    table.add_column("Proto",       justify="center",          width=7)
    table.add_column("Service",     style="bright_yellow",     width=12)
    table.add_column("State",       justify="center",          width=14)
    table.add_column("PID",         justify="right",           width=7)
    table.add_column("Process",     style="bright_green",      width=20)
    table.add_column("CPU%",        justify="right",           width=7)
    table.add_column("MEM (MB)",    justify="right",           width=10)
    table.add_column("Connections", justify="right",           width=12)

    for p in ports:
        table.add_row(
            str(p.port),
            _proto_text(p.proto),
            p.service,
            _state_text(p.state),
            str(p.pid) if p.pid else "–",
            p.process_name[:20],
            f"{p.process_cpu_percent:.1f}",
            f"{p.process_memory_mb:.1f}",
            str(len(p.connections)),
        )

    return table


def make_connection_table(port_info: PortInfo) -> Table:
    """Build per-port connection detail table."""
    table = Table(
        title=f"[bold bright_green]Port [bright_yellow]{port_info.port}[/] — Connections[/]",
        box=box.HEAVY_EDGE,
        border_style="yellow",
        header_style="bold bright_green on grey11",
        show_lines=False,
        expand=True,
    )

    table.add_column("Proto",       justify="center", width=7)
    table.add_column("Local Addr",  width=18)
    table.add_column("Local Port",  justify="right", width=10)
    table.add_column("Remote Addr", width=18)
    table.add_column("Remote Port", justify="right", width=11)
    table.add_column("State",       justify="center", width=14)
    table.add_column("PID",         justify="right", width=7)
    table.add_column("Process",     width=18)

    for c in port_info.connections:
        table.add_row(
            _proto_text(c.proto),
            c.local_addr,
            str(c.local_port),
            c.remote_addr if c.remote_addr else "–",
            str(c.remote_port) if c.remote_port else "–",
            _state_text(c.state),
            str(c.pid) if c.pid else "–",
            c.process_name[:18],
        )

    return table


def make_process_panel(port_info: PortInfo) -> Panel:
    """Build process metadata panel."""
    pid_str = str(port_info.pid) if port_info.pid else "–"
    content = (
        f"[bold bright_green]PID:[/]         {pid_str}\n"
        f"[bold bright_green]Name:[/]        {port_info.process_name}\n"
        f"[bold bright_green]Status:[/]      {port_info.process_status}\n"
        f"[bold bright_green]CPU:[/]         {port_info.process_cpu_percent:.2f}%\n"
        f"[bold bright_green]Memory:[/]      {port_info.process_memory_mb:.2f} MB\n"
        f"[bold bright_green]Command:[/]     {port_info.process_cmdline[:100]}"
    )
    return Panel(content, title="[bold bright_yellow]Process Info[/]", border_style="green", padding=(0, 1))


def make_netio_panel(net_io: dict) -> Panel:
    """Build system-wide network IO panel."""
    content = (
        f"[bold bright_yellow]Bytes Sent:[/]     {_bytes_human(net_io.get('bytes_sent', 0))}\n"
        f"[bold bright_yellow]Bytes Received:[/] {_bytes_human(net_io.get('bytes_recv', 0))}\n"
        f"[bold bright_yellow]Pkts Sent:[/]      {net_io.get('packets_sent', 0):,}\n"
        f"[bold bright_yellow]Pkts Received:[/]  {net_io.get('packets_recv', 0):,}"
    )
    return Panel(content, title="[bold bright_green]Network I/O[/]", border_style="yellow", padding=(0, 1))


# ── High-level renderers ──────────────────────────────────────────────────────

def render_overview(snapshot: dict, verbose: bool = False) -> None:
    """Render the full overview."""
    ports   = snapshot["ports"]
    net_io  = snapshot["net_io"]
    ts      = snapshot["timestamp"]
    host    = snapshot["host"]

    console.rule(
        f"[bold bright_green]>> aport -- Port Inspector[/]  [dim]host:[/] [bright_yellow]{host}[/]  "
        f"[dim]scan:[/] [bright_green]{ts}[/]",
        style="green",
    )
    console.print()

    if not ports:
        console.print(
            Panel("[yellow]No open ports found.[/]  "
                  "[dim](try running as Administrator for full visibility)[/dim]",
                  border_style="yellow")
        )
        return

    # Summary stats
    tcp_count  = sum(1 for p in ports if "TCP" in p.proto)
    udp_count  = sum(1 for p in ports if "UDP" in p.proto)
    est_count  = sum(1 for p in ports if p.state == "ESTABLISHED")
    list_count = sum(1 for p in ports if p.state == "LISTENING")

    stat_text = (
        f"[bold white]Total:[/] [bright_green]{len(ports)}[/]  "
        f"[bold white]TCP:[/] [bright_green]{tcp_count}[/]  "
        f"[bold white]UDP:[/] [yellow]{udp_count}[/]  "
        f"[bold white]LISTENING:[/] [bright_green]{list_count}[/]  "
        f"[bold white]ESTABLISHED:[/] [bright_yellow]{est_count}[/]"
    )
    console.print(Panel(stat_text, title="[bold bright_green]Summary Stats[/]", border_style="green", padding=(0, 2)))
    console.print()

    # Main table
    console.print(make_main_table(ports))
    console.print()

    # System net IO
    console.print(make_netio_panel(net_io))
    console.print()

    if verbose:
        for p in ports:
            console.print(make_process_panel(p))
            if p.connections:
                console.print(make_connection_table(p))
            console.print()


def render_port_detail(snapshot: dict, port_num: int) -> None:
    """Render full detail for a single port."""
    ports = [p for p in snapshot["ports"] if p.port == port_num]

    if not ports:
        console.print(f"[bold red]No data found for port {port_num}.[/]")
        return

    for p in ports:
        console.rule(
            f"[bold bright_yellow]Port {p.port} — {p.proto} — {p.service}[/]",
            style="green",
        )
        console.print()
        console.print(make_process_panel(p))
        console.print()
        if p.connections:
            console.print(make_connection_table(p))
        else:
            console.print("[dim]No connection records for this port.[/dim]")
        console.print()


def render_watch(snapshot: dict) -> Table:
    """Compact table for live-watch mode."""
    ports = snapshot["ports"]
    table = Table(
        title=f"[bold bright_green]>> aport LIVE  [dim]{snapshot['timestamp']}[/][/]",
        box=box.MINIMAL_HEAVY_HEAD,
        border_style="green",
        header_style="bold bright_yellow",
        expand=True,
    )
    table.add_column("Port",  justify="right", width=7)
    table.add_column("Proto", justify="center", width=7)
    table.add_column("Service", width=12)
    table.add_column("State",   justify="center", width=14)
    table.add_column("PID",    justify="right", width=7)
    table.add_column("Process", width=22)
    table.add_column("Conns",  justify="right", width=6)
    table.add_column("CPU%",   justify="right", width=6)

    for p in ports:
        table.add_row(
            str(p.port),
            _proto_text(p.proto),
            p.service,
            _state_text(p.state),
            str(p.pid) if p.pid else "–",
            p.process_name[:22],
            str(len(p.connections)),
            f"{p.process_cpu_percent:.1f}",
        )
    return table


def render_json(snapshot: dict) -> None:
    """Dump snapshot as pretty JSON (ports as dicts)."""
    import dataclasses

    def to_dict(obj):
        if dataclasses.is_dataclass(obj):
            return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items()}
        if isinstance(obj, list):
            return [to_dict(i) for i in obj]
        return obj

    snapshot_copy = dict(snapshot)
    snapshot_copy["ports"] = [to_dict(p) for p in snapshot["ports"]]
    console.print_json(json.dumps(snapshot_copy, indent=2))
