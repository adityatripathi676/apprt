"""
monitor.py — Real-time process + system monitor dashboard for aport.

Renders a live htop-style TUI with:
  - System header : CPU bars, RAM/Swap gauges, uptime, host info
  - Process table : sortable by CPU/MEM/NET, color-coded
  - Network I/O   : per-NIC live counters
  - Port activity : top ports by connection count
"""

from __future__ import annotations

import sys
import time
import os
import socket
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

import psutil
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.style import Style

console = Console(force_terminal=True)

# ── Colour palette ────────────────────────────────────────────────────────────
_CPU_LOW    = "bright_green"
_CPU_MED    = "yellow"
_CPU_HIGH   = "red"
_MEM_LOW    = "cyan"
_MEM_HIGH   = "bright_red"

_SORT_KEYS = ["cpu", "mem", "pid", "name", "conn"]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_bytes(n: float) -> str:
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:6.1f}{u}"
        n /= 1024
    return f"{n:6.1f}P"

def _fmt_uptime(secs: float) -> str:
    td = timedelta(seconds=int(secs))
    h, rem = divmod(td.seconds, 3600)
    m, s   = divmod(rem, 60)
    days   = td.days
    if days:
        return f"{days}d {h:02d}:{m:02d}:{s:02d}"
    return f"{h:02d}:{m:02d}:{s:02d}"

def _cpu_color(pct: float) -> str:
    if pct < 50:
        return _CPU_LOW
    if pct < 85:
        return _CPU_MED
    return _CPU_HIGH

def _mem_color(pct: float) -> str:
    return _MEM_HIGH if pct > 75 else _MEM_LOW

def _bar(value: float, width: int = 20, color: str = "bright_green") -> Text:
    """Render a filled bar like  [#######   ] 35.0%"""
    filled = int(width * value / 100)
    bar    = "[" + "#" * filled + "." * (width - filled) + "]"
    t = Text()
    t.append(bar, style=f"bold {color}")
    t.append(f" {value:5.1f}%", style="white")
    return t

def _is_admin() -> bool:
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ── System header (compact, responsive) ──────────────────────────────────────

def _header_geometry(term_cols: int, n_cores: int) -> tuple[int, int, int]:
    """
    Return (cores_per_row, bar_width, header_size) based on terminal width.
    header_size = meta(1) + cpu_total(1) + core_rows(ceil(n/cpr)) + ram_swap(1) + borders(2)
    """
    if term_cols >= 180:
        cpr, bw = 8, 8
    elif term_cols >= 140:
        cpr, bw = 6, 10
    elif term_cols >= 110:
        cpr, bw = 4, 13
    else:
        cpr, bw = 2, 16
    import math
    size = math.ceil(n_cores / cpr) + 5
    return cpr, bw, size


def _make_system_header(term_cols: int = 120) -> Panel:
    """
    Compact system header — cores per row scales with terminal width so the
    panel uses as few vertical lines as possible, leaving maximum room for
    the process table.
    """
    cpu_percore = psutil.cpu_percent(percpu=True)
    cpu_total   = psutil.cpu_percent()
    mem         = psutil.virtual_memory()
    swap        = psutil.swap_memory()
    uptime      = time.time() - psutil.boot_time()
    n_cores     = psutil.cpu_count(logical=True)
    freq        = psutil.cpu_freq()
    freq_str    = f"{freq.current:.0f}MHz" if freq else "?"
    hostname    = socket.gethostname()
    admin_tag   = "[bright_green]ADMIN[/]" if _is_admin() else "[yellow]USER[/]"

    cpr, bw, _ = _header_geometry(term_cols, n_cores)

    lines: list[Text] = []

    # Row 1: identity + privilege + clock
    t = Text()
    t.append(" Host: ", style="dim")
    t.append(hostname, style="bold bright_cyan")
    t.append(f"  Cores: {n_cores}  Freq: {freq_str}  Uptime: ", style="dim")
    t.append(_fmt_uptime(uptime), style="bright_yellow")
    t.append("  Priv: ", style="dim")
    t.append_text(Text.from_markup(admin_tag))
    t.append(f"   {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}", style="dim")
    lines.append(t)

    # Row 2: overall CPU bar
    cc = _cpu_color(cpu_total)
    cpu_ln = Text(" CPU Total  ")
    cpu_ln.append_text(_bar(cpu_total, 30, cc))
    lines.append(cpu_ln)

    # Per-core rows — cpr cores per row
    for i in range(0, len(cpu_percore), cpr):
        row = Text()
        for j in range(cpr):
            idx = i + j
            if idx >= len(cpu_percore):
                break
            c = cpu_percore[idx]
            row.append(f" C{idx:<2d} ", style="dim")
            row.append_text(_bar(c, bw, _cpu_color(c)))
        lines.append(row)

    # RAM + Swap on a single line (saves one row vs separate lines)
    rl = Text(" RAM  ")
    rl.append_text(_bar(mem.percent, 20, _mem_color(mem.percent)))
    rl.append(f"  {_fmt_bytes(mem.used)}/{_fmt_bytes(mem.total)}", style="dim")
    rl.append("    Swap  ", style="dim")
    rl.append_text(_bar(swap.percent, 20, _mem_color(swap.percent)))
    rl.append(f"  {_fmt_bytes(swap.used)}/{_fmt_bytes(swap.total)}", style="dim")
    lines.append(rl)

    return Panel(
        Text("\n").join(lines),
        title="[bold bright_white]SYSTEM STATUS[/]",
        border_style="bright_blue",
        padding=(0, 1),
    )


# ── Network I/O panel (compact) ───────────────────────────────────────────────

_prev_net: dict = {}
_prev_net_time: float = 0.0

def _make_net_panel() -> Panel:
    """Compact NIC table — essential columns only, fits in a narrow column."""
    global _prev_net, _prev_net_time

    now      = time.time()
    counters = psutil.net_io_counters(pernic=True)
    dt       = now - _prev_net_time if _prev_net_time else 1.0

    table = Table(box=box.SIMPLE, show_header=True,
                  header_style="bold bright_yellow", expand=True, padding=(0, 1))
    table.add_column("NIC",      style="bright_cyan", no_wrap=True, ratio=2)
    table.add_column("↑/s",      justify="right", ratio=1)
    table.add_column("↓/s",      justify="right", ratio=1)
    table.add_column("Tx",       justify="right", ratio=1)
    table.add_column("Rx",       justify="right", ratio=1)
    table.add_column("Err",      justify="right", width=4)

    for nic, c in sorted(counters.items()):
        prev = _prev_net.get(nic)
        sent_ps = (c.bytes_sent - prev.bytes_sent) / dt if prev and dt > 0 else 0.0
        recv_ps = (c.bytes_recv - prev.bytes_recv) / dt if prev and dt > 0 else 0.0
        errs = c.errin + c.errout + c.dropin + c.dropout
        table.add_row(
            nic[:18],
            _fmt_bytes(sent_ps) + "/s",
            _fmt_bytes(recv_ps) + "/s",
            _fmt_bytes(c.bytes_sent),
            _fmt_bytes(c.bytes_recv),
            Text(str(errs), style="bright_red" if errs else "dim"),
        )

    _prev_net      = dict(counters)
    _prev_net_time = now

    return Panel(table, title="[bold bright_white]NET I/O[/]",
                 border_style="magenta", padding=(0, 0))


# ── Disk I/O panel (compact) ──────────────────────────────────────────────

_prev_disk: dict = {}
_prev_disk_time: float = 0.0

def _make_disk_panel() -> Panel:
    """Compact disk table — essential columns only, fits in a narrow column."""
    global _prev_disk, _prev_disk_time

    now      = time.time()
    dt       = now - _prev_disk_time if _prev_disk_time else 1.0
    counters = psutil.disk_io_counters(perdisk=True) or {}

    table = Table(box=box.SIMPLE, show_header=True,
                  header_style="bold bright_yellow", expand=True, padding=(0, 1))
    table.add_column("Disk",    style="bright_cyan", no_wrap=True, ratio=2)
    table.add_column("R/s",     justify="right", ratio=1)
    table.add_column("W/s",     justify="right", ratio=1)
    table.add_column("Rd Total", justify="right", ratio=1)
    table.add_column("Wr Total", justify="right", ratio=1)

    for disk, c in sorted(counters.items()):
        prev = _prev_disk.get(disk)
        r_ps = (c.read_bytes  - prev.read_bytes)  / dt if prev and dt > 0 else 0.0
        w_ps = (c.write_bytes - prev.write_bytes) / dt if prev and dt > 0 else 0.0
        table.add_row(
            disk[:16],
            _fmt_bytes(r_ps) + "/s",
            _fmt_bytes(w_ps) + "/s",
            _fmt_bytes(c.read_bytes),
            _fmt_bytes(c.write_bytes),
        )

    _prev_disk      = dict(counters)
    _prev_disk_time = now

    return Panel(table, title="[bold bright_white]DISK I/O[/]",
                 border_style="yellow", padding=(0, 0))


# ── Process table ─────────────────────────────────────────────────────────────

_prev_proc_io: dict[int, tuple] = {}

def _make_process_table(sort_by: str = "cpu", limit: int = 30,
                        filter_name: str = "") -> Panel:
    """Build the main process table."""

    now = time.time()
    procs = []

    for p in psutil.process_iter(
        ["pid", "name", "status", "cpu_percent", "memory_info",
         "num_threads", "username", "io_counters"]
    ):
        try:
            info = p.info
            if not info["name"]:
                continue
            if filter_name and filter_name.lower() not in info["name"].lower():
                continue

            mem_mb  = (info["memory_info"].rss / (1024 * 1024)) if info["memory_info"] else 0.0
            cpu_pct = info["cpu_percent"] or 0.0
            threads = info["num_threads"] or 0
            status  = info["status"] or "?"
            user    = (info["username"] or "?").split("\\")[-1][:12]

            # Fetch connections separately (not in process_iter attrs in psutil 6+)
            try:
                conns = len(p.net_connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                try:
                    conns = len(p.connections())  # psutil < 6 fallback
                except Exception:
                    conns = 0

            # Disk I/O rate
            io = info["io_counters"]
            prev_io = _prev_proc_io.get(info["pid"])
            if io and prev_io:
                dt = now - prev_io[2]
                r_ps = (io.read_bytes  - prev_io[0]) / dt if dt > 0 else 0
                w_ps = (io.write_bytes - prev_io[1]) / dt if dt > 0 else 0
            else:
                r_ps = w_ps = 0.0
            if io:
                _prev_proc_io[info["pid"]] = (io.read_bytes, io.write_bytes, now)

            procs.append({
                "pid":    info["pid"],
                "name":   info["name"],
                "status": status,
                "cpu":    cpu_pct,
                "mem":    mem_mb,
                "mem_pct": (info["memory_info"].rss / psutil.virtual_memory().total * 100)
                           if info["memory_info"] else 0.0,
                "thr":    threads,
                "user":   user,
                "conn":   conns,
                "r_ps":   r_ps,
                "w_ps":   w_ps,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort
    rev = sort_by in ("cpu", "mem", "conn")
    procs.sort(key=lambda x: x.get(sort_by, 0), reverse=rev)
    procs = procs[:limit]

    table = Table(
        box=box.MINIMAL_HEAVY_HEAD,
        border_style="bright_blue",
        header_style="bold bright_yellow on grey19",
        show_lines=False,
        expand=True,
        padding=(0, 1),
    )
    table.add_column("PID",    justify="right",  width=7)
    table.add_column("User",   width=12)
    table.add_column("Name",   width=22)
    table.add_column("Status", justify="center", width=10)
    table.add_column("CPU%",   justify="right",  width=7)
    table.add_column("MEM MB", justify="right",  width=8)
    table.add_column("MEM%",   justify="right",  width=6)
    table.add_column("THR",    justify="right",  width=5)
    table.add_column("Conns",  justify="right",  width=6)
    table.add_column("R/s",    justify="right",  width=9)
    table.add_column("W/s",    justify="right",  width=9)

    STATUS_COLORS = {
        "running":  "bright_green",
        "sleeping": "dim white",
        "idle":     "dim",
        "stopped":  "yellow",
        "zombie":   "bright_red",
        "dead":     "red",
    }

    for p in procs:
        sc = _cpu_color(p["cpu"])
        st_color = STATUS_COLORS.get(p["status"], "white")

        table.add_row(
            str(p["pid"]),
            p["user"],
            Text(p["name"][:22], style="bold white"),
            Text(p["status"][:10], style=st_color),
            Text(f"{p['cpu']:6.1f}", style=f"bold {sc}"),
            f"{p['mem']:7.1f}",
            Text(f"{p['mem_pct']:5.1f}", style=_mem_color(p["mem_pct"])),
            str(p["thr"]),
            Text(str(p["conn"]), style="cyan" if p["conn"] else "dim"),
            _fmt_bytes(p["r_ps"]) + "/s",
            _fmt_bytes(p["w_ps"]) + "/s",
        )

    sort_hint = f"[dim]sorted by [bold bright_cyan]{sort_by.upper()}[/][/dim]"
    if filter_name:
        sort_hint += f"  [dim]filter:[/dim] [yellow]{filter_name}[/]"

    return Panel(
        table,
        title=f"[bold bright_white]PROCESSES ({len(procs)} shown)[/]  {sort_hint}",
        border_style="bright_blue",
        padding=(0, 0),
    )


# ── Top ports panel ───────────────────────────────────────────────────────────

def _make_port_panel(limit: int = 12) -> Panel:
    """Show top ports by connection count from current snapshot."""
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        conns = []

    port_count: dict[tuple, int] = defaultdict(int)
    port_state: dict[tuple, str] = {}
    for c in conns:
        if c.laddr and hasattr(c.laddr, "port"):
            key = (c.laddr.port, c.type)
            port_count[key] += 1
            port_state[key] = c.status or "-"

    top = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:limit]

    table = Table(box=box.SIMPLE, show_header=True,
                  header_style="bold bright_yellow", expand=True)
    table.add_column("Port",  justify="right", width=7)
    table.add_column("Proto", justify="center", width=6)
    table.add_column("State", justify="center", width=14)
    table.add_column("Conns", justify="right",  width=6)
    table.add_column("Bar",   width=20)

    max_cnt = top[0][1] if top else 1
    PROTO_NAMES = {1: "TCP", 2: "UDP"}

    for (port, ptype), cnt in top:
        proto = PROTO_NAMES.get(ptype, str(ptype))
        state = port_state.get((port, ptype), "–")
        pct   = cnt / max_cnt * 100
        bar   = "#" * int(pct / 5)
        table.add_row(
            str(port),
            Text(proto, style="dodger_blue1" if "TCP" in proto else "orange1"),
            Text(state[:14], style="bright_green" if "LISTEN" in state else "cyan"),
            str(cnt),
            Text(f"[{'=' * int(pct/5):<20}] {cnt}", style="bright_cyan"),
        )

    return Panel(table, title="[bold bright_white]TOP PORTS[/]",
                 border_style="steel_blue1", padding=(0, 0))


# ── Help bar ──────────────────────────────────────────────────────────────────

def _make_help_bar(sort_by: str) -> Text:
    keys = {
        "c": "sort CPU",
        "m": "sort MEM",
        "n": "sort NAME",
        "p": "sort PID",
        "k": "sort CONN",
        "q": "quit",
    }
    t = Text()
    t.append(" Controls: ", style="dim bold")
    for key, desc in keys.items():
        t.append(f" [{key}]", style="bold bright_yellow")
        t.append(f" {desc} ", style="dim")
    t.append(f"   Active sort: ", style="dim")
    t.append(sort_by.upper(), style="bold bright_cyan")
    return t


def _refresh_layout_inplace(
    root: Layout,
    sort_by: str,
    filter_name: str,
    header_size: int,
    bottom_size: int,
) -> None:
    """
    Update every sub-region of *root* in place.

    Reads console.size on every call so that:
      • The process limit grows/shrinks immediately when the terminal is resized.
      • The header adjusts cores-per-row when the terminal is widened/narrowed.

    The root Layout skeleton is NEVER replaced — only sub-region renderables
    change, so Rich diffs cell-by-cell and emits minimal ANSI each cycle.
    """
    w = console.size.width
    h = console.size.height

    # Dynamic process limit: all rows not consumed by fixed regions
    # procs panel height = h - header_size - bottom_size - help(3)
    # content rows       = procs panel - borders(2) - table header(2)
    dyn_limit = max(5, h - header_size - bottom_size - 3 - 4)

    root["header"].update(_make_system_header(term_cols=w))
    root["procs"].update(
        _make_process_table(sort_by=sort_by, limit=dyn_limit, filter_name=filter_name)
    )
    root["bottom"]["net"].update(_make_net_panel())
    root["bottom"]["disk"].update(_make_disk_panel())
    root["bottom"]["ports"].update(_make_port_panel())
    root["help"].update(
        Panel(_make_help_bar(sort_by), border_style="grey30", padding=(0, 0))
    )


def _build_layout(
    sort_by: str,
    filter_name: str,
    header_size: int,
    bottom_size: int = 8,
) -> Layout:
    """
    Create the one-time Layout skeleton and populate it.

    Region heights
    --------------
    header  : fixed – computed from CPU core count + terminal width (compact)
    procs   : ratio=1 – fills ALL remaining terminal height (max process rows)
    bottom  : fixed bottom_size – split 3 ways: NET | DISK | PORTS
    help    : fixed 3 rows
    """
    root = Layout()
    root.split_column(
        Layout(name="header", size=header_size),
        Layout(name="procs",  ratio=1),          # gets everything left over
        Layout(name="bottom", size=bottom_size),
        Layout(name="help",   size=3),
    )
    # 3-column bottom row so all stats panels are visible without scrolling
    root["bottom"].split_row(
        Layout(name="net"),
        Layout(name="disk"),
        Layout(name="ports"),
    )
    _refresh_layout_inplace(root, sort_by, filter_name, header_size, bottom_size)
    return root


def run_monitor(
    interval: float = 2.0,
    limit: int = 25,
    sort_by: str = "cpu",
    filter_name: str = "",
) -> None:
    """
    Fixed dashboard with responsive, component-level updates and live controls.

    Keyboard controls
    -----------------
    c  sort by CPU%     m  sort by MEM     n  sort by name
    p  sort by PID      k  sort by conns   q  quit

    The dashboard structure (borders, panel titles, column headers) is painted
    ONCE at startup and never redrawn.  The data thread fires one live.refresh()
    per interval.  Key presses trigger an immediate additional refresh so the
    table re-sorts without waiting for the next data cycle.

    auto_refresh=False → terminal is completely still between events.
    screen=True        → alternate buffer; layout anchored, no scroll.
    """
    import threading

    psutil.cpu_percent(percpu=True)   # prime: first call always returns 0.0
    time.sleep(0.2)

    # Mutable sort state — shared between the key handler and the data thread.
    # Using a dict so the nested closure can update it without nonlocal.
    _sort = {"key": sort_by if sort_by in _SORT_KEYS else "cpu"}

    n_cores = psutil.cpu_count(logical=True) or 2
    _, _, header_size = _header_geometry(console.size.width, n_cores)
    bottom_size = 8

    root     = _build_layout(_sort["key"], filter_name, header_size, bottom_size)
    stop     = threading.Event()
    _lock    = threading.Lock()
    live_ref: list = [None]

    # ── Data thread ────────────────────────────────────────────────────────────
    def _data_loop() -> None:
        while not stop.is_set():
            stop.wait(timeout=interval)
            if stop.is_set():
                break
            try:
                with _lock:
                    _refresh_layout_inplace(
                        root, _sort["key"], filter_name, header_size, bottom_size
                    )
                live = live_ref[0]
                if live is not None:
                    live.refresh()
            except Exception:
                pass

    # ── Key → action map ──────────────────────────────────────────────────────
    _KEY_SORT = {
        'c': 'cpu',
        'm': 'mem',
        'n': 'name',
        'p': 'pid',
        'k': 'conn',
    }

    def _apply_key(key: str) -> bool:
        """Handle one keypress.  Returns False when the user wants to quit."""
        if key == 'q':
            return False
        new_sort = _KEY_SORT.get(key)
        if new_sort and new_sort != _sort["key"]:
            _sort["key"] = new_sort
            # Immediate refresh so the list re-sorts without waiting for next interval
            try:
                with _lock:
                    _refresh_layout_inplace(
                        root, _sort["key"], filter_name, header_size, bottom_size
                    )
                live = live_ref[0]
                if live is not None:
                    live.refresh()
            except Exception:
                pass
        return True

    # ── Platform key reader ───────────────────────────────────────────────────
    if sys.platform == "win32":
        import msvcrt

        def _read_key() -> Optional[str]:
            """Non-blocking read from the Windows console input buffer."""
            if not msvcrt.kbhit():
                return None
            ch = msvcrt.getch()
            # Arrow keys / function keys emit two bytes; discard the second
            if ch in (b'\x00', b'\xe0'):
                msvcrt.getch()
                return None
            try:
                return ch.decode('utf-8').lower()
            except UnicodeDecodeError:
                return None
    else:
        import select
        import tty
        import termios as _termios

        _saved_attrs = _termios.tcgetattr(sys.stdin)

        def _read_key() -> Optional[str]:
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if r:
                return sys.stdin.read(1).lower()
            return None

    # ── Main loop (key polling at 20 Hz) ─────────────────────────────────────
    worker = threading.Thread(target=_data_loop, daemon=True)

    try:
        worker.start()
        with Live(root, console=console, screen=True, auto_refresh=False) as live:
            live_ref[0] = live
            live.refresh()

            # Put terminal into raw mode on Unix so keystrokes arrive immediately
            if sys.platform != "win32":
                tty.setraw(sys.stdin.fileno())

            try:
                running = True
                while running:
                    key = _read_key()
                    if key is not None:
                        running = _apply_key(key)
                    time.sleep(0.05)   # 20 Hz poll — feels instant to the user
            finally:
                # Restore Unix terminal attributes
                if sys.platform != "win32":
                    _termios.tcsetattr(sys.stdin, _termios.TCSADRAIN, _saved_attrs)

    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        live_ref[0] = None






