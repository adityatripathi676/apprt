"""
shell.py -- aport interactive shell (REPL-style dashboard).

Displays a colourful header + status bar, then drops into a
command prompt where the user types:

    aport> help
    aport> list
    aport> list tcp listen
    aport> monitor
    aport> top 10
    aport> port 443
    aport> watch
    aport> services
    aport> sysinfo
    aport> clear
    aport> exit
"""

from __future__ import annotations

import os
import sys
import time
import socket
import traceback
from datetime import datetime, timedelta

import psutil
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.live import Live

console = Console(force_terminal=True, highlight=False)

# ──────────────────────────────────────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────────────────────────────────────

_BANNER = r"""
  ______  ____  ____  ____  ______
 /  _  \ |  _ \|  _ \|  _ \|_   _|
 | |_| | | |_) | |_) | |_) | | |
 |  _  | |  __/|  __/|  _ <  | |
 |_| |_| |_|   |_|   |_| \_\ |_|
"""

_TAGLINE = "Advanced Port Inspector  --  System Network Monitor"


def _is_admin() -> bool:
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _request_elevation() -> None:
    """Re-launch this session with UAC elevation from inside the shell."""
    import ctypes
    console.print()
    console.print("[yellow]  Requesting Administrator privileges via UAC...[/]")
    python_exe = sys.executable
    # Find run.py: one directory above this package
    run_script = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "run.py")
    )
    if not os.path.exists(run_script):
        console.print("[bold red]  Could not locate run.py -- elevation aborted.[/]")
        return

    params = f'"{run_script}"'
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", python_exe, params,
        os.path.dirname(run_script), 1,
    )
    if ret > 32:
        console.print()
        console.print("[bright_green]  Elevated window launched successfully.[/]")
        console.print("[dim]  Closing this non-admin window...[/]")
        try:
            input("  Press Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass
        sys.exit(0)
    else:
        console.print(f"[bold red]  Elevation failed or was denied (UAC code {ret}).[/]")
        console.print("[dim]  Continuing as USER.[/]")


def _fmt_bytes(n: float) -> str:
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}P"


def _uptime() -> str:
    td = timedelta(seconds=int(time.time() - psutil.boot_time()))
    d  = td.days
    h, rem = divmod(td.seconds, 3600)
    m, s   = divmod(rem, 60)
    return f"{d}d {h:02d}:{m:02d}:{s:02d}" if d else f"{h:02d}:{m:02d}:{s:02d}"


# ──────────────────────────────────────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────────────────────────────────────

def _render_header() -> None:
    """Print the full colourful header + live stat strip."""
    console.print()

    # ── ASCII art banner in a panel ──
    banner_text = Text(justify="center")
    colors = ["bright_yellow", "yellow", "bright_green", "green", "bright_yellow", "yellow"]
    for i, line in enumerate(_BANNER.strip("\n").splitlines()):
        banner_text.append(line + "\n", style=f"bold {colors[i % len(colors)]}")

    console.print(Panel(
        Align.center(banner_text),
        title="[bold bright_green] apprt [/]",
        subtitle=f"[dim italic] {_TAGLINE} [/]",
        border_style="green",
        padding=(0, 6),
    ))
    console.print()

    # ── Stat bar (2 rows) ──
    _render_stat_bar()
    console.print()

    # ── Hint ──
    console.print(Align.center(
        '[dim]Type [bold bright_yellow]help[/] for commands'
        '  [white]|[/]  '
        '[bold bright_yellow]elevate[/] for admin'
        '  [white]|[/]  '
        '[bold bright_yellow]exit[/] to quit[/dim]'
    ))
    console.print()


def _render_stat_bar() -> None:
    """Two-row stat panels: identity+resources on row 1, network+time on row 2."""
    mem      = psutil.virtual_memory()
    cpu      = psutil.cpu_percent(interval=0.3)
    host     = socket.gethostname()
    priv     = "ADMIN" if _is_admin() else "USER"
    priv_col = "bright_green" if _is_admin() else "yellow"
    up       = _uptime()

    try:
        conns     = psutil.net_connections(kind="tcp")
        listening = sum(1 for c in conns if c.status == "LISTEN")
        est       = sum(1 for c in conns if c.status == "ESTABLISHED")
        port_str  = f"{listening} listen / {est} active"
    except Exception:
        port_str  = "N/A"

    cpu_col = "bright_green" if cpu < 50 else ("yellow" if cpu < 85 else "bright_red")
    mem_col = "bright_green" if mem.percent < 60 else ("yellow" if mem.percent < 85 else "bright_red")

    table = Table(
        box=box.SQUARE,
        border_style="green",
        show_header=False,
        expand=True,
        padding=(0, 2),
    )
    table.add_column("C1", no_wrap=True)
    table.add_column("C2", no_wrap=True)
    table.add_column("C3", no_wrap=True)
    table.add_column("C4", no_wrap=True)

    def _stat_text(label: str, value: str, val_style: str) -> Text:
        t = Text()
        t.append(f"{label}: ", style="dim bright_green")
        t.append(f"{value}", style=f"bold {val_style}")
        return t

    table.add_row(
        _stat_text("HOST", host, "bright_yellow"),
        _stat_text("PRIV", priv, priv_col),
        _stat_text("CPU", f"{cpu:.1f}%", cpu_col),
        _stat_text("RAM", f"{mem.percent:.1f}%", mem_col)
    )
    
    table.add_row(
        _stat_text("UPTIME", up, "bright_yellow"),
        _stat_text("TCP", port_str, "bright_green"),
        _stat_text("TIME", datetime.now().strftime("%H:%M:%S"), "white"),
        _stat_text("SWAP", f"{_fmt_bytes(psutil.swap_memory().used)}", "yellow")
    )

    console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
# HELP
# ──────────────────────────────────────────────────────────────────────────────

_HELP_ROWS = [
    ("list",                    "all",            "List every open port with PID, process, CPU, RAM"),
    ("list tcp",                "tcp only",       "Filter to TCP ports"),
    ("list udp",                "udp only",       "Filter to UDP ports"),
    ("list tcp listen",         "TCP + LISTEN",   "TCP ports in LISTENING state"),
    ("list tcp established",    "TCP + EST",      "TCP ports with ESTABLISHED connections"),
    ("list -v",                 "verbose",        "Add per-port connection detail rows"),
    ("port <N>",                "port detail",    "Full detail for port number N"),
    ("kill <N>",                "port action",    "Kill the process listening on port N"),
    ("transfer <N>",            "port action",    "Move the process on port N to a random free port; show both ports"),
    ("top",                     "top 10",         "Top 10 ports by connection count"),
    ("top <N>",                 "top N",          "Top N ports by connection count"),
    ("watch",                   "live ports",     "Auto-refresh port table (Ctrl-C to stop)"),
    ("monitor",                 "live dash",      "htop-style live system dashboard"),
    ("monitor mem",             "sort MEM",       "Monitor sorted by memory usage"),
    ("monitor cpu 30",          "cpu / 30 procs", "Monitor sorted by CPU, show 30 processes"),
    ("services",                "all",            "Map every open port to its service name"),
    ("services <N>",            "port N",         "Service name for a specific port"),
    ("sysinfo",                 "snapshot",       "Print full system configuration"),
    ("elevate",                 "UAC",            "Re-launch with Administrator privileges (UAC prompt)"),
    ("clear",                   "",               "Clear the screen and re-print the header"),
    ("exit / quit",             "",               "Exit apprt"),
]


def _show_help() -> None:
    table = Table(
        title="[bold bright_green]apprt Commands[/]",
        box=box.SQUARE,
        border_style="green",
        header_style="bold bright_yellow on grey11",
        show_lines=True,
        expand=True,
    )
    table.add_column("Command",     style="bold bright_yellow",  width=28)
    table.add_column("Scope",       style="bright_green",      width=16)
    table.add_column("Description", style="white")

    for cmd, scope, desc in _HELP_ROWS:
        table.add_row(cmd, scope, desc)

    console.print(table)
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# COMMAND DISPATCH
# ──────────────────────────────────────────────────────────────────────────────

def _run_apprt(args: list[str]) -> None:
    """Import and invoke the apprt CLI with the given argument list."""
    old_argv = sys.argv[:]
    sys.argv  = ["apprt"] + args
    try:
        from apprt.cli import main as _main
        _main()
    except SystemExit:
        pass
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
    finally:
        sys.argv = old_argv


def _clear_screen() -> None:
    """Clear terminal screen and scrollback buffer using native OS command."""
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")


def _dispatch(raw: str) -> bool:
    """
    Parse and dispatch one shell command.
    Returns False if the user wants to exit.
    """
    parts = raw.strip().split()
    if not parts:
        return True

    cmd   = parts[0].lower()
    rest  = parts[1:]

    # ── exit ──
    if cmd in ("exit", "quit", "q"):
        return False

    # ── clear / cls ──
    if cmd in ("clear", "cls"):
        _clear_screen()
        _render_header()
        return True

    # ── help ──
    if cmd in ("help", "?", "h"):
        _show_help()
        return True

    # ── sysinfo ──
    if cmd in ("sysinfo", "sys", "info"):
        try:
            from run import print_system_config
            print_system_config()
        except Exception:
            # Inline fallback if run.py not on path
            _show_sysinfo_inline()
        return True

    # ── list [proto] [state] [-v] ──
    if cmd == "list":
        args_out = ["list"]
        proto    = "all"
        state    = "all"
        verbose  = False
        for tok in rest:
            t = tok.lower()
            if t in ("tcp", "udp"):
                proto = t
            elif t in ("listen", "established"):
                state = t
            elif t in ("-v", "--verbose", "verbose", "v"):
                verbose = True
        args_out += ["--proto", proto, "--state", state]
        if verbose:
            args_out.append("--verbose")
        _run_apprt(args_out)
        return True

    # ── port <N> ──
    if cmd == "port":
        if not rest or not rest[0].isdigit():
            console.print("[yellow]Usage:[/] port <number>   e.g.  port 443")
            return True
        _run_apprt(["port", rest[0]])
        return True

    # ── kill <N> ──
    if cmd == "kill":
        if not rest or not rest[0].isdigit():
            console.print("[yellow]Usage:[/] kill <port>   e.g.  kill 8080")
            return True
        from apprt.actions import kill_port
        kill_port(int(rest[0]))
        return True

    # ── transfer <N> ──
    if cmd in ("transfer", "assign"):
        if not rest or not rest[0].isdigit():
            console.print("[yellow]Usage:[/] transfer <port>   e.g.  transfer 8080")
            console.print("[dim]  Moves the process to a random free port and shows both ports.[/dim]")
            return True
        from apprt.actions import transfer_port
        transfer_port(int(rest[0]))
        return True

    # ── top [N] ──
    if cmd == "top":
        limit = rest[0] if rest and rest[0].isdigit() else "10"
        _run_apprt(["top", "--limit", limit])
        return True

    # ── watch [proto] [state] [interval] ──
    if cmd == "watch":
        proto    = "all"
        state    = "all"
        interval = "2"
        for tok in rest:
            t = tok.lower()
            if t in ("tcp", "udp"):
                proto = t
            elif t in ("listen", "established"):
                state = t
            elif t.replace(".", "").isdigit():
                interval = t
        _run_apprt(["watch", "--proto", proto, "--state", state, "--interval", interval])
        return True

    # ── monitor [sort] [limit] ──
    if cmd == "monitor":
        sort  = "cpu"
        limit = "25"
        for tok in rest:
            t = tok.lower()
            if t in ("cpu", "mem", "pid", "name", "conn"):
                sort = t
            elif t.isdigit():
                limit = t
        _run_apprt(["monitor", "--sort", sort, "--limit", limit])
        return True

    # ── services [N] ──
    if cmd in ("services", "svc"):
        if rest and rest[0].isdigit():
            _run_apprt(["services", "--port", rest[0]])
        else:
            _run_apprt(["services"])
        return True

    # ── elevate / sudo / admin ──
    if cmd in ("elevate", "sudo", "admin"):
        if _is_admin():
            console.print()
            console.print("[bright_green]  Already running as ADMINISTRATOR.[/]  No elevation needed.")
        else:
            _request_elevation()
        return True

    # ── unknown ──
    console.print(
        f"[bold red]  Unknown command:[/] [bright_cyan]{raw}[/]   "
        "Type [bold bright_yellow]help[/] to see all commands."
    )
    return True


def _show_sysinfo_inline() -> None:
    """Inline sysinfo panel (fallback if run.py unavailable)."""
    import platform
    mem  = psutil.virtual_memory()
    cpu  = psutil.cpu_count(logical=True)
    freq = psutil.cpu_freq()

    table = Table(box=box.SIMPLE, show_header=False, expand=False, padding=(0, 2))
    table.add_column("Key",   style="bold bright_cyan",  width=18)
    table.add_column("Value", style="white")

    rows = [
        ("OS",          f"{platform.system()} {platform.release()}"),
        ("Version",     platform.version()[:60]),
        ("Host",        socket.gethostname()),
        ("Python",      sys.version.split()[0]),
        ("CPU Cores",   f"{psutil.cpu_count(logical=False)} physical / {cpu} logical"),
        ("CPU Freq",    f"{freq.current:.0f} MHz" if freq else "-"),
        ("RAM Total",   f"{mem.total/(1024**3):.2f} GB"),
        ("RAM Used",    f"{mem.used/(1024**3):.2f} GB  ({mem.percent:.1f}%)"),
        ("Uptime",      _uptime()),
        ("Privilege",   "ADMIN" if _is_admin() else "USER"),
    ]
    for k, v in rows:
        table.add_row(k, v)

    console.print(Panel(table, title="[bold bright_white]System Info[/]",
                        border_style="bright_blue"))


# ──────────────────────────────────────────────────────────────────────────────
# PROMPT
# ──────────────────────────────────────────────────────────────────────────────

def _prompt() -> str:
    """Render the coloured prompt and read a line."""
    priv_color = "bright_green" if _is_admin() else "yellow"
    # We can't embed ANSI in input() on all terminals, so print the prompt
    # with Rich then use bare input().
    console.print(
        Text.assemble(
            ("  apprt", f"bold {priv_color}"),
            (" > ", "bold white"),
        ),
        end="",
    )
    try:
        return input()
    except (EOFError, KeyboardInterrupt):
        return "exit"


# ──────────────────────────────────────────────────────────────────────────────
# MAIN SHELL LOOP
# ──────────────────────────────────────────────────────────────────────────────

def run_shell() -> None:
    """Entry point for the interactive shell."""
    _clear_screen()
    _render_header()

    while True:
        try:
            raw = _prompt()
            console.print()          # blank line after input for breathing room

            keep_running = _dispatch(raw)
            if not keep_running:
                _goodbye()
                break

            console.print()          # blank line after output

        except KeyboardInterrupt:
            console.print("\n[dim]  (Ctrl-C caught -- type [bold]exit[/] to quit)[/]\n")
        except Exception:
            console.print(f"[bold red]Shell error:[/]\n{traceback.format_exc()}")


def _goodbye() -> None:
    console.print()
    console.rule("[bold bright_cyan]  apprt  --  Goodbye!  [/]", style="bright_blue")
    console.print()
    if _is_admin() and sys.platform == "win32":
        try:
            input("  Press Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass
