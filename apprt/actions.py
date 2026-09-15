import socket
import random
import psutil
import subprocess
import time
from rich.prompt import Confirm, Prompt
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

console = Console()


# ── helpers ───────────────────────────────────────────────────────────────────

def get_process_on_port(port: int):
    """Return the psutil.Process bound to the given port, or None."""
    for p in psutil.process_iter(['pid', 'name']):
        try:
            conns = p.net_connections()
            for c in conns:
                if c.laddr.port == port and (
                    c.type == socket.SOCK_DGRAM or c.status == "LISTEN"
                ):
                    return p
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        except Exception:
            continue
    return None


def find_free_port(start: int = 10000, end: int = 65000, retries: int = 50) -> int | None:
    """
    Return a random unoccupied TCP port in [start, end].
    Tries up to *retries* candidates before giving up.
    """
    occupied: set[int] = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.laddr:
                occupied.add(c.laddr.port)
    except Exception:
        pass

    candidates = list(range(start, end + 1))
    random.shuffle(candidates)
    for port in candidates[:retries]:
        if port in occupied:
            continue
        # Double-check with a real socket bind
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", port))
                return port
        except OSError:
            continue
    return None


def _collect_port_info(port: int) -> dict:
    """Gather display info for a port snapshot (before or after transfer)."""
    info = {
        "port": port,
        "pid": "–",
        "process": "–",
        "cmdline": "–",
        "cpu": "–",
        "mem": "–",
        "state": "–",
        "connections": 0,
    }
    try:
        conns = psutil.net_connections(kind="inet")
        port_conns = [c for c in conns if c.laddr and c.laddr.port == port]
        info["connections"] = len(port_conns)
        if port_conns:
            first = port_conns[0]
            info["state"] = first.status or "–"
            pid = first.pid
            if pid:
                try:
                    p = psutil.Process(pid)
                    with p.oneshot():
                        info["pid"] = pid
                        info["process"] = p.name()
                        cmdline = " ".join(p.cmdline())
                        info["cmdline"] = cmdline[:60] or p.name()
                        info["cpu"] = f"{p.cpu_percent(interval=0.1):.1f}%"
                        info["mem"] = f"{p.memory_info().rss / (1024**2):.1f} MB"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
    except Exception:
        pass
    return info


def _render_port_panel(info: dict, label: str, border_color: str) -> Panel:
    """Render a single port's info as a Rich Panel."""
    t = Table(box=None, show_header=False, padding=(0, 1))
    t.add_column("Key",   style="bold bright_cyan",  width=14, no_wrap=True)
    t.add_column("Value", style="white")

    state_color = "bright_green" if "LISTEN" in str(info["state"]) else "bright_yellow"

    rows = [
        ("Port",        str(info["port"])),
        ("PID",         str(info["pid"])),
        ("Process",     str(info["process"])),
        ("Cmdline",     str(info["cmdline"])),
        ("CPU",         str(info["cpu"])),
        ("Memory",      str(info["mem"])),
        ("State",       str(info["state"])),
        ("Connections", str(info["connections"])),
    ]
    for k, v in rows:
        val_text = Text(v)
        if k == "State":
            val_text = Text(v, style=state_color)
        t.add_row(k, val_text)

    return Panel(
        t,
        title=f"[bold {border_color}]{label}[/]",
        border_style=border_color,
        padding=(0, 1),
    )


def _show_transfer_comparison(old_info: dict, new_info: dict) -> None:
    """Render a side-by-side comparison of old port and new port."""
    console.print()
    console.rule("[bold bright_magenta]  Transfer Complete — Port Comparison  [/]", style="bright_magenta")
    console.print()

    old_panel = _render_port_panel(old_info, f" ◀  Original  Port {old_info['port']} ", "bright_yellow")
    new_panel = _render_port_panel(new_info, f" ▶  New Port  {new_info['port']} ", "bright_green")

    console.print(Columns([old_panel, new_panel], equal=True, expand=True))
    console.print()

    console.print(
        f"[dim]  Port [bold bright_yellow]{old_info['port']}[/] still bound (original process unchanged)  "
        f"→  New random port [bold bright_green]{new_info['port']}[/] is now active.[/dim]"
    )
    console.print()


# ── kill ──────────────────────────────────────────────────────────────────────

def kill_port(port: int, force: bool = False) -> bool:
    """Kill the process listening on the given port."""
    p = get_process_on_port(port)
    if not p:
        console.print(f"[yellow]No process found listening on port {port}.[/yellow]")
        return False

    name = p.info.get('name', 'Unknown')
    pid  = p.info.get('pid',  'Unknown')

    if not force:
        if not Confirm.ask(f"[bold red]Process {name} (PID {pid}) is using port {port}. Kill it?[/bold red]"):
            console.print("[dim]Aborted.[/dim]")
            return False

    try:
        p.kill()
        p.wait(timeout=3)
        console.print(f"[bright_green]Success: Killed {name} (PID {pid}). Port {port} is now free.[/bright_green]")
        return True
    except psutil.AccessDenied:
        console.print(f"[bold red]Access Denied: Could not kill {name}. You may need Administrator privileges.[/bold red]")
        return False
    except Exception as e:
        console.print(f"[bold red]Error killing process: {e}[/bold red]")
        return False


# ── transfer ──────────────────────────────────────────────────────────────────

def transfer_port(port: int) -> bool:
    """
    Transfer the process currently on *port* to a random unoccupied port.

    Behaviour
    ---------
    • Does NOT close or kill the original port — it stays bound.
    • Finds a random free port in the ephemeral range (10 000–65 000).
    • Restarts the process that owns *port* with an environment variable
      PORT=<new_port> injected so service-aware apps can pick it up.
      For Windows Services the service is stopped and re-started via
      ``sc config`` + ``net start``.
    • Displays a before/after dual-pane comparison when done.
    """
    console.print(f"\n[bold bright_cyan]  Transfer: port {port} → new random port[/]")
    console.print("[dim]  (Original port will NOT be closed)[/dim]\n")

    # ── 1. Snapshot original port ───────────────────────────────────────────
    old_info = _collect_port_info(port)

    if old_info["pid"] == "–":
        console.print(f"[yellow]  No active process found on port {port}. Nothing to transfer.[/yellow]")
        return False

    # ── 2. Find a free random port ──────────────────────────────────────────
    console.print("[dim]  Searching for a free random port...[/dim]")
    new_port = find_free_port()
    if new_port is None:
        console.print("[bold red]  Could not find a free port. Aborting.[/bold red]")
        return False

    console.print(f"  [bright_green]Found free port:[/] [bold bright_white]{new_port}[/]\n")

    # ── 3. Confirm with user ────────────────────────────────────────────────
    pid     = old_info["pid"]
    name    = old_info["process"]
    cmdline = old_info["cmdline"]

    console.print(f"  [bold bright_yellow]Process to transfer:[/] {name} (PID {pid})")
    console.print(f"  [dim]Cmdline:[/] {cmdline}")
    console.print()

    mode = Prompt.ask(
        "[bold bright_white]  How should the process be moved to the new port?[/]\n"
        "  [dim][1] Restart process with PORT env var injected (generic)\n"
        "  [2] Windows Service — stop and reconfigure port\n"
        "  [3] Manual — I will handle it myself (just show me the new port)\n"
        "  [q] Cancel[/dim]\n"
        "  Choice",
        choices=["1", "2", "3", "q"],
        default="1",
    )

    if mode == "q":
        console.print("[dim]  Transfer cancelled.[/dim]")
        return False

    success = False

    # ── Mode 1: restart process with PORT env var ───────────────────────────
    if mode == "1":
        try:
            proc = psutil.Process(int(pid))
            env  = proc.environ()
            env["PORT"] = str(new_port)

            # Grab the original command line
            try:
                cmd = proc.cmdline()
            except psutil.AccessDenied:
                cmd = []

            if not cmd:
                console.print("[yellow]  Cannot read process cmdline (Access Denied). Falling back to manual mode.[/yellow]")
                mode = "3"
            else:
                cwd = None
                try:
                    cwd = proc.cwd()
                except psutil.AccessDenied:
                    pass

                console.print(f"\n  [dim]Launching: {' '.join(cmd)}[/]")
                console.print(f"  [dim]       CWD: {cwd or '(inherited)'}[/]")
                console.print(f"  [dim]  PORT env: {new_port}[/]\n")

                subprocess.Popen(cmd, env=env, cwd=cwd)
                time.sleep(1.2)   # allow new process to bind
                success = True
                console.print(f"  [bright_green]Process re-launched on port {new_port}.[/]")

        except psutil.NoSuchProcess:
            console.print("[bold red]  Process disappeared before transfer. Aborted.[/bold red]")
            return False
        except Exception as e:
            console.print(f"[bold red]  Error restarting process: {e}[/bold red]")
            return False

    # ── Mode 2: Windows Service reconfiguration ─────────────────────────────
    if mode == "2":
        svc_name = Prompt.ask(
            "  [bold bright_yellow]Enter the Windows Service name[/] (e.g. W3SVC, Apache2.4)"
        )
        if svc_name.strip().lower() in ("", "cancel", "q"):
            console.print("[dim]  Transfer cancelled.[/dim]")
            return False

        console.print(f"\n  [dim]Stopping service '{svc_name}'...[/dim]")
        r = subprocess.run(["net", "stop", svc_name], capture_output=True, text=True)
        if r.returncode != 0:
            out = (r.stdout + r.stderr).strip()
            console.print(f"[yellow]  Warning stopping service: {out}[/yellow]")

        # Update service listen port via environment key (best-effort)
        console.print(f"  [dim]Configuring service to use port {new_port}...[/dim]")
        subprocess.run(
            ["sc", "config", svc_name, f"binpath= \"{cmdline}\" --port {new_port}"],
            capture_output=True, text=True,
        )

        console.print(f"  [dim]Starting service '{svc_name}'...[/dim]")
        r = subprocess.run(["net", "start", svc_name], capture_output=True, text=True)
        if r.returncode == 0:
            success = True
            console.print(f"  [bright_green]Service '{svc_name}' restarted.[/]")
        else:
            out = (r.stdout + r.stderr).strip()
            console.print(f"[bold red]  Failed to start service: {out}[/bold red]")

    # ── Mode 3: manual — user handles it ───────────────────────────────────
    if mode == "3":
        console.print(
            f"\n  [bold bright_white]New port reserved:[/] [bold bright_green]{new_port}[/]\n"
            f"  [dim]Configure your application to bind on port [bold]{new_port}[/] and restart it manually.[/dim]"
        )
        success = True

    # ── 4. Collect new-port info and show comparison ────────────────────────
    if success:
        time.sleep(0.5)
        new_info = _collect_port_info(new_port)
        # Even if nothing yet bound (manual mode), still show the panel
        new_info["port"] = new_port
        _show_transfer_comparison(old_info, new_info)

    return success
