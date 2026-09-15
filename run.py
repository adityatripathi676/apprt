"""
run.py -- Privileged launcher for apprt.

Behaviour:
  1. Checks if the current process is already running as Administrator.
  2. If NOT admin -> prompts the user, then re-launches via Windows UAC
     (ShellExecuteW with verb "runas") so they get the full permission dialog.
  3. Once elevated (or if already admin) -> prints full system config,
     then hands off to the normal apprt CLI.

Usage (from the project root):
    python run.py [apprt-args ...]

Examples:
    python run.py list
    python run.py monitor --sort cpu --limit 30
    python run.py list --proto tcp --state listen --verbose
    python run.py top --limit 10
    python run.py --help
"""

from __future__ import annotations

import ctypes
import os
import sys
import traceback

# ── Root dir on sys.path (so 'apprt' package is always importable) ────────────
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ── Crash log (written before any print, so even total crashes are captured) ──
_LOG_PATH = os.path.join(_ROOT, "apprt_crash.log")


def _write_log(text: str) -> None:
    """Append text to the crash log file."""
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception:
        pass


# ── Safe stdout setup ─────────────────────────────────────────────────────────

def _setup_encoding() -> None:
    """
    Force UTF-8 on Windows console without crashing.
    Works even if stdout has no .buffer (e.g. IDLE, pythonw).
    """
    if sys.platform != "win32":
        return
    import io
    # Try to reconfigure first (Python 3.7+)
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
            continue
        except AttributeError:
            pass
        # Fallback: wrap the buffer
        try:
            buf = getattr(stream, "buffer", None)
            if buf is not None:
                wrapped = io.TextIOWrapper(buf, encoding="utf-8", errors="replace")
                setattr(sys, stream_name, wrapped)
        except Exception:
            pass


_setup_encoding()


def _safe_print(*args, **kwargs) -> None:
    """Print that never raises even on codec errors."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        # Strip non-ASCII and retry
        safe = " ".join(
            str(a).encode("ascii", "replace").decode("ascii") for a in args
        )
        try:
            print(safe, **{k: v for k, v in kwargs.items() if k != "end"})
        except Exception:
            pass
    except Exception:
        pass


# ── Admin detection ───────────────────────────────────────────────────────────

def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ── Elevation ─────────────────────────────────────────────────────────────────

def _quote(s: str) -> str:
    """Wrap a string in double-quotes, escaping any inner quotes."""
    return '"' + s.replace('"', '\\"') + '"'


def request_elevation_windows(args: list[str]) -> bool:
    """
    Re-launch this script with UAC elevation.
    Returns True if ShellExecuteW reported success (>32).
    """
    python_exe = sys.executable          # full path to current interpreter
    script     = os.path.abspath(__file__)

    # Inject sys.path so the elevated process inherits our venv paths
    path_flag  = ";".join(sys.path)
    env_inject = f"PYTHONPATH={_quote(path_flag)}"

    # Parameters passed to python.exe in the elevated process
    params = " ".join([_quote(script)] + [_quote(a) for a in args])

    _safe_print("\n[apprt] Requesting Administrator privileges via UAC...")

    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        python_exe,
        params,
        _ROOT,
        1,
    )

    if ret > 32:
        return True

    _safe_print(f"[apprt] Elevation failed or was denied (code {ret}).")
    _safe_print("[apprt] Continuing without administrator privileges.\n")
    return False


def request_elevation_unix(args: list[str]) -> None:
    """Re-launch with sudo on Linux/macOS."""
    cmd = ["sudo", sys.executable, os.path.abspath(__file__)] + args
    _safe_print(f"[apprt] Requesting root via sudo: {' '.join(cmd)}\n")
    os.execvp("sudo", cmd)   # replaces current process entirely


# ── Boot-keyed consent cache  (DPAPI-encrypted on Windows) ───────────────────

import base64 as _b64
import json as _json
import tempfile as _tempfile

# Encrypted binary blob stored as base64 text for safe transport
_CONSENT_FILE = os.path.join(_tempfile.gettempdir(), "apprt_consent.dat")


def _boot_time_key() -> str:
    """
    Return the system boot time as an integer string.
    Changes every reboot — perfect per-boot cache key.
    """
    try:
        import psutil
        return str(int(psutil.boot_time()))
    except Exception:
        return "unknown"


# ── DPAPI helpers (Windows-only, zero extra packages) ────────────────────────

def _dpapi_encrypt(plaintext: bytes) -> bytes | None:
    """
    Encrypt bytes using Windows CryptProtectData (DPAPI).
    Ties the blob to the current user + machine -- cannot be
    transferred to another machine or forged by editing the file.
    Returns None on non-Windows or failure.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        class _BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_ulong),
                        ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        buf     = (ctypes.c_ubyte * len(plaintext))(*plaintext)
        in_blob = _BLOB(len(plaintext), buf)
        out_blob = _BLOB()

        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            ctypes.c_wchar_p("apprt-consent"),
            None, None, None,
            ctypes.c_uint(0),            # user-level (no flag needed)
            ctypes.byref(out_blob),
        )
        if not ok:
            _write_log(f"[dpapi] CryptProtectData failed: {ctypes.GetLastError()}")
            return None

        result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return result
    except Exception as e:
        _write_log(f"[dpapi] encrypt error: {e}")
        return None


def _dpapi_decrypt(ciphertext: bytes) -> bytes | None:
    """
    Decrypt a DPAPI blob produced by _dpapi_encrypt.
    Returns None on failure or wrong machine/user.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        class _BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_ulong),
                        ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        buf      = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
        in_blob  = _BLOB(len(ciphertext), buf)
        out_blob = _BLOB()

        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None, None, None, None,
            ctypes.c_uint(0),
            ctypes.byref(out_blob),
        )
        if not ok:
            _write_log(f"[dpapi] CryptUnprotectData failed: {ctypes.GetLastError()}")
            return None

        result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return result
    except Exception as e:
        _write_log(f"[dpapi] decrypt error: {e}")
        return None


# ── Consent read / write ──────────────────────────────────────────────────────

def _consent_for_this_boot() -> bool:
    """
    Return True if the user already granted elevation this boot session.
    Reads the DPAPI-encrypted consent file; falls back to plaintext.
    """
    try:
        raw = _CONSENT_FILE.replace(".dat", ".json")   # legacy plaintext path
        path = _CONSENT_FILE

        if os.path.exists(path):
            # Encrypted path
            with open(path, "r", encoding="ascii") as f:
                blob_b64 = f.read().strip()
            blob = _b64.b64decode(blob_b64)
            plaintext = _dpapi_decrypt(blob)
            if plaintext is None:
                _write_log("[apprt] DPAPI decrypt returned None -- treating as no consent")
                return False
            data = _json.loads(plaintext.decode("utf-8"))
        elif os.path.exists(raw):
            # Legacy unencrypted file (upgrade path)
            with open(raw, "r", encoding="utf-8") as f:
                data = _json.load(f)
        else:
            return False

        return (
            data.get("boot_key") == _boot_time_key()
            and data.get("granted") is True
        )
    except Exception as e:
        _write_log(f"[apprt] consent read error: {e}")
        return False


def _save_consent(granted: bool) -> None:
    """
    Persist the user's elevation choice for this boot session,
    DPAPI-encrypted so the file cannot be tampered with by hand.
    Falls back to plaintext JSON on non-Windows.
    """
    try:
        data      = {"boot_key": _boot_time_key(), "granted": granted}
        plaintext = _json.dumps(data).encode("utf-8")
        blob      = _dpapi_encrypt(plaintext)

        if blob is not None:
            # Write as base64 text so the file is ASCII-safe
            with open(_CONSENT_FILE, "w", encoding="ascii") as f:
                f.write(_b64.b64encode(blob).decode("ascii"))
            _write_log(f"[apprt] consent saved (DPAPI-encrypted)  "
                       f"granted={granted}  boot_key={data['boot_key']}")
        else:
            # Fallback: plaintext (non-Windows or DPAPI not available)
            fallback = _CONSENT_FILE.replace(".dat", ".json")
            with open(fallback, "w", encoding="utf-8") as f:
                _json.dump(data, f)
            _write_log(f"[apprt] consent saved (plaintext fallback)  "
                       f"granted={granted}  boot_key={data['boot_key']}")

    except Exception as e:
        _write_log(f"[apprt] could not save consent: {e}")


# ── System configuration snapshot ────────────────────────────────────────────

def print_system_config() -> None:
    """Print key system configuration items (best seen when elevated)."""
    import platform
    import socket as _socket

    try:
        import psutil
        has_psutil = True
    except ImportError:
        has_psutil = False

    SEP = "=" * 62

    _safe_print("\n" + SEP)
    _safe_print("  SYSTEM CONFIGURATION")
    if is_admin():
        _safe_print("  Privilege: ADMINISTRATOR  (full access)")
    else:
        _safe_print("  Privilege: USER  (limited -- some info may be hidden)")
    _safe_print(SEP)

    try:
        _safe_print(f"  OS          : {platform.system()} {platform.release()}")
        _safe_print(f"  Version     : {platform.version()[:60]}")
        _safe_print(f"  Architecture: {platform.machine()} / {platform.processor()[:40]}")
        _safe_print(f"  Python      : {sys.version.split()[0]}  ({sys.executable})")
        _safe_print(f"  Hostname    : {_socket.gethostname()}")
    except Exception as e:
        _safe_print(f"  [basic info error: {e}]")

    if has_psutil:
        import time
        try:
            cpu      = psutil.cpu_count(logical=True) or 0
            phys     = psutil.cpu_count(logical=False) or 0
            freq     = psutil.cpu_freq()
            mem      = psutil.virtual_memory()
            swap     = psutil.swap_memory()
            boot     = psutil.boot_time()
            uptime   = time.time() - boot
            h, rem   = divmod(int(uptime), 3600)
            m, s     = divmod(rem, 60)
            days     = int(uptime // 86400)

            _safe_print(f"  CPU Cores   : {phys} physical / {cpu} logical")
            if freq:
                _safe_print(f"  CPU Freq    : {freq.current:.0f} MHz "
                            f"(min {freq.min:.0f} / max {freq.max:.0f})")
            _safe_print(f"  RAM Total   : {mem.total / (1024**3):.2f} GB")
            _safe_print(f"  RAM Used    : {mem.used  / (1024**3):.2f} GB  "
                        f"({mem.percent:.1f}%  free: "
                        f"{mem.available / (1024**3):.2f} GB)")
            _safe_print(f"  Swap Total  : {swap.total / (1024**3):.2f} GB  "
                        f"used {swap.percent:.1f}%")
            _safe_print(f"  Uptime      : {days}d {h:02d}h {m:02d}m {s:02d}s")
        except Exception as e:
            _safe_print(f"  [CPU/RAM info error: {e}]")

        # Disk partitions
        _safe_print("\n  Disk Partitions:")
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    _safe_print(
                        f"    {part.device:<16} {part.mountpoint:<14} "
                        f"{part.fstype:<8}  "
                        f"{usage.total/(1024**3):.1f} GB total  "
                        f"{usage.percent:.1f}% used"
                    )
                except (PermissionError, OSError):
                    _safe_print(f"    {part.device:<16} {part.mountpoint:<14} "
                                f"[access denied]")
        except Exception as e:
            _safe_print(f"    [error: {e}]")

        # Network interfaces
        _safe_print("\n  Network Interfaces:")
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for nic, addr_list in addrs.items():
                st  = stats.get(nic)
                up  = "UP  " if (st and st.isup) else "DOWN"
                spd = f"{st.speed} Mbps" if (st and st.speed) else "  -"
                for addr in addr_list:
                    import socket as _sock
                    if addr.family == _sock.AF_INET:
                        _safe_print(
                            f"    {nic:<22} {addr.address:<18} "
                            f"{up}  {spd}"
                        )
        except Exception as e:
            _safe_print(f"    [error: {e}]")

        # Open TCP ports count
        try:
            conns      = psutil.net_connections(kind="tcp")
            listening  = sum(1 for c in conns if c.status == "LISTEN")
            established = sum(1 for c in conns if c.status == "ESTABLISHED")
            _safe_print(f"\n  TCP Ports   : {len(conns)} total  "
                        f"({listening} LISTENING  {established} ESTABLISHED)")
        except Exception:
            pass

    _safe_print("\n" + SEP + "\n")


# ── CLI runner helper ─────────────────────────────────────────────────────────

def _run_apprt(args: list) -> None:
    """Run apprt CLI with the given args list. Swallows SystemExit."""
    sys.argv = ["apprt"] + args
    try:
        from apprt.cli import main as apprt_main
        apprt_main()
    except SystemExit:
        pass
    except ImportError as e:
        _safe_print(f"\n[apprt] Could not import apprt package: {e}")
        _safe_print("[apprt] Make sure you ran:  pip install -e .")
        _write_log(f"[apprt] ImportError:\n{traceback.format_exc()}")
    except Exception as e:
        _safe_print(f"\n[apprt] Error: {e}")
        _write_log(f"[apprt] Error:\n{traceback.format_exc()}")


# ── Interactive menu ──────────────────────────────────────────────────────────

_MENU_WIDTH = 62

_COMMANDS = [
    ("1", "list",     "List all open ports  (PID, process, CPU, MEM, state)"),
    ("2", "monitor",  "Live system dashboard  (htop: CPU/RAM/procs/NIC/disk)"),
    ("3", "watch",    "Live port table  (auto-refresh, like top for ports)"),
    ("4", "top",      "Top ports ranked by active connection count"),
    ("5", "services", "Port -> service name map"),
    ("6", "port",     "Deep-dive into one specific port number"),
    ("7", "sysinfo",  "Re-print full system configuration snapshot"),
    ("q", "quit",     "Exit apprt"),
]


def _menu_header() -> None:
    SEP = "=" * _MENU_WIDTH
    _safe_print("\n" + SEP)
    _safe_print("  apprt  --  Advanced Port Inspector")
    priv = "ADMINISTRATOR (full access)" if is_admin() else "USER (limited access)"
    _safe_print(f"  Privilege : {priv}")
    _safe_print(SEP)
    _safe_print("")
    for key, _cmd, desc in _COMMANDS:
        _safe_print(f"    [{key}]  {desc}")
    _safe_print("")
    _safe_print("-" * _MENU_WIDTH)


def _ask(prompt: str, default: str = "") -> str:
    try:
        val = input(prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default


def _run_list() -> None:
    _safe_print("\n  Filters (press Enter to accept defaults):")
    proto   = _ask("    Protocol [tcp / udp / all]             (all): ", "all")
    state   = _ask("    State    [listen / established / all]  (all): ", "all")
    verbose = _ask("    Verbose? show per-port connections     [y/N]: ", "n")
    args = ["list", "--proto", proto, "--state", state]
    if verbose.lower() in ("y", "yes"):
        args.append("--verbose")
    _safe_print("")
    _run_aport(args)


def _run_monitor() -> None:
    _safe_print("\n  Monitor options (press Enter to accept defaults):")
    sort     = _ask("    Sort by [cpu / mem / pid / name / conn]  (cpu): ", "cpu")
    limit    = _ask("    Max processes to show                     (25): ", "25")
    interval = _ask("    Refresh interval seconds                   (2): ", "2")
    filt     = _ask("    Filter by process name (blank = all):          ", "")
    args = ["monitor", "--sort", sort, "--limit", limit, "--interval", interval]
    if filt:
        args += ["--filter", filt]
    _safe_print("")
    _run_aport(args)


def _run_watch() -> None:
    _safe_print("\n  Watch options (press Enter to accept defaults):")
    proto    = _ask("    Protocol [tcp / udp / all]              (all): ", "all")
    state    = _ask("    State [listen / established / all]      (all): ", "all")
    interval = _ask("    Refresh interval seconds                  (2): ", "2")
    _safe_print("")
    _run_aport(["watch", "--proto", proto, "--state", state, "--interval", interval])


def _run_top() -> None:
    _safe_print("\n  Top options:")
    limit = _ask("    Number of top ports to show (10): ", "10")
    _safe_print("")
    _run_aport(["top", "--limit", limit])


def _run_services() -> None:
    _safe_print("\n  Services options:")
    port = _ask("    Specific port number to look up (blank = all): ", "")
    args = ["services"]
    if port:
        args += ["--port", port]
    _safe_print("")
    _run_aport(args)


def _run_port() -> None:
    _safe_print("\n  Port detail:")
    port = _ask("    Enter port number: ", "")
    if not port.isdigit():
        _safe_print("  [!] Invalid port number -- returning to menu.")
        return
    _safe_print("")
    _run_aport(["port", port])


def interactive_menu() -> None:
    """Interactive menu loop -- runs until user quits."""
    _HANDLERS = {
        "1": _run_list,
        "2": _run_monitor,
        "3": _run_watch,
        "4": _run_top,
        "5": _run_services,
        "6": _run_port,
        "7": print_system_config,
    }

    while True:
        try:
            _menu_header()
            choice = _ask("  Enter option number: ", "q").lower().strip()

            if choice in ("q", "quit", "exit", ""):
                _safe_print("\n  Goodbye!\n")
                break

            handler = _HANDLERS.get(choice)
            if handler is None:
                _safe_print(f"\n  [!] Unknown option '{choice}'. Try 1-7 or q.\n")
                continue

            _safe_print("")
            try:
                handler()
            except KeyboardInterrupt:
                _safe_print("\n  [Interrupted -- returning to menu]\n")
            except Exception as e:
                _safe_print(f"\n  [Error: {e}]")
                _write_log(f"[menu] handler error:\n{traceback.format_exc()}")

            _safe_print("\n" + "-" * _MENU_WIDTH)
            _ask("  Press Enter to return to menu...", "")

        except KeyboardInterrupt:
            _safe_print("\n\n  Tip: Use [q] + Enter to quit. Returning to menu...\n")
            continue

    # Keep elevated window open after quitting
    if is_admin() and sys.platform == "win32":
        _safe_print("=" * _MENU_WIDTH)
        _ask("[aport] Press Enter to close this window...", "")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    _write_log(f"\n{'='*60}")
    _write_log(f"[apprt] run.py started  pid={os.getpid()}  admin={is_admin()}")
    _write_log(f"[apprt] sys.argv = {sys.argv}")

    forwarded_args = sys.argv[1:]

    # ── Step 1: Privilege check and optional UAC elevation ─────────────────
    if not is_admin():
        already_consented = _consent_for_this_boot()

        if already_consented:
            # User already said yes this boot session — skip prompt, auto-elevate
            _safe_print("[apprt] Auto-elevating (consent cached for this boot)...")
            should_elevate = True
        else:
            _safe_print("=" * 62)
            _safe_print("  apprt -- Privileged Launcher")
            _safe_print("=" * 62)
            _safe_print("\n  [!] This process is NOT running as Administrator.")
            _safe_print("  [!] Some ports and process info will be hidden.")
            _safe_print("  [*] Your answer is remembered until the next reboot.\n")

            try:
                answer = input("  Request Administrator privileges? [Y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"

            should_elevate = answer in ("", "y", "yes")
            _save_consent(should_elevate)   # remember for rest of this boot

        if should_elevate:
            if sys.platform == "win32":
                ok = request_elevation_windows(forwarded_args)
                if ok:
                    if not already_consented:
                        _safe_print("\n[apprt] Elevated window launched.")
                        _safe_print("[apprt] Next time you run apprt this boot,")
                        _safe_print("[apprt] it will auto-elevate without asking.\n")
                    try:
                        input("[apprt] Press Enter to close this window...")
                    except (EOFError, KeyboardInterrupt):
                        pass
                    sys.exit(0)
            else:
                request_elevation_unix(forwarded_args)
        else:
            _safe_print("\n  [apprt] Continuing without elevation.\n")

    # ── Step 2: Print system config ───────────────────────────────────────────
    try:
        print_system_config()
    except Exception as e:
        _safe_print(f"[apprt] system config error: {e}")
        _write_log(f"[apprt] system config error:\n{traceback.format_exc()}")

    # ── Step 3: Interactive shell OR direct CLI pass-through ──────────────────
    if forwarded_args:
        # Called with explicit args (e.g. python run.py list) -- run directly
        _run_apprt(forwarded_args)
    else:
        # No args -> drop into the interactive REPL shell
        from apprt.shell import run_shell
        run_shell()

    _write_log("[apprt] run.py exited normally")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        tb = traceback.format_exc()
        _write_log(f"[apprt] FATAL:\n{tb}")
        # Try to print to screen too
        try:
            _safe_print("\n[apprt] FATAL ERROR:\n")
            _safe_print(tb)
        except Exception:
            pass
        # Last resort: keep window open so user can see the error
        try:
            input("\n[apprt] Press Enter to exit...")
        except Exception:
            pass
        sys.exit(1)
