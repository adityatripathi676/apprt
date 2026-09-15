# aport — Engineering Journal & Technical Reference

> **Advanced Port Inspector** | Windows 11 | Python 3.13 | PyArmor 9.2.7

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Decisions](#2-architecture-decisions)
3. [File-by-File Breakdown](#3-file-by-file-breakdown)
4. [Privilege Elevation System](#4-privilege-elevation-system)
5. [Boot-Keyed Consent Cache](#5-boot-keyed-consent-cache)
6. [DPAPI Encryption](#6-dpapi-encryption)
7. [Interactive Shell (REPL)](#7-interactive-shell-repl)
8. [Obfuscation — How It Works](#8-obfuscation--how-it-works)
9. [Obfuscation — File-by-File Analysis](#9-obfuscation--file-by-file-analysis)
10. [Reversing the Obfuscation — Theoretical Limits](#10-reversing-the-obfuscation--theoretical-limits)
11. [Security Properties Summary](#11-security-properties-summary)
12. [Build & Distribution](#12-build--distribution)

---

## 1. Project Overview

`aport` is a Windows system tool that:

- Lists **all open TCP/UDP ports** with per-port activity stats
- Shows which **process** owns each port (name, PID, CPU, RAM)
- Provides a live **htop-style monitor dashboard**
- Has an **interactive REPL shell** with a colourful banner
- Requests and **remembers Administrator elevation** for the duration of a boot session
- Stores the elevation consent in a **DPAPI-encrypted file** so it cannot be forged

The tool is shipped as a **Python package** and distributed as an **obfuscated build**
in the `dist/` directory using PyArmor 9.

---

## 2. Architecture Decisions

### 2.1 Modular package over a single script

**Decision:** Split functionality into `aport/` package modules rather than one large file.

**Why:** Each concern (scanning, display, CLI, shell, monitor) changes independently.
A monolith makes it impossible to test or swap individual components. Click also requires
a proper package structure to register entry-point commands.

---

### 2.2 Click for the CLI layer

**Decision:** Use `click` for command parsing instead of `argparse`.

**Why:** Click provides sub-commands with zero boilerplate, automatic `--help` generation,
type validation, and coloured output. The command tree
(`list`, `monitor`, `top`, `port`, `watch`, `services`, `shell`) maps naturally to Click groups.

---

### 2.3 Rich for the display layer

**Decision:** Use the `rich` library for all table and panel rendering.

**Why:** Rich gives auto-sized columns, coloured cells, live-updating panels (via `Live`),
and progress bars without manual ANSI escape-code management. The alternative
(`colorama` + manual formatting) would have required hundreds of lines of alignment code.

---

### 2.4 psutil for system data

**Decision:** Use `psutil` as the only system-data library.

**Why:** psutil wraps `netstat`, `/proc/net/tcp`, and Windows PDH APIs into a uniform
interface. Writing raw WinAPI calls for the same data would require `ctypes` structs for
`MIB_TCPTABLE2` and `MIB_UDPTABLE` — hundreds of lines of fragile C-interop code.

**Key psutil quirk discovered:** psutil 6.0+ removed `"connections"` from the
`process_iter()` attribute list. Calling `psutil.process_iter(["connections"])` raises
a `ValueError`. The fix is to call `p.net_connections()` inside an explicit `try/except`
loop per-process.

---

### 2.5 Separate `run.py` privileged launcher

**Decision:** Keep the UAC elevation logic entirely in `run.py`, separate from the `aport` package.

**Why:** The aport package should be importable and testable without elevation. `run.py`
is the "system entry point" that handles privilege negotiation before handing off to Click.
This means `aport --help` works without admin, while `python run.py` handles the UAC dance.

**Elevation flow:**
```
run.py (non-admin)
  -> ShellExecuteW("runas", python.exe, run.py, args)
       -> Windows shows UAC dialog
            -> run.py (admin) starts fresh
                 -> aport CLI / shell
```

`ShellExecuteW` with verb `"runas"` is the only standard API for triggering the UAC consent
dialog from Python without a manifest file or task scheduler entry.

---

### 2.6 UTF-8 forced on Windows console

**Decision:** Call `sys.stdout.reconfigure(encoding="utf-8")` at startup.

**Why:** Windows PowerShell and CMD default to cp1252. Any Unicode character outside that
range — even an em-dash (--) — raises `UnicodeEncodeError` and crashes the elevated process
before any output appears.

**Bug encountered:** The original code used em-dashes in section headers. These caused silent
crashes in the elevated window because the elevated process inherited the cp1252 console
encoding. All em-dashes were replaced with plain `-`.

---

### 2.7 PYTHONPATH injection into elevated process

**Decision:** Build a `PYTHONPATH` string from `sys.path` and pass it to the elevated process
via `ShellExecuteW`.

**Why:** When Windows launches an elevated process, it creates a **new session** with a clean
environment. The elevated `python.exe` does not inherit the current venv's `site-packages`.
Without `PYTHONPATH` injection, the elevated process fails with
`ModuleNotFoundError: No module named 'click'`.

---

### 2.8 Crash log before any output

**Decision:** Create `_write_log()` appending to `aport_crash.log` and call it at the very
first line of `main()`.

**Why:** Elevated windows close instantly on crash. The user sees nothing. A file-based crash
log written *before* any print statement means even a total import failure is captured and
readable after the window closes.

---

## 3. File-by-File Breakdown

```
aport/
├── __init__.py      Package init; exposes version
├── cli.py           Click command tree (list, monitor, top, port, watch, services, shell)
├── scanner.py       psutil data collection -- ports, processes, interfaces
├── display.py       Rich table/panel rendering for port data
├── monitor.py       Live htop-style dashboard using Rich Live
└── shell.py         Interactive REPL with banner, status bar, command dispatch

run.py               Privileged launcher (UAC + consent cache)
aport.bat            Convenience wrapper: `aport` -> `python -m aport.cli`
dist/                PyArmor-obfuscated distributable build
DOCS.md              This file
```

### `scanner.py`
Collects raw data from psutil:
- `get_connections()` -> all open sockets with local/remote addr, state, PID
- `enrich_with_process()` -> annotates each connection with process name, CPU%, RAM
- `get_interfaces()` -> network interface stats (bytes sent/recv)

### `display.py`
Renders data into Rich tables:
- `render_port_table()` -> main port listing with colour-coded states
  (LISTEN=green, ESTABLISHED=cyan, TIME_WAIT=yellow, etc.)
- `render_port_detail()` -> single-port deep-dive panel
- `render_sysinfo()` -> system config snapshot table

### `monitor.py`
Live dashboard with 5 panels updating every second:
- System panel (CPU, RAM, swap, uptime)
- Top processes (sortable by cpu/mem/pid/name)
- Network I/O (bytes in/out per interface)
- Disk usage (all partitions)
- Top ports (by connection count)

### `shell.py`
The REPL loop:
- Prints ASCII banner + live status bar (CPU%, RAM%, privilege, uptime, time)
- Reads commands from `input()` in a `while True` loop
- Dispatches to handlers: `_run_list()`, `_run_monitor()`, `_run_top()`, etc.
- Supports inline args: `list tcp listen`, `top 20`, `monitor mem 40`

### `run.py`
The privileged entry point (700+ lines):
1. Forces UTF-8 output
2. Sets up crash log
3. Checks `IsUserAnAdmin()`
4. Reads consent cache (DPAPI-decrypted)
5. If no consent -> asks once -> saves answer (DPAPI-encrypted)
6. If consent -> auto-elevates via `ShellExecuteW("runas")`
7. Prints system config snapshot
8. Launches shell REPL or passes CLI args to Click

---

## 4. Privilege Elevation System

### The UAC Flow

```
User runs: python run.py
          |
          v
   is_admin() == False?
          |
    YES   |  NO ─────────────────────────────────┐
          v                                       v
  _consent_for_this_boot()?              (already admin)
          |                                      |
   YES    |  NO                                  v
    ──────┴──────────               print_system_config()
    |            |                  run_shell() or CLI
    v            v
  Auto-elevate  Show prompt once
  (silent)      Save answer (DPAPI)
    |                |
    └────────────────┘
          |
          v
   ShellExecuteW("runas", python.exe, run.py, args)
          |
          v
   Windows UAC dialog appears
          |
   User clicks YES
          |
          v
   New elevated run.py process starts
   is_admin() == True -> skips all elevation logic
   -> print_system_config() -> run_shell()
```

### Why `ShellExecuteW` and not `CreateProcessWithTokenW`

`CreateProcessWithTokenW` requires duplicating an admin token -- which itself requires
`SE_IMPERSONATE_PRIVILEGE`, a privilege you only have if you are already admin. It is
circular. `ShellExecuteW` with `"runas"` is the documented user-facing API that triggers
the OS consent UI. No privilege is required to call it.

### The non-admin fallback

If the user says `n` to the prompt, aport continues as a regular user. Some ports
(kernel-bound or system-process-owned) will show `[ACCESS DENIED]` instead of process names.
The tool is still useful -- it shows all user-space ports.

---

## 5. Boot-Keyed Consent Cache

### The problem

We want "ask once per boot, never again until reboot." The naive solution -- a flag file --
fails because:
- A permanent file survives reboots -> user is never asked again after the first run ever
- A session file (using session ID) is unavailable to elevated processes (different session)
- A registry key is hard to clean up and requires write access to HKLM

### The solution: `psutil.boot_time()` as cache key

`psutil.boot_time()` returns the Unix timestamp (float) of when the OS kernel started.
This value:
- Is **constant** for the entire current boot session
- **Changes** at every shutdown/reboot
- Is **readable without admin** from any process
- Is **identical** between the non-elevated and elevated process on the same boot

```python
def _boot_time_key() -> str:
    return str(int(psutil.boot_time()))
    # Example: "1788634154"
    # = 2026-09-06 00:19:14 UTC -- when this machine last booted
```

The cache file (`%TEMP%\aport_consent.dat`) stores (before encryption):
```json
{"boot_key": "1788634154", "granted": true}
```

### Comparison with alternatives

| Method              | Survives reboot? | Works across elevation? | Extra permissions? |
|---------------------|------------------|-------------------------|--------------------|
| `boot_time()` key   | No (key changes) | Yes                     | No                 |
| Session ID          | No               | No (new session)        | No                 |
| Registry HKCU       | Yes (bad)        | Yes                     | No                 |
| Scheduled Task      | Yes (bad)        | Yes                     | Yes (admin)        |
| Named pipe / mutex  | No               | Yes                     | No                 |

`boot_time()` is the cleanest option with zero side effects.

---

## 6. DPAPI Encryption

### Why encrypt a consent file?

Without encryption, anyone (or any malware) can write:
```json
{"boot_key": "1788634154", "granted": true}
```
...using the current boot time (publicly readable via `psutil`) and trick aport into
auto-elevating without ever showing a UAC prompt.

### What is DPAPI?

Windows Data Protection API (`crypt32.dll`) provides OS-managed encryption tied to the
current Windows user's login credentials. The key material is stored in
`%APPDATA%\Microsoft\Protect\`. You never see or manage the key -- Windows does.

### Our implementation

```python
# Encrypt: plaintext bytes -> DPAPI blob
ctypes.windll.crypt32.CryptProtectData(
    in_blob,                     # data to encrypt
    c_wchar_p("aport-consent"),  # optional description label
    None, None, None,
    c_uint(0),                   # 0 = user-level
    out_blob,                    # output: encrypted BLOB
)

# Decrypt: DPAPI blob -> plaintext bytes
ctypes.windll.crypt32.CryptUnprotectData(
    in_blob, None, None, None, None,
    c_uint(0),
    out_blob,
)
```

**Critical fix discovered:** `ctypes.POINTER(c_byte)` returns **signed** bytes on Windows.
Calling `bytes(blob.pbData[:blob.cbData])` on a signed pointer raises
`ValueError: bytes must be in range(0, 256)`.
Fix: use `c_ubyte` and `ctypes.string_at(blob.pbData, blob.cbData)` for the final copy.

### Storage format

The DPAPI blob is raw binary. It is base64-encoded for safe ASCII storage:

```
File: %TEMP%\aport_consent.dat

AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAARVbGSDY4ck2ZK+WszlsyiAAAAAAcAAAA
YQBwAG8AcgB0AC0AYwBvAG4AcwBlAG4AdAAAAA...
```

Changing even 1 character -> `CryptUnprotectData` returns `False` -> consent denied.

### Security properties

| Property       | Detail                                                         |
|----------------|----------------------------------------------------------------|
| User-bound     | Only decryptable by the same Windows user                      |
| Machine-bound  | Blob copied to another machine fails to decrypt                |
| Tamper-proof   | Any edit to the file causes decrypt failure                    |
| Key-less       | No key file; Windows manages key material in Protect\ folder   |
| Zero deps      | Pure `ctypes` -- no `cryptography` package needed              |
| Fallback       | Non-Windows: plaintext JSON (Linux/macOS have no DPAPI)        |

---

## 7. Interactive Shell (REPL)

### Design

The shell (`aport/shell.py`) is a `while True` input loop -- no external library needed.

```
  ______  ____  ____  ____  ______
 /  _  \ |  _ \|  _ \|  _ \|_   _|
 | |_| | | |_) | |_) | |_) | | |
 |  _  | |  __/|  __/|  _ <  | |
 |_| |_| |_|   |_|   |_| \_\ |_|

  Advanced Port Inspector  --  System Network Monitor

[ HOST: RG-19-Cyber ] [ PRIV: ADMIN ] [ CPU: 16% ] [ RAM: 53% ] [ TIME: 13:39 ]

  aport >
```

### Command dispatch table

| Command    | Handler           | Description                       |
|------------|-------------------|-----------------------------------|
| `list`     | `_run_list()`     | All open ports (filterable)       |
| `monitor`  | `_run_monitor()`  | Live htop dashboard               |
| `top N`    | `_run_top()`      | Top N ports by connections        |
| `port N`   | `_run_port()`     | Detail for port N                 |
| `kill N`   | `kill_port()`     | Kill process on port N            |
| `transfer N`| `transfer_port()` | Kill process and assign new service|
| `services` | `_run_services()` | Service name lookup               |
| `watch`    | `_run_watch()`    | Auto-refreshing port table        |
| `sysinfo`  | `print_system_config()` | System snapshot             |
| `elevate`  | `_request_elevation()`| Re-launch with Administrator (UAC)|
| `help`     | `_print_help()`   | Command reference                 |
| `clear`    | `_clear_screen()` | Clear + reprint banner            |
| `exit`     | break             | Exit REPL                         |

### Why not `prompt_toolkit`?

`prompt_toolkit` gives history and autocomplete but adds a large dependency and requires
careful handling in elevated consoles (restricted terminal capabilities). The simple
`input()` loop is 100% reliable in any Windows console, elevated or not.

---

## 8. Obfuscation -- How It Works

### Tool: PyArmor 9.2.7

PyArmor works by:

1. **Compiling** each `.py` file to CPython bytecode internally
2. **Encrypting** the bytecode with a per-build AES key
3. **Replacing** the source file with a 3-line loader stub
4. **Providing** a native extension (`pyarmor_runtime.pyd`) that holds the decryption
   engine and key

### Command used

```powershell
pyarmor gen --recursive --output dist aport run.py
```

- `--recursive`: process all `.py` files inside `aport/`
- `--output dist`: write obfuscated files to `dist/`
- `aport run.py`: two top-level resources (package + launcher script)

### What PyArmor generates

```
dist/
├── run.py                         <- obfuscated loader (3 lines, ~116 KB payload)
├── aport/
│   ├── cli.py                     <- obfuscated loader (~47 KB)
│   ├── display.py                 <- obfuscated loader (~51 KB)
│   ├── monitor.py                 <- obfuscated loader (~80 KB)
│   ├── scanner.py                 <- obfuscated loader (~34 KB)
│   ├── shell.py                   <- obfuscated loader (~61 KB)
│   └── __init__.py                <- obfuscated loader (~2 KB)
└── pyarmor_runtime_000000/
    ├── __init__.py                <- thin Python init for the runtime package
    └── pyarmor_runtime.pyd        <- native DLL (~625 KB), decryption engine
```

### The 3-line loader (what every obfuscated file looks like)

```python
# Pyarmor 9.2.7 (trial), 000000, non-profits, 2026-09-07T16:59:27.584658
from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x00\x03\r\x00...<encrypted bytes>...')
```

- **Line 1:** Comment -- PyArmor version, license ID, timestamp
- **Line 2:** Imports the `__pyarmor__` function from the runtime extension
- **Line 3:** Calls `__pyarmor__()` with three arguments:
  - `__name__` -- the module name (so the runtime registers it correctly)
  - `__file__` -- the file path (used for error tracebacks)
  - `b'...'` -- the payload: encrypted bytecode as a bytes literal

### Anatomy of the payload bytes

```
Offset  Size  Content
------  ----  -------------------------------------------------
0       8     Magic header: b'PY000000'  (PyArmor signature)
8       1     Major version byte: 0x00
9       1     Minor version byte: 0x03
10      2     Flags / mode word
12      4     Checksum / header metadata
16      4     Encrypted payload length (little-endian uint32)
20      N     AES-encrypted CPython bytecode (.pyc format internally)
```

The encrypted payload is the `.pyc` bytecode of the original `.py` file, encrypted with a
key stored **inside** `pyarmor_runtime.pyd`. The key is never written to disk as a
standalone file -- it lives in native (compiled C) memory.

### What `pyarmor_runtime.pyd` does at runtime

1. `__pyarmor__()` is called with the payload bytes
2. The `.pyd` reads the payload header to identify encryption parameters
3. It decrypts the payload in native memory using the embedded key
4. It unmarshals the result as a Python code object (equivalent to `marshal.loads()`)
5. It executes the code object in the calling module's namespace
6. All original functions, classes, and globals are now live in memory

From the caller's perspective, `import aport.cli` is identical whether the file is
obfuscated or not.

---

## 9. Obfuscation -- File-by-File Analysis

### `dist/run.py` (~116 KB payload)

Largest file because `run.py` is the most complex module (~700 lines including DPAPI,
system config, menu, elevation logic). The payload is ~116 KB of encrypted bytecode.

Original source contains:
- `is_admin()` -- WinAPI call via ctypes
- `_dpapi_encrypt()` / `_dpapi_decrypt()` -- DPAPI wrappers
- `_consent_for_this_boot()` / `_save_consent()` -- consent cache R/W
- `request_elevation_windows()` -- ShellExecuteW call
- `print_system_config()` -- system snapshot
- `main()` -- orchestrates all of the above
- `interactive_menu()` -- numbered menu loop

All of this is invisible in the obfuscated file -- only the 3-line loader is visible.

### `dist/aport/cli.py` (~47 KB payload)

Contains all Click command definitions. The original has `@click.command()` decorators,
argument parsing, and dispatch calls. All hidden.

### `dist/aport/display.py` (~51 KB payload)

Rich table rendering code. String-heavy (colour names, column headers, format strings).
All encrypted -- no string literals visible.

### `dist/aport/monitor.py` (~80 KB payload)

Largest aport submodule. Contains the live dashboard with 5 Rich panels and the 1-second
refresh loop. The `Rich.Live` context manager code, panel layout, and all metric
formatting is hidden.

### `dist/aport/scanner.py` (~34 KB payload)

psutil data collection. The original has `psutil.net_connections()`, `process_iter()`,
and interface stats calls. None visible in obfuscated form.

### `dist/aport/shell.py` (~61 KB payload)

REPL loop, banner art, status bar, command dispatch table. The ASCII art banner string
(which is large) contributes significantly to the payload size.

### `dist/aport/__init__.py` (~2 KB payload)

Just the version string and package init. Smallest file.

### `dist/pyarmor_runtime_000000/pyarmor_runtime.pyd` (~625 KB)

This is a **Windows native DLL** (renamed `.pyd` for Python import compatibility).
It is not Python source -- it is compiled x86_64 machine code. It contains:

- The AES decryption engine
- The embedded decryption key for this specific build
- Anti-debug checks (in licensed/pro versions)
- The `__pyarmor__()` function exported for Python import

**This file is the most critical component.** Without it, no obfuscated file can run.

---

## 10. Reversing the Obfuscation -- Theoretical Limits

### What is NOT possible without the key

| Attack                          | Why it fails                                              |
|---------------------------------|-----------------------------------------------------------|
| Read source from `.py` file     | Only encrypted bytes present; no AST or identifiers       |
| `dis.dis()` the module          | You get the `__pyarmor__()` call -- nothing from original |
| `inspect.getsource()`           | Returns the 3-line loader only                            |
| `marshal.loads()` on payload    | Payload is AES-encrypted; `marshal` sees garbage          |
| `strings` / grep on `.py`       | All string literals are inside the encrypted payload      |
| Grep for function names         | No function names in the `.py` file                       |

### What IS theoretically possible (advanced)

| Attack                        | Difficulty | Notes                                               |
|-------------------------------|------------|-----------------------------------------------------|
| Memory dump at runtime        | Very Hard  | Decrypted bytecode exists briefly in RAM. A kernel-level debugger (WinDbg) could dump the heap and find the decrypted `.pyc` bytecode object |
| Hook `marshal.loads`          | Hard       | PyArmor calls an internal equivalent of `marshal.loads`. Hooking it via ctypes or a `.pyd` shim could capture the decrypted code object |
| Reverse the `.pyd`            | Expert     | IDA Pro / Ghidra can disassemble `pyarmor_runtime.pyd`. The decryption key is embedded in native code -- extracting it requires days of reverse engineering |
| PyArmor trial key attack      | N/A        | Trial uses a known license ID (000000), but PyArmor still rotates per-build parameters, so source code is not directly recoverable |

### Bottom line

For practical purposes -- protecting source code from casual inspection, competitors,
or script-kiddie extraction -- PyArmor 9 provides **strong protection**:

- Source is not readable
- String literals are not grep-able
- Function names are gone
- No class hierarchy is visible

For protection against a determined reverse engineer with kernel debugger access,
no Python obfuscation is absolute. The language requires eventual execution as Python
bytecode, which means decrypted code exists transiently in memory.

**If absolute protection is required:** compile to native code using **Nuitka**
(transpiles Python to C++ -> machine code) or **Cython**. These eliminate the Python
interpreter layer entirely.

---

## 11. Security Properties Summary

| Feature                          | Protection Level | Notes                                          |
|----------------------------------|------------------|------------------------------------------------|
| Source obfuscation (PyArmor)     | Strong           | No readable source; no strings; no func names  |
| Consent file encryption (DPAPI)  | Strong           | OS-managed key; user+machine bound; tamperproof|
| Boot-keyed consent expiry        | By Design        | Automatically expires on reboot; no cleanup    |
| UAC elevation                    | OS-level         | Standard Windows security; cannot be bypassed  |
| Crash log                        | Operational      | All errors captured to `aport_crash.log`       |
| PYTHONPATH injection             | Operational      | Ensures venv packages available when elevated  |

---

## 12. Build & Distribution

### Running the source version

```powershell
# From project root: d:\Aditya\aport\
pip install -e .           # install package in editable mode
python run.py              # ask for privilege -> elevated shell
aport --help               # CLI directly, no elevation
```

### Running the obfuscated version

```powershell
cd dist\
python run.py              # identical UX to source version
```

**Requirements for `dist/` to work:**
- `pyarmor_runtime_000000/` must be present alongside the Python files
- The runtime `.pyd` is platform-specific (Windows x86_64 only in this build)
- Python 3.13 required (PyArmor 9 generates version-specific bytecode)

### Re-obfuscating after source changes

```powershell
# From project root
Remove-Item -Recurse -Force dist\
pyarmor gen --recursive --output dist aport run.py
```

### PyArmor advanced protection modes (licensed build only)

| Mode         | What it does                                  | Protection level   |
|--------------|-----------------------------------------------|--------------------|
| Default      | Encrypts bytecode (current build)             | Good               |
| RFT Mode     | Renames functions/variables before encryption | Better             |
| BCC Mode     | Converts bytecode to native C code            | Best (near-Nuitka) |

Upgrade with:
```powershell
pyarmor reg <license-file.regi>
pyarmor gen --recursive --output dist aport run.py
```

---

*Document generated: 2026-09-07 | aport v0.1.0 | Machine: RG-19-Cyber | Windows 11 Build 26200*
