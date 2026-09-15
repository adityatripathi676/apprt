# aport 🔍

> **Advanced Port Inspector CLI** — real-time open port scanner with per-port process activity, connection details, and live-watch mode.

---

## Features

| Feature | Description |
|---|---|
| **`list`** | All open ports with PID, process name, CPU, memory, connection count |
| **`port <N>`** | Deep-dive into a single port: process details + every connection |
| **`watch`** | Live auto-refresh table (like `top` but for ports) |
| **`top`** | Ports ranked by active connection count |
| **`services`** | Map open ports to well-known service names |
| **JSON output** | `--json` flag on `list` and `port` commands |
| **Filters** | `--proto tcp|udp|all` and `--state listen|established|all` |

---

## Install

```bash
# 1. Create & activate a virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 2. Install aport in editable mode
pip install -e .
```

> **Windows note:** Run your terminal as **Administrator** for full port + process visibility.

---

## Usage

```
aport --help

Commands:
  list      List all open ports
  port      Deep-dive into a specific port
  watch     Live auto-refresh port table
  top       Top ports by connection count
  services  Port → service name lookup
```

### Examples

```bash
# List all open ports
aport list

# Only TCP ports in LISTENING state, verbose (shows process + connection tables)
aport list --proto tcp --state listen --verbose

# Full detail for port 443
aport port 443

# JSON output for port 80
aport port 80 --json

# Live-watch, refresh every 3 seconds
aport watch --interval 3

# Top 5 ports by connection count
aport top --limit 5

# Service name lookup for all open ports
aport services

# Resolve a single port
aport services --port 443
```

---

## Requirements

- Python 3.9+
- `psutil` — OS socket / process data
- `rich` — terminal rendering
- `click` — CLI framework
