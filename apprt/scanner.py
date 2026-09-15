"""
scanner.py — Core port scanning and activity engine.
Uses psutil to access OS-level socket/process data without needing raw system calls.
"""

import socket
import psutil
import time
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# ── Protocol helpers ─────────────────────────────────────────────────────────

_PROTO_MAP = {
    (socket.AF_INET, socket.SOCK_STREAM): "TCP",
    (socket.AF_INET, socket.SOCK_DGRAM):  "UDP",
    (socket.AF_INET6, socket.SOCK_STREAM): "TCP6",
    (socket.AF_INET6, socket.SOCK_DGRAM):  "UDP6",
}

_STATE_DISPLAY = {
    "LISTEN":       "LISTENING",
    "ESTABLISHED":  "ESTABLISHED",
    "TIME_WAIT":    "TIME_WAIT",
    "CLOSE_WAIT":   "CLOSE_WAIT",
    "SYN_SENT":     "SYN_SENT",
    "SYN_RECV":     "SYN_RECV",
    "FIN_WAIT1":    "FIN_WAIT1",
    "FIN_WAIT2":    "FIN_WAIT2",
    "LAST_ACK":     "LAST_ACK",
    "CLOSING":      "CLOSING",
    "CLOSED":       "CLOSED",
    "NONE":         "–",
}

# Known service names cache
_SERVICE_CACHE: dict[int, str] = {}


def resolve_service(port: int, proto: str = "tcp") -> str:
    if port in _SERVICE_CACHE:
        return _SERVICE_CACHE[port]
    try:
        name = socket.getservbyport(port, proto.lower().replace("6", ""))
    except (OSError, OverflowError):
        name = "–"
    _SERVICE_CACHE[port] = name
    return name


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class Connection:
    """Represents a single network connection tied to a port."""
    proto: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: Optional[int]
    process_name: str
    created: Optional[float]   # epoch seconds


@dataclass
class PortInfo:
    """Aggregated info for one local port."""
    port: int
    proto: str
    service: str
    state: str
    pid: Optional[int]
    process_name: str
    process_cmdline: str
    process_status: str
    process_cpu_percent: float
    process_memory_mb: float
    connections: list[Connection] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0


# ── Scanner ───────────────────────────────────────────────────────────────────

class PortScanner:
    """Collects open ports and their per-port activity from the OS."""

    def __init__(self, proto_filter: str = "all", state_filter: str = "all"):
        """
        proto_filter : 'tcp' | 'udp' | 'all'
        state_filter : 'listen' | 'established' | 'all'
        """
        self.proto_filter = proto_filter.upper()
        self.state_filter = state_filter.upper()

    # ── helpers ──

    def _process_info(self, pid: Optional[int]) -> dict:
        """Safely fetch process metadata."""
        info = {
            "name": "–",
            "cmdline": "–",
            "status": "–",
            "cpu_percent": 0.0,
            "memory_mb": 0.0,
        }
        if pid is None:
            return info
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                info["name"]       = p.name()
                info["cmdline"]    = " ".join(p.cmdline())[:120] or p.name()
                info["status"]     = p.status()
                info["cpu_percent"] = p.cpu_percent(interval=0.1)
                mem = p.memory_info()
                info["memory_mb"]  = round(mem.rss / (1024 * 1024), 2)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return info

    def _net_io_for_iface(self) -> dict:
        """Return per-interface IO counters (summed for totals)."""
        try:
            counters = psutil.net_io_counters(pernic=False)
            return {
                "bytes_sent":   counters.bytes_sent,
                "bytes_recv":   counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
            }
        except Exception:
            return {}

    # ── public API ──

    def scan(self) -> list[PortInfo]:
        """Return a list of PortInfo objects for every open local port."""

        # 1. Collect all connections from the OS
        try:
            raw_conns = psutil.net_connections(kind="all")
        except psutil.AccessDenied:
            # On Windows without admin, fall back to inet only
            raw_conns = psutil.net_connections(kind="inet")

        # 2. Group connections by (local_port, proto)
        port_map: dict[tuple, PortInfo] = {}

        for conn in raw_conns:
            if conn.laddr is None or not hasattr(conn.laddr, "port"):
                continue

            local_port = conn.laddr.port
            proto = _PROTO_MAP.get((conn.family, conn.type), "UNKNOWN")

            # Protocol filter
            if self.proto_filter != "ALL":
                if not proto.startswith(self.proto_filter.replace("6", "")):
                    continue

            # State filter
            state_raw = conn.status if conn.status else "NONE"
            state     = _STATE_DISPLAY.get(state_raw, state_raw)

            if self.state_filter == "LISTEN" and "LISTEN" not in state:
                continue
            if self.state_filter == "ESTABLISHED" and "ESTABLISHED" not in state:
                continue

            pid = conn.pid
            pinfo = self._process_info(pid)

            local_addr  = conn.laddr.ip  if conn.laddr  else "–"
            remote_addr = conn.raddr.ip  if conn.raddr  else "–"
            remote_port = conn.raddr.port if conn.raddr else 0

            connection = Connection(
                proto       = proto,
                local_addr  = local_addr,
                local_port  = local_port,
                remote_addr = remote_addr,
                remote_port = remote_port,
                state       = state,
                pid         = pid,
                process_name= pinfo["name"],
                created     = None,
            )

            key = (local_port, proto)
            if key not in port_map:
                service = resolve_service(local_port, proto)
                port_map[key] = PortInfo(
                    port             = local_port,
                    proto            = proto,
                    service          = service,
                    state            = state,
                    pid              = pid,
                    process_name     = pinfo["name"],
                    process_cmdline  = pinfo["cmdline"],
                    process_status   = pinfo["status"],
                    process_cpu_percent = pinfo["cpu_percent"],
                    process_memory_mb   = pinfo["memory_mb"],
                )

            port_map[key].connections.append(connection)

        # 3. Sort by port number
        result = sorted(port_map.values(), key=lambda x: x.port)
        return result

    def snapshot(self) -> dict:
        """Return a full system snapshot with port list + system network IO."""
        ports     = self.scan()
        net_io    = self._net_io_for_iface()
        timestamp = datetime.now().isoformat(timespec="seconds")

        return {
            "timestamp": timestamp,
            "host":      socket.gethostname(),
            "net_io":    net_io,
            "ports":     ports,
        }
