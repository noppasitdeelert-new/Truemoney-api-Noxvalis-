"""Helpers shared by command modules (scope checks, formatting, process tables)."""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional

from .. import net_utils, system


def authorize(ctx, host_or_url: str, port: Optional[int] = None) -> str:
    """Scope-check a host/URL and every address it resolves to."""
    host = ctx.guard.authorize(host_or_url, port)
    if net_utils.is_ip(host):
        ctx.guard.check_ip(host)
    return host


def resolve_checked(ctx, host: str, qtype: str = "A") -> List[str]:
    addresses = net_utils.resolve(host, qtype)
    for address in addresses:
        ctx.guard.check_ip(address)
    return addresses


def human_bytes(value: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} PB"


def ms_text(value: float) -> str:
    return f"{value:.1f} ms"


def status_badge(console, ok: bool) -> str:
    return console.green("OPEN") if ok else console.red("CLOSED")


def windows_process_table(limit: int = 30, sort_key: str = "cpu") -> List[List[str]]:
    """Return [pid, name, memory, cpu] rows, Windows-first with POSIX fallback."""
    rows: List[List[str]] = []
    if system.is_windows():
        script = (
            "$p = Get-Process | Sort-Object -Property "
            + ("CPU" if sort_key == "cpu" else "WorkingSet64" if sort_key == "mem" else "ProcessName")
            + " -Descending | Select-Object -First "
            + str(limit)
            + " Id,ProcessName,@{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB,1)}},"
            "@{n='CpuSec';e={if($_.CPU){[math]::Round($_.CPU,1)}else{0}}};"
            "$p | ForEach-Object { \"$($_.Id)|$($_.ProcessName)|$($_.MemMB)|$($_.CpuSec)\" }"
        )
        output = system.powershell(script)
        for line in output.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 4 and parts[0].isdigit():
                rows.append([parts[0], parts[1], f"{parts[2]} MB", parts[3]])
        if rows:
            return rows
        output = system.run_text(["tasklist", "/fo", "csv", "/nh"])
        for line in output.splitlines():
            cells = [cell.strip('"') for cell in line.split('","')]
            if len(cells) >= 5 and cells[1].isdigit():
                rows.append([cells[1], cells[0].strip('"'), cells[4].strip('"'), "-"])
            if len(rows) >= limit:
                break
        return rows

    args = ["ps", "-eo", "pid,comm,rss,pcpu", "--sort=-pcpu"] if system.have("ps") else []
    if args:
        output = system.run_text(args)
        for line in output.splitlines()[1 : limit + 1]:
            parts = line.split(None, 3)
            if len(parts) == 4 and parts[0].isdigit():
                rows.append([parts[0], parts[1], human_bytes(int(parts[2]) * 1024), parts[3]])
    return rows


def listening_ports() -> List[Dict[str, str]]:
    """Parse local listening sockets with owning PIDs (netstat/ss)."""
    entries: List[Dict[str, str]] = []
    if system.is_windows():
        output = system.run_text(["netstat", "-ano", "-p", "TCP"])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                local, pid = parts[1], parts[4]
                address, _, port = local.rpartition(":")
                entries.append({"address": address, "port": port, "pid": pid, "proto": "TCP"})
        return entries

    if system.have("ss"):
        output = system.run_text(["ss", "-ltnp"])
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            address, _, port = local.rpartition(":")
            pid = ""
            if "pid=" in line:
                pid = line.split("pid=", 1)[1].split(",", 1)[0]
            entries.append({"address": address, "port": port, "pid": pid, "proto": "TCP"})
    elif system.have("netstat"):
        output = system.run_text(["netstat", "-ltn"])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].lower().startswith("tcp"):
                local = parts[3]
                address, _, port = local.rpartition(":")
                entries.append({"address": address, "port": port, "pid": "", "proto": "TCP"})
    return entries


def pid_name(pid: str) -> str:
    if not pid or not pid.isdigit():
        return ""
    if system.is_windows():
        output = system.run_text(["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"])
        first = output.splitlines()[0] if output.splitlines() else ""
        cells = [cell.strip('"') for cell in first.split('","')]
        return cells[0] if cells and cells[0] and "INFO" not in cells[0].upper() else ""
    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return system.run_text(["ps", "-p", pid, "-o", "comm="]).strip()


def local_addresses() -> List[str]:
    addresses: List[str] = []
    try:
        infos = socket_infos()
    except OSError:
        return addresses
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def socket_infos():
    import socket

    return socket.getaddrinfo(socket.gethostname(), None)


def env_items(prefix: str = "") -> List[List[str]]:
    secret_markers = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "COOKIE", "AUTH")
    rows: List[List[str]] = []
    for key in sorted(os.environ):
        if prefix and not key.lower().startswith(prefix.lower()):
            continue
        value = os.environ[key]
        if any(marker in key.upper() for marker in secret_markers):
            value = "***hidden***" if value else ""
        rows.append([key, value if len(value) <= 90 else value[:87] + "..."])
    return rows


def current_python() -> str:
    return f"{sys.implementation.name} {system.python_version()}"
