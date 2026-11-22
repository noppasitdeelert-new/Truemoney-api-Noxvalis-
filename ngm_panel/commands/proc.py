"""Process and service inspection."""

from __future__ import annotations

import os
from typing import List

from .. import system
from ..registry import Registry
from ..runner import parse_flags
from .common import windows_process_table


def cmd_list(ctx, argv: List[str]) -> int:
    positionals, flags = parse_flags(argv, {"sort": "str", "top": "int", "n": "int"})
    sort_key = str(flags.get("sort", "cpu")).lower()
    limit = int(flags.get("top") or flags.get("n") or 25)
    rows = windows_process_table(limit=limit, sort_key=sort_key)
    ctx.console.heading(f"Processes (top {limit} by {sort_key})")
    if not rows:
        ctx.console.warn("อ่านรายการโปรเซสไม่ได้บนระบบนี้")
        return 1
    ctx.console.table(["PID", "Name", "Memory", "CPU(s)"], rows)
    ctx.print_json({"processes": rows})
    return 0


def cmd_find(ctx, argv: List[str]) -> int:
    needle = ctx.need(argv, 0, "proc.find <name>", "ชื่อโปรเซส").lower()
    rows = [row for row in windows_process_table(limit=400) if needle in row[1].lower()]
    ctx.console.heading(f"Processes matching '{needle}'")
    if not rows:
        ctx.console.warn("ไม่พบโปรเซส")
        return 1
    ctx.console.table(["PID", "Name", "Memory", "CPU(s)"], rows)
    return 0


def cmd_kill(ctx, argv: List[str]) -> int:
    pid = ctx.need(argv, 0, "proc.kill <pid> [--yes]", "PID")
    if not pid.isdigit():
        ctx.console.err("PID ต้องเป็นตัวเลข")
        return 2
    if not ctx.options.yes and not ctx.console.confirm(f"ยืนยันการสิ้นสุดโปรเซส PID {pid}?", default=False):
        ctx.console.warn("ยกเลิก")
        return 0
    if ctx.options.dry_run:
        ctx.console.info(f"--dry-run: จะสิ้นสุด PID {pid}")
        return 0
    if system.is_windows():
        output = system.run_text(["taskkill", "/PID", pid, "/F"])
    else:
        output = system.run_text(["kill", "-TERM", pid])
    ctx.console.line("  " + (output or "(no output)"))
    return 0


def cmd_services(ctx, argv: List[str]) -> int:
    needle = (argv[0] if argv else "").lower()
    ctx.console.heading("Windows services" + (f" · filter={needle}" if needle else ""))
    if system.is_windows():
        output = system.powershell(
            "Get-Service | Sort-Object Status,Name | "
            "ForEach-Object { \"$($_.Status)|$($_.Name)|$($_.DisplayName)\" }",
            timeout=45,
        )
        rows = []
        for line in output.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 3:
                if needle and needle not in parts[1].lower() and needle not in parts[2].lower():
                    continue
                rows.append(parts)
        if not rows:
            ctx.console.warn("อ่านรายการ service ไม่ได้")
            return 1
        ctx.console.table(["Status", "Name", "Display name"], rows[:200])
        return 0
    if system.have("systemctl"):
        output = system.run_text(["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"])
        rows = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and (not needle or needle in line.lower()):
                rows.append([parts[3], parts[0], " ".join(parts[4:])])
        ctx.console.table(["State", "Unit", "Description"], rows[:200])
        return 0
    ctx.console.warn("ไม่พบระบบ service ที่รองรับ")
    return 1


def service_status(ctx, name: str) -> int:
    ctx.console.heading(f"Service · {name}")
    if system.is_windows():
        output = system.run_text(["sc", "query", name], timeout=ctx.timeout())
    elif system.have("systemctl"):
        output = system.run_text(["systemctl", "status", name, "--no-pager"], timeout=ctx.timeout())
    else:
        output = ""
    if not output.strip():
        ctx.console.warn("ไม่พบ service นี้หรือระบบไม่รองรับ")
        return 1
    for line in output.splitlines()[:40]:
        if line.strip():
            ctx.console.line("  " + line.strip())
    ctx.print_json({"service": name, "raw": output})
    return 0


def cmd_service(ctx, argv: List[str]) -> int:
    name = ctx.need(argv, 0, "proc.service <service-name>", "ชื่อ service")
    return service_status(ctx, name)


def make_service_command(name: str):
    def handler(ctx, argv: List[str]) -> int:
        return service_status(ctx, name)

    return handler


def cmd_startup(ctx, argv: List[str]) -> int:
    ctx.console.heading("Startup programs")
    entries: List[List[str]] = []
    if system.is_windows():
        output = system.powershell(
            "Get-CimInstance Win32_StartupCommand | "
            "ForEach-Object { \"$($_.Name)|$($_.Command)|$($_.Location)\" }"
        )
        for line in output.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 3:
                entries.append([parts[0], parts[1][:90], parts[2]])
    if not entries:
        ctx.console.warn("ไม่พบข้อมูล startup (หรือไม่ใช่ Windows)")
        return 1
    ctx.console.table(["Name", "Command", "Location"], entries)
    return 0


def cmd_ports(ctx, argv: List[str]) -> int:
    """Listening ports with owning process — same data as net.listen, proc view."""
    from .common import listening_ports, pid_name

    ctx.console.heading("Ports by process")
    entries = listening_ports()
    if not entries:
        ctx.console.warn("อ่านข้อมูลไม่ได้")
        return 1
    rows = [[entry["port"], entry["proto"], entry["pid"], pid_name(entry["pid"])] for entry in entries]
    ctx.console.table(["Port", "Proto", "PID", "Process"], sorted(rows, key=lambda row: int(row[0])))
    return 0


def register(registry: Registry) -> None:
    registry.add(cmd_list, name="proc.list", category="proc", usage="proc.list [--sort cpu|mem|name] [--top N]",
                 description="รายการโปรเซสที่ใช้ทรัพยากรสูงสุด")
    registry.add(cmd_find, name="proc.find", category="proc", usage="proc.find <name>",
                 description="ค้นหาโปรเซสจากชื่อ")
    registry.add(cmd_kill, name="proc.kill", category="proc", usage="proc.kill <pid> [--yes]",
                 description="สิ้นสุดโปรเซสตาม PID (มีคำยืนยัน)")
    registry.add(cmd_services, name="proc.services", category="proc", usage="proc.services [filter]",
                 description="รายการ service ทั้งหมดของ Windows พร้อมสถานะ")
    registry.add(cmd_service, name="proc.service", category="proc", usage="proc.service <service-name>",
                 description="สถานะ service เดี่ยว (sc query / systemctl status)")
    registry.add(cmd_startup, name="proc.startup", category="proc", usage="proc.startup",
                 description="รายการโปรแกรมที่เริ่มทำงานตอนเปิดเครื่อง")
    registry.add(cmd_ports, name="proc.ports", category="proc", usage="proc.ports",
                 description="พอร์ตที่เปิดอยู่พร้อมโปรเซสเจ้าของ")
