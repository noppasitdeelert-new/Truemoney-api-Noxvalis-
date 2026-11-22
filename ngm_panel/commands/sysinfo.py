"""Local system inspection: OS, hardware, disks, environment, adapters."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import time
from typing import List

from .. import system
from ..registry import Registry
from ..runner import parse_flags
from .common import env_items, human_bytes


def _windows_drives() -> List[str]:
    drives: List[str] = []
    try:
        import ctypes

        bitmask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
        for index in range(26):
            if bitmask & (1 << index):
                drives.append(chr(ord("A") + index) + ":\\")
    except Exception:
        drives = ["C:\\"]
    return drives


def cmd_info(ctx, argv: List[str]) -> int:
    ctx.console.heading("System information")
    ctx.console.keyvalue(
        [
            ("Hostname", socket.gethostname()),
            ("OS", f"{platform.system()} {platform.release()} ({platform.version()})"),
            ("Architecture", f"{platform.machine()} / {platform.processor() or 'n/a'}"),
            ("Python", f"{platform.python_version()} ({platform.python_implementation()})"),
            ("User", system.local_username()),
            ("Home", system.home()),
            ("Working dir", os.getcwd()),
            ("CPU cores", os.cpu_count() or "?"),
            ("Boot time", f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - _uptime_seconds()))}"),
        ]
    )
    payload = {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "user": system.local_username(),
        "cwd": os.getcwd(),
        "cpu_count": os.cpu_count(),
    }
    ctx.print_json(payload)
    return 0


def _uptime_seconds() -> float:
    if system.is_windows():
        try:
            import ctypes

            return ctypes.windll.kernel32.GetTickCount64() / 1000.0  # type: ignore[attr-defined]
        except Exception:
            return 0.0
    try:
        with open("/proc/uptime", "r", encoding="ascii") as handle:
            return float(handle.read().split()[0])
    except (OSError, ValueError):
        return 0.0


def cmd_uptime(ctx, argv: List[str]) -> int:
    seconds = _uptime_seconds()
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    ctx.console.heading("Uptime")
    ctx.console.line(f"  {days}d {hours}h {minutes}m {secs}s")
    ctx.print_json({"uptime_seconds": seconds})
    return 0


def cmd_disk(ctx, argv: List[str]) -> int:
    ctx.console.heading("Disk usage")
    rows = []
    drives = _windows_drives() if system.is_windows() else ["/"]
    if not system.is_windows():
        try:
            with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as handle:
                mounts = [line.split()[1] for line in handle if line.startswith("/dev/")]
            drives = ["/"] + [m for m in mounts if m not in {"/"}][:10]
        except OSError:
            pass
    for drive in drives:
        try:
            usage = shutil.disk_usage(drive)
        except OSError:
            continue
        used_ratio = usage.used / usage.total if usage.total else 0
        rows.append(
            [
                drive,
                human_bytes(usage.total),
                human_bytes(usage.used),
                human_bytes(usage.free),
                ctx.console.bar(used_ratio, width=16) + f" {used_ratio * 100:5.1f}%",
            ]
        )
    ctx.console.table(["Drive", "Total", "Used", "Free", "Usage"], rows)
    ctx.print_json({"drives": rows})
    return 0


def cmd_hardware(ctx, argv: List[str]) -> int:
    ctx.console.heading("Hardware")
    ctx.console.keyvalue(
        [
            ("Machine", platform.machine()),
            ("Processor", platform.processor() or "n/a"),
            ("Logical CPUs", os.cpu_count() or "?"),
        ]
    )
    memory = _total_memory()
    if memory:
        ctx.console.line(f"  {'Memory':<16}  {human_bytes(memory)}")
    if system.is_windows():
        output = system.powershell(
            "$c=Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfCores,NumberOfLogicalProcessors;"
            "$b=Get-CimInstance Win32_BaseBoard | Select-Object -First 1 Manufacturer,Product;"
            "$c | Format-List; $b | Format-List"
        )
        if "ngm-panel" not in output:
            ctx.console.heading("CIM detail")
            for line in output.splitlines():
                if line.strip():
                    ctx.console.line("  " + line.strip())
    ctx.print_json({"machine": platform.machine(), "cpu": platform.processor(), "cpu_count": os.cpu_count(),
                    "memory_bytes": memory})
    return 0


def _total_memory() -> int:
    if system.is_windows():
        try:
            import ctypes

            class MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatusEx()
            status.dwLength = ctypes.sizeof(MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
                return int(status.ullTotalPhys)
        except Exception:
            return 0
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return 0


def cmd_env(ctx, argv: List[str]) -> int:
    prefix = argv[0] if argv else ""
    rows = env_items(prefix)
    ctx.console.heading(f"Environment variables{' · prefix=' + prefix if prefix else ''}")
    ctx.console.table(["Name", "Value"], rows)
    ctx.print_json({"prefix": prefix, "variables": {row[0]: row[1] for row in rows}})
    return 0


def cmd_env_get(ctx, argv: List[str]) -> int:
    name = ctx.need(argv, 0, "sys.env-get <NAME>", "ชื่อตัวแปร")
    value = os.environ.get(name)
    if value is None:
        ctx.console.warn(f"ไม่พบตัวแปร {name}")
        return 1
    ctx.console.line(f"  {name} = {value}")
    ctx.print_json({name: value})
    return 0


def cmd_adapters(ctx, argv: List[str]) -> int:
    ctx.console.heading("Network adapters")
    if system.is_windows():
        output = system.run_text(["ipconfig", "/all"], timeout=ctx.timeout())
        for line in output.splitlines():
            if line.strip():
                ctx.console.line("  " + line.rstrip())
        ctx.print_json({"raw": output})
        return 0
    if system.have("ip"):
        ctx.console.line(system.run_text(["ip", "-brief", "address"]))
    elif system.have("ifconfig"):
        ctx.console.line(system.run_text(["ifconfig", "-a"]))
    else:
        ctx.console.warn("ไม่พบคำสั่ง ip/ifconfig")
        return 1
    return 0


def cmd_users(ctx, argv: List[str]) -> int:
    ctx.console.heading("Logged-on users")
    if system.is_windows():
        output = system.run_text(["query", "user"], timeout=ctx.timeout())
    else:
        output = system.run_text(["who"], timeout=ctx.timeout())
    ctx.console.line(output or "(none)")
    return 0


def cmd_time(ctx, argv: List[str]) -> int:
    now = time.time()
    ctx.console.heading("Time")
    ctx.console.keyvalue(
        [
            ("Local", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))),
            ("UTC", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now))),
            ("Timezone", time.tzname[0] if time.tzname else "-"),
            ("Epoch", f"{now:.0f}"),
        ]
    )
    ctx.print_json({"local": time.ctime(now), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                    "tz": time.tzname, "epoch": now})
    return 0


def cim_query(ctx, class_name: str) -> int:
    ctx.console.heading(f"CIM · {class_name}")
    if not system.is_windows():
        ctx.console.warn("คำสั่ง CIM/WMI ใช้ได้บน Windows เท่านั้น")
        return 1
    script = f"Get-CimInstance -ClassName {class_name} | Format-List *"
    output = system.powershell(script, timeout=45)
    if not output.strip():
        ctx.console.warn(f"ไม่พบข้อมูลสำหรับ {class_name}")
        return 1
    for line in output.splitlines():
        if line.strip():
            ctx.console.line("  " + line.strip()[:200])
    ctx.print_json({"class": class_name, "raw": output})
    return 0


def cmd_cim(ctx, argv: List[str]) -> int:
    class_name = ctx.need(argv, 0, "sys.cim <Win32_Class>", "ชื่อ CIM class")
    return cim_query(ctx, class_name)


def make_cim_command(class_name: str):
    def handler(ctx, argv: List[str]) -> int:
        return cim_query(ctx, class_name)

    return handler


def register(registry: Registry) -> None:
    registry.add(cmd_info, name="sys.info", category="sys", usage="sys.info",
                 description="ข้อมูลระบบปฏิบัติการ เครื่อง และผู้ใช้")
    registry.add(cmd_hardware, name="sys.hardware", category="sys", usage="sys.hardware",
                 description="ข้อมูล CPU/เมนบอร์ด/หน่วยความจำของเครื่อง")
    registry.add(cmd_disk, name="sys.disk", category="sys", usage="sys.disk",
                 description="พื้นที่ดิสก์ทั้งหมดที่ใช้งานได้ พร้อมแถบเปอร์เซ็นต์")
    registry.add(cmd_env, name="sys.env", category="sys", usage="sys.env [prefix]",
                 description="แสดงตัวแปรสภาพแวดล้อม (ปิดบังค่า secret อัตโนมัติ)")
    registry.add(cmd_env_get, name="sys.env-get", category="sys", usage="sys.env-get <NAME>",
                 description="อ่านค่าตัวแปรสภาพแวดล้อมตัวเดียว")
    registry.add(cmd_adapters, name="sys.adapters", category="sys", usage="sys.adapters",
                 description="รายละเอียด network adapter ในเครื่อง (ipconfig /all)")
    registry.add(cmd_uptime, name="sys.uptime", category="sys", usage="sys.uptime",
                 description="ระยะเวลาที่เครื่องเปิดทำงาน")
    registry.add(cmd_users, name="sys.users", category="sys", usage="sys.users",
                 description="รายชื่อผู้ใช้ที่ล็อกอินอยู่ (query user / who)")
    registry.add(cmd_time, name="sys.time", category="sys", usage="sys.time",
                 description="เวลา local/UTC/timezone ของเครื่อง")
    registry.add(cmd_cim, name="sys.cim", category="sys", usage="sys.cim <Win32_Class>",
                 description="query WMI/CIM class ใดก็ได้บน Windows")
