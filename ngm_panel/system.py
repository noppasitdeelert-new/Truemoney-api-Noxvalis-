"""Thin, dependency-free wrappers around the local operating system."""

from __future__ import annotations

import locale
import os
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence


def is_windows() -> bool:
    return os.name == "nt"


def is_termux() -> bool:
    """True when running inside Termux on Android."""
    if os.environ.get("TERMUX_VERSION"):
        return True
    prefix = os.environ.get("PREFIX", "")
    return "com.termux" in prefix


def is_android() -> bool:
    if is_termux():
        return True
    return os.environ.get("ANDROID_ROOT") is not None and os.name == "posix"


def is_mobile() -> bool:
    """Termux / Android terminal: narrow screens and touch keyboards."""
    return is_termux() or is_android()


def platform_tag() -> str:
    if is_windows():
        return "windows"
    if is_termux():
        return "termux"
    if is_android():
        return "android"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def android_release() -> str:
    """Android version from system properties (Termux only, best effort)."""
    if not is_android():
        return ""
    for prop in ("ro.build.version.release", "ro.build.version.sdk"):
        output = run_text(["getprop", prop], timeout=5)
        if output and not output.startswith("[ngm-panel]"):
            return output.strip()
    return ""


def android_model() -> str:
    if not is_android():
        return ""
    output = run_text(["getprop", "ro.product.model"], timeout=5)
    return "" if output.startswith("[ngm-panel]") else output.strip()


def have(executable: str) -> bool:
    return shutil.which(executable) is not None


def _encoding() -> str:
    try:
        return locale.getpreferredencoding(False) or "utf-8"
    except Exception:
        return "utf-8"


def run(
    args: Sequence[str],
    timeout: float = 20.0,
    stdin_text: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a local program. Output is decoded defensively on any Windows codepage."""
    return subprocess.run(  # noqa: S603 - args are fixed lists, never shell strings
        list(args),
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding=_encoding(),
        errors="replace",
        timeout=timeout,
        shell=False,
    )


def run_text(args: Sequence[str], timeout: float = 20.0) -> str:
    try:
        completed = run(args, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"[ngm-panel] could not run {args[0]}: {exc}"
    output = (completed.stdout or "") + (completed.stderr or "")
    return output.strip()


def powershell(script: str, timeout: float = 25.0) -> str:
    """Run a read-only PowerShell snippet locally (Windows only)."""
    if not is_windows():
        return "[ngm-panel] PowerShell command is available on Windows only."
    exe = "powershell"
    if have("pwsh"):
        exe = "pwsh"
    return run_text(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
    )


def local_username() -> str:
    try:
        return os.getlogin()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def home() -> str:
    return os.path.expanduser("~")


TERMUX_API_COMMANDS = {
    "battery-status": "สถานะแบตเตอรี่ (termux-battery-status)",
    "brightness": "ระดับความสว่างหน้าจอ",
    "camera-info": "ข้อมูลกล้อง",
    "clipboard-get": "อ่านคลิปบอร์ด",
    "clipboard-set": "เขียนคลิปบอร์ด",
    "contact-list": "รายชื่อผู้ติดต่อ (ต้องอนุญาตสิทธิ์)",
    "downloads": "รายการไฟล์ใน Downloads",
    "fingerprint": "ทดสอบลายนิ้วมือ",
    "infrared-frequencies": "รายการความถี่ IR",
    "job-scheduler": "ตรวจ job scheduler",
    "location": "ตำแหน่งปัจจุบัน (ต้องอนุญาตสิทธิ์)",
    "media-player": "ควบคุมเครื่องเล่นมีเดีย",
    "microphone": "บันทึกเสียง",
    "notification": "ส่ง notification",
    "notification-list": "รายการ notification",
    "notification-remove": "ลบ notification",
    "sensor": "อ่านเซนเซอร์",
    "share": "แชร์ไฟล์ออกจาก Termux",
    "sms-list": "อ่าน SMS (ต้องอนุญาตสิทธิ์)",
    "storage-get": "เลือกไฟล์ผ่าน SAF",
    "telephony-cellinfo": "ข้อมูลเซลล์",
    "telephony-deviceinfo": "ข้อมูลอุปกรณ์โทรศัพท์",
    "toast": "แสดง toast",
    "torch": "เปิด/ปิดไฟฉาย",
    "tts-speak": "อ่านข้อความออกเสียง",
    "vibrate": "สั่น",
    "volume": "ระดับเสียง",
    "wifi-connectioninfo": "ข้อมูล Wi-Fi ที่เชื่อมต่อ",
    "wifi-scaninfo": "สแกน Wi-Fi รอบข้าง",
}


def termux_api_exe(name: str) -> Optional[str]:
    """Return the termux-api executable name when installed."""
    if not is_termux():
        return None
    executable = "termux-" + name
    return executable if have(executable) else None


def termux_api_missing_hint(name: str = "") -> str:
    executable = "termux-" + (name or "api")
    return (
        f"ไม่พบ {executable}\n"
        "ติดตั้ง: pkg install termux-api  (และติดตั้งแอป Termux:API จาก F-Droid)\n"
        "จากนั้นอนุญาตสิทธิ์ให้ Termux:API ตามที่ระบบขอ"
    )


def termux_run(name: str, args: Sequence[str] = (), timeout: float = 20.0) -> str:
    """Run a Termux:API helper and return its JSON/text output."""
    executable = termux_api_exe(name)
    if executable is None:
        return ""
    return run_text([executable, *args], timeout=timeout)


def termux_packages() -> List[str]:
    """Installed Termux packages (dpkg), empty when unavailable."""
    if not is_termux():
        return []
    output = run_text(["dpkg", "-f", "${Package}", "-W"], timeout=30)
    return [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("[ngm-panel]")]


def python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def cim_classes() -> List[str]:
    """A curated list of Windows CIM/WMI classes exposed as generated commands."""
    return [
        "Win32_OperatingSystem",
        "Win32_ComputerSystem",
        "Win32_Processor",
        "Win32_PhysicalMemory",
        "Win32_DiskDrive",
        "Win32_LogicalDisk",
        "Win32_NetworkAdapter",
        "Win32_NetworkAdapterConfiguration",
        "Win32_BIOS",
        "Win32_BaseBoard",
        "Win32_VideoController",
        "Win32_SoundDevice",
        "Win32_Printer",
        "Win32_USBController",
        "Win32_Keyboard",
        "Win32_PointingDevice",
        "Win32_Service",
        "Win32_Process",
        "Win32_StartupCommand",
        "Win32_Product",
        "Win32_QuickFixEngineering",
        "Win32_UserAccount",
        "Win32_Group",
        "Win32_Environment",
        "Win32_PageFileUsage",
        "Win32_SystemEnclosure",
        "Win32_TemperatureProbe",
        "Win32_Fan",
        "Win32_Battery",
        "Win32_DesktopMonitor",
        "Win32_SerialPort",
        "Win32_Modem",
        "Win32_Share",
        "Win32_Directory",
        "Win32_Volume",
        "Win32_ScheduledJob",
        "Win32_NetworkLoginProfile",
        "Win32_LoggedOnUser",
        "Win32_ComputerSystemProduct",
        "Win32_TimeZone",
    ]


def windows_services() -> List[str]:
    """Common Windows services exposed as generated `proc.service-<name>` commands."""
    return [
        "wuauserv", "bits", "cryptsvc", "trustedinstaller", "msiserver", "w32time",
        "dnscache", "dhcp", "nsi", "lmhosts", "netprofm", "nlasvc", "netman",
        "lanmanworkstation", "lanmanserver", "browser", "netlogon", "wkssvc",
        "seclogon", "samss", "lsm", "eventlog", "wecsvc", "wmiapsrv", "winmgmt",
        "schedule", "taskhostw", "spooler", "fax", "termservice", "sessionenv",
        "umrdp", "rdpclip", "themes", "audiosrv", "audioendpointbuilder",
        "dps", "sysmain", "wsearch", "wuauserv", "windefend", "mpssvc", "bfe",
        "sharedaccess", "remoteaccess", "rasman", "vpnagent", "sshd",
    ]
