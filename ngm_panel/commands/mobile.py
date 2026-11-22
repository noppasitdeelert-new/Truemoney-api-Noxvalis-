"""Termux / Android commands — same panel, phone-sized.

Everything here runs locally inside Termux. Commands that need the phone
hardware call the Termux:API helpers (``termux-battery-status`` and friends);
when those helpers are not installed the command explains exactly what to
install instead of failing with a traceback.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import List

from .. import config, system
from ..registry import Registry
from ..runner import parse_flags
from .common import human_bytes


def _require_termux(ctx) -> bool:
    if system.is_termux():
        return True
    ctx.console.warn("คำสั่งนี้ใช้บน Termux (Android) เท่านั้น")
    ctx.console.sub("ติดตั้ง Termux จาก F-Droid แล้วรัน: pkg install python")
    return False


def _json_or_text(text: str) -> object:
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(stripped)
        except ValueError:
            return stripped
    return stripped


def _api(ctx, name: str, args: List[str] = (), timeout: float = 25.0, title: str = "") -> int:
    """Run one Termux:API helper and print its JSON output."""
    if not _require_termux(ctx):
        return 1
    executable = system.termux_api_exe(name)
    if executable is None:
        ctx.console.err(system.termux_api_missing_hint(name))
        return 1
    ctx.console.heading(title or f"Termux:API · {name}")
    output = system.termux_run(name, args, timeout=timeout)
    if not output.strip():
        ctx.console.warn("ไม่มีข้อมูลตอบกลับ (อาจยังไม่ได้อนุญาตสิทธิ์)")
        return 1
    payload = _json_or_text(output)
    if isinstance(payload, (dict, list)):
        if isinstance(payload, dict):
            ctx.console.keyvalue([(key, _short(value)) for key, value in payload.items()])
        else:
            for item in payload[:40]:
                ctx.console.line("  " + _short(item))
        ctx.print_json(payload)
    else:
        for line in str(payload).splitlines()[:60]:
            ctx.console.line("  " + line)
    return 0


def _short(value: object) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 160 else text[:157] + "..."


def cmd_status(ctx, argv: List[str]) -> int:
    from ..console import term_size

    ctx.console.heading("Mobile / Termux status")
    size = term_size()
    api = [name for name in sorted(system.TERMUX_API_COMMANDS) if system.termux_api_exe(name)]
    packages = system.termux_packages()
    storage = os.path.expanduser("~/storage")
    ctx.console.keyvalue(
        [
            ("Platform", system.platform_tag()),
            ("Termux", "yes" if system.is_termux() else "no"),
            ("Android", system.android_release() or "-"),
            ("Device", system.android_model() or "-"),
            ("TERMUX_VERSION", os.environ.get("TERMUX_VERSION", "-")),
            ("PREFIX", os.environ.get("PREFIX", "-")),
            ("Python", system.python_version()),
            ("Packages", str(len(packages)) if packages else "n/a"),
            ("Termux:API", f"{len(api)} helpers" if api else "not installed"),
            ("Storage", "shared storage linked" if os.path.isdir(storage) else "run mobile.setup-storage"),
            ("Config dir", str(config.ensure_home())),
            ("Terminal", f"{size.columns}x{size.lines}"),
            ("Layout", "mobile (stacked tables)" if size.columns < 64 or system.is_mobile() else "desktop"),
        ]
    )
    ctx.print_json(
        {
            "platform": system.platform_tag(),
            "termux": system.is_termux(),
            "android": system.android_release(),
            "device": system.android_model(),
            "python": system.python_version(),
            "packages": len(packages),
            "termux_api": api,
            "storage_linked": os.path.isdir(storage),
            "terminal": {"columns": size.columns, "lines": size.lines},
        }
    )
    return 0


def cmd_doctor(ctx, argv: List[str]) -> int:
    if not _require_termux(ctx):
        return 1
    ctx.console.heading("Termux doctor")
    checks = []
    checks.append(("python3", system.have("python") or system.have("python3"),
                   "pkg install python"))
    checks.append(("pip", system.have("pip"), "pkg install python-pip (หรือ python -m ensurepip)"))
    checks.append(("git", system.have("git"), "pkg install git"))
    api_count = len([name for name in system.TERMUX_API_COMMANDS if system.termux_api_exe(name)])
    checks.append(("termux-api", api_count > 0, "pkg install termux-api + แอป Termux:API"))
    checks.append(("shared storage", os.path.isdir(os.path.expanduser("~/storage")), "mobile.setup-storage"))
    checks.append(("ngm-panel entry", shutil.which("ngm-panel") is not None,
                   "pip install -e . หรือใช้ packaging/termux/ngm-panel"))
    checks.append(("UTF-8 locale", True, os.environ.get("LANG", "ไม่ตั้ง LANG (ยังใช้ UTF-8 ได้)")))
    for label, ok, hint in checks:
        if ok:
            ctx.console.ok(f"{label} — พร้อมใช้งาน")
        else:
            ctx.console.warn(f"{label} — ต้องติดตั้ง: {hint}")
    failed = [label for label, ok, _ in checks if not ok]
    ctx.console.blank()
    if failed:
        ctx.console.sub("ขาด: " + ", ".join(failed))
        return 1
    ctx.console.ok("ทุกอย่างพร้อมสำหรับ ngm-panel บน Termux")
    return 0


def cmd_pkg(ctx, argv: List[str]) -> int:
    if not _require_termux(ctx):
        return 1
    needle = (argv[0] if argv else "").lower()
    ctx.console.heading("Installed Termux packages" + (f" · {needle}" if needle else ""))
    packages = [name for name in system.termux_packages() if not needle or needle in name.lower()]
    if not packages:
        ctx.console.warn("อ่านรายการแพ็กเกจไม่ได้ (dpkg ไม่พร้อมใช้งาน)")
        return 1
    for index in range(0, len(packages), 3):
        ctx.console.line("  " + "".join(name.ljust(28) for name in packages[index : index + 3]).rstrip())
    ctx.console.blank()
    ctx.console.sub(f"{len(packages)} packages · ติดตั้งเพิ่ม: pkg install <name>")
    ctx.print_json({"packages": packages})
    return 0


def cmd_pkg_search(ctx, argv: List[str]) -> int:
    term = ctx.need(argv, 0, "mobile.pkg-search <คำค้น>", "คำค้น")
    if not _require_termux(ctx):
        return 1
    ctx.console.heading(f"pkg search · {term}")
    output = system.run_text(["pkg", "search", term], timeout=60)
    if not output.strip():
        ctx.console.warn("ไม่พบผลลัพธ์")
        return 1
    for line in output.splitlines()[:80]:
        ctx.console.line("  " + line[:120])
    return 0


def cmd_pkg_install(ctx, argv: List[str]) -> int:
    if not _require_termux(ctx):
        return 1
    packages = [token for token in argv if not token.startswith("-")]
    if not packages:
        ctx.console.err("usage: mobile.pkg-install <package...> [--yes]")
        return 2
    if not ctx.options.yes and not ctx.console.confirm(
        "ติดตั้งแพ็กเกจด้วย pkg install: " + ", ".join(packages) + "?", default=False
    ):
        ctx.console.warn("ยกเลิก")
        return 0
    if ctx.options.dry_run:
        ctx.console.info(f"--dry-run: pkg install -y {' '.join(packages)}")
        return 0
    ctx.console.heading("pkg install")
    for line in system.run_text(["pkg", "install", "-y", *packages], timeout=240).splitlines():
        ctx.console.line("  " + line[:120])
    return 0


def cmd_storage(ctx, argv: List[str]) -> int:
    ctx.console.heading("Termux storage")
    rows = []
    for name in ("home", "shared", "downloads", "dcim", "pictures", "movies", "music", "documents"):
        path = os.path.expanduser("~/storage/" + name)
        if os.path.exists(path):
            target = os.path.realpath(path)
            rows.append([name, path, target])
    if not rows:
        ctx.console.warn("ยังไม่ได้เชื่อม shared storage")
        ctx.console.sub("รัน: mobile.setup-storage  (หรือ termux-setup-storage)")
        return 1
    ctx.console.table(["Link", "Path", "Target"], rows)
    try:
        usage = shutil.disk_usage(os.path.expanduser("~"))
        ctx.console.line(
            "  " + ctx.console.bar(usage.used / usage.total if usage.total else 0, width=16)
            + f"  {human_bytes(usage.used)} / {human_bytes(usage.total)}"
        )
    except OSError:
        pass
    return 0


def cmd_setup_storage(ctx, argv: List[str]) -> int:
    if not _require_termux(ctx):
        return 1
    if not ctx.options.yes and not ctx.console.confirm(
        "เรียก termux-setup-storage เพื่อขอสิทธิ์เข้าถึงไฟล์?", default=False
    ):
        ctx.console.warn("ยกเลิก")
        return 0
    if ctx.options.dry_run:
        ctx.console.info("--dry-run: termux-setup-storage")
        return 0
    ctx.console.heading("termux-setup-storage")
    output = system.run_text(["termux-setup-storage"], timeout=120)
    ctx.console.line("  " + (output.strip() or "ส่งคำขอสิทธิ์แล้ว — ยืนยันในหน้าต่าง Android"))
    return 0


def cmd_iface(ctx, argv: List[str]) -> int:
    ctx.console.heading("Android network interfaces")
    if system.have("ip"):
        ctx.console.line(system.run_text(["ip", "-brief", "address"]))
    elif system.have("ifconfig"):
        ctx.console.line(system.run_text(["ifconfig"]))
    else:
        ctx.console.warn("ไม่พบ ip/ifconfig")
        return 1
    if system.termux_api_exe("wifi-connectioninfo"):
        ctx.console.heading("Wi-Fi")
        output = system.termux_run("wifi-connectioninfo")
        payload = _json_or_text(output)
        if isinstance(payload, dict):
            keys = ("ssid", "bssid", "ip", "mac_address", "link_speed_mbps", "frequency_mhz", "supplicant_state")
            ctx.console.keyvalue([(key, _short(payload.get(key, "-"))) for key in keys if key in payload])
            ctx.print_json(payload)
    return 0


def cmd_clipboard(ctx, argv: List[str]) -> int:
    if not _require_termux(ctx):
        return 1
    action = (argv[0] if argv else "get").lower()
    if action == "set":
        text = " ".join(argv[1:]).strip()
        if not text:
            ctx.console.err("usage: mobile.clipboard set <text>")
            return 2
        return _api(ctx, "clipboard-set", [text], title="Clipboard · set")
    return _api(ctx, "clipboard-get", title="Clipboard · get")


def cmd_notify(ctx, argv: List[str]) -> int:
    title = ctx.need(argv, 0, "mobile.notify <title> [body]", "หัวข้อ")
    body = " ".join(argv[1:])
    args = ["--title", title]
    if body:
        args += ["--content", body]
    return _api(ctx, "notification", args, title="Notification")


def cmd_toast(ctx, argv: List[str]) -> int:
    text = " ".join(argv).strip()
    if not text:
        ctx.console.err("usage: mobile.toast <text>")
        return 2
    return _api(ctx, "toast", [text], timeout=10, title="Toast")


def cmd_vibrate(ctx, argv: List[str]) -> int:
    duration = argv[0] if argv and argv[0].isdigit() else "300"
    return _api(ctx, "vibrate", ["-d", duration], timeout=10, title="Vibrate")


def cmd_torch(ctx, argv: List[str]) -> int:
    state = (argv[0] if argv else "on").lower()
    if state not in {"on", "off"}:
        ctx.console.err("usage: mobile.torch <on|off>")
        return 2
    return _api(ctx, "torch", ["-c" if state == "on" else "-o"], timeout=10, title=f"Torch · {state}")


def cmd_sensor(ctx, argv: List[str]) -> int:
    sensor = argv[0] if argv else ""
    args: List[str] = []
    if sensor:
        args = ["-s", sensor, "-l", "1"]
    return _api(ctx, "sensor", args, timeout=20, title="Sensors" + (f" · {sensor}" if sensor else ""))


def cmd_location(ctx, argv: List[str]) -> int:
    provider = (argv[0] if argv else "network").lower()
    if provider not in {"gps", "network", "passive"}:
        ctx.console.err("usage: mobile.location [gps|network|passive]")
        return 2
    return _api(ctx, "location", ["-p", provider, "-l", "1"], timeout=45, title=f"Location · {provider}")


def cmd_sms(ctx, argv: List[str]) -> int:
    _, flags = parse_flags(argv, {"limit": "int"})
    limit = int(flags.get("limit", 10))
    return _api(ctx, "sms-list", ["-l", str(limit)], timeout=30, title=f"SMS · last {limit}")


def cmd_contacts(ctx, argv: List[str]) -> int:
    return _api(ctx, "contact-list", timeout=30, title="Contacts")


def cmd_telephony(ctx, argv: List[str]) -> int:
    if not _require_termux(ctx):
        return 1
    ctx.console.heading("Telephony")
    for name in ("telephony-deviceinfo", "telephony-cellinfo"):
        if system.termux_api_exe(name) is None:
            ctx.console.warn(system.termux_api_missing_hint(name))
            continue
        payload = _json_or_text(system.termux_run(name))
        ctx.console.line("  " + ctx.console.bold(name))
        if isinstance(payload, dict):
            ctx.console.keyvalue([(key, _short(value)) for key, value in payload.items()], indent=4)
        else:
            ctx.console.line("    " + _short(payload))
    return 0


def cmd_share(ctx, argv: List[str]) -> int:
    path = ctx.need(argv, 0, "mobile.share <file>", "ไฟล์")
    if not os.path.exists(os.path.expanduser(path)):
        ctx.console.err(f"ไม่พบไฟล์: {path}")
        return 1
    return _api(ctx, "share", [os.path.expanduser(path)], timeout=20, title="Share file")


def cmd_wakelock(ctx, argv: List[str]) -> int:
    if not _require_termux(ctx):
        return 1
    action = (argv[0] if argv else "status").lower()
    ctx.console.heading("Wake lock")
    if action == "on":
        ctx.console.line("  " + (system.run_text(["termux-wake-lock"]) or "acquired"))
    elif action == "off":
        ctx.console.line("  " + (system.run_text(["termux-wake-unlock"]) or "released"))
    else:
        payload = _json_or_text(system.termux_run("notification-list"))
        if isinstance(payload, list):
            held = [item for item in payload if isinstance(item, dict) and "wake" in str(item.get("title", "")).lower()]
            ctx.console.line(f"  wake lock notifications: {len(held)}")
        else:
            ctx.console.sub("ใช้ mobile.wakelock on / off")
    return 0


def cmd_tts(ctx, argv: List[str]) -> int:
    text = " ".join(argv).strip()
    if not text:
        ctx.console.err("usage: mobile.tts <text>")
        return 2
    return _api(ctx, "tts-speak", [text], timeout=30, title="Text to speech")


def cmd_api(ctx, argv: List[str]) -> int:
    name = ctx.need(argv, 0, "mobile.api <helper-name> [args...]", "ชื่อ helper")
    name = name.replace("termux-", "")
    if name not in system.TERMUX_API_COMMANDS:
        ctx.console.err(f"ไม่รู้จัก helper '{name}'")
        ctx.console.sub("รายการที่รองรับ: " + ", ".join(sorted(system.TERMUX_API_COMMANDS)))
        return 2
    return _api(ctx, name, argv[1:])


def make_api_command(name: str):
    def handler(ctx, argv: List[str]) -> int:
        return _api(ctx, name, argv)

    return handler


def register(registry: Registry) -> None:
    registry.add(cmd_status, name="mobile.status", category="mobile", usage="mobile.status",
                 description="สถานะ Termux/Android, ขนาดหน้าจอ, termux-api และ shared storage")
    registry.add(cmd_doctor, name="mobile.doctor", category="mobile", usage="mobile.doctor",
                 description="ตรวจความพร้อมของ Termux (python, pip, git, termux-api, storage)")
    registry.add(cmd_pkg, name="mobile.pkg", category="mobile", usage="mobile.pkg [filter]",
                 description="รายการแพ็กเกจ Termux ที่ติดตั้งแล้ว (dpkg)")
    registry.add(cmd_pkg_search, name="mobile.pkg-search", category="mobile", usage="mobile.pkg-search <term>",
                 description="ค้นแพ็กเกจใน repo ของ Termux ด้วย pkg search")
    registry.add(cmd_pkg_install, name="mobile.pkg-install", category="mobile",
                 usage="mobile.pkg-install <package...> [--yes]",
                 description="ติดตั้งแพ็กเกจ Termux (มีคำยืนยัน)")
    registry.add(cmd_storage, name="mobile.storage", category="mobile", usage="mobile.storage",
                 description="ตรวจ ~/storage และพื้นที่ว่างบนอุปกรณ์")
    registry.add(cmd_setup_storage, name="mobile.setup-storage", category="mobile", usage="mobile.setup-storage",
                 description="เรียก termux-setup-storage เพื่อขอสิทธิ์เข้าถึงไฟล์")
    registry.add(cmd_iface, name="mobile.iface", category="mobile", usage="mobile.iface",
                 description="network interface + ข้อมูล Wi-Fi บน Android")
    registry.add(cmd_clipboard, name="mobile.clipboard", category="mobile", usage="mobile.clipboard [get|set <text>]",
                 description="อ่าน/เขียนคลิปบอร์ดผ่าน Termux:API")
    registry.add(cmd_notify, name="mobile.notify", category="mobile", usage="mobile.notify <title> [body]",
                 description="ส่ง notification ของ Android")
    registry.add(cmd_toast, name="mobile.toast", category="mobile", usage="mobile.toast <text>",
                 description="แสดง toast บนหน้าจอ Android")
    registry.add(cmd_vibrate, name="mobile.vibrate", category="mobile", usage="mobile.vibrate [ms]",
                 description="สั่นเครื่องตามระยะเวลาที่กำหนด")
    registry.add(cmd_torch, name="mobile.torch", category="mobile", usage="mobile.torch <on|off>",
                 description="เปิด/ปิดไฟฉาย")
    registry.add(cmd_sensor, name="mobile.sensor", category="mobile", usage="mobile.sensor [sensor]",
                 description="อ่านค่าเซนเซอร์ของอุปกรณ์หนึ่งครั้ง")
    registry.add(cmd_location, name="mobile.location", category="mobile", usage="mobile.location [gps|network|passive]",
                 description="อ่านตำแหน่งปัจจุบัน (ต้องอนุญาตสิทธิ์)")
    registry.add(cmd_sms, name="mobile.sms", category="mobile", usage="mobile.sms [--limit N]",
                 description="อ่าน SMS ล่าสุด (ต้องอนุญาตสิทธิ์)")
    registry.add(cmd_contacts, name="mobile.contacts", category="mobile", usage="mobile.contacts",
                 description="อ่านรายชื่อผู้ติดต่อ (ต้องอนุญาตสิทธิ์)")
    registry.add(cmd_telephony, name="mobile.telephony", category="mobile", usage="mobile.telephony",
                 description="ข้อมูลอุปกรณ์โทรศัพท์และเซลล์")
    registry.add(cmd_share, name="mobile.share", category="mobile", usage="mobile.share <file>",
                 description="แชร์ไฟล์ออกจาก Termux ผ่าน Android share sheet")
    registry.add(cmd_wakelock, name="mobile.wakelock", category="mobile", usage="mobile.wakelock [on|off|status]",
                 description="ควบคุม wake lock ไม่ให้ Android ฆ่าโปรเซส")
    registry.add(cmd_tts, name="mobile.tts", category="mobile", usage="mobile.tts <text>",
                 description="อ่านข้อความออกเสียงผ่าน Termux:API")
    registry.add(cmd_api, name="mobile.api", category="mobile", usage="mobile.api <helper-name> [args...]",
                 description="เรียก Termux:API helper ใดก็ได้ใน allowlist")

    for name in sorted(system.TERMUX_API_COMMANDS):
        registry.add(
            make_api_command(name),
            name=f"mobile.api-{name}",
            category="mobile",
            usage=f"mobile.api-{name} [args...]",
            description=system.TERMUX_API_COMMANDS[name] + f" (termux-{name})",
            family="mobile.api",
        )
