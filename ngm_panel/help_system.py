"""Categorised, searchable, paged help."""

from __future__ import annotations

from typing import List, Optional

from .console import Console, term_size, visible_len
from .registry import Command, Registry

DANGER_LABELS = {
    "safe": "local",
    "scope": "scoped network",
    "active": "load test",
}

CATEGORY_LABELS = {
    "net": "เครือข่าย / DNS / พอร์ต",
    "web": "ตรวจเว็บ / headers / TLS / load test",
    "sys": "ข้อมูลระบบ Windows",
    "proc": "โปรเซส / บริการ",
    "file": "ไฟล์และโฟลเดอร์",
    "diag": "วินิจฉัยเครือข่าย",
    "sec": "ความปลอดภัยและ scope",
    "osint": "OSINT: username/email/domain/IP/dork/metadata",
    "mobile": "Termux / Android (มือถือ)",
}

QUICK_START = [
    ("ngm-panel run", "เข้าโหมดหน้าจอเต็ม (alternate screen)"),
    ("ngm-panel help web", "ดูคำสั่งหมวด web"),
    ("ngm-panel scope add example.com --ports 80,443", "เพิ่มเป้าหมายที่ได้รับอนุญาต"),
    ("ngm-panel web.scan https://example.com", "ตรวจ headers/TLS"),
    ("ngm-panel web.test-l7 https://example.com -n 5 -d 10 -r 5", "โหลดเทสต์แบบมีขอบเขต"),
    ("ngm-panel help search <คำ>", "ค้นหาคำสั่ง"),
    ("ngm-panel osint.username <name>", "ลิงก์โปรไฟล์ทุกแพลตฟอร์ม (offline)"),
    ("ngm-panel osint.email you@example.com", "วิเคราะห์อีเมล + breach links"),
    ("ngm-panel help osint", "ดูตระกูล OSINT ทั้งหมด"),
    ("ngm-panel mobile.status", "ตรวจ Termux/Android บนมือถือ"),
]


def _cmd_line(console: Console, command: Command, width: int) -> str:
    usage = command.usage
    desc = command.description
    prefix = "  " + console.cyan(usage)
    available = width - visible_len(prefix) - 4
    if available <= 20 or len(desc) <= available:
        return prefix + "  " + desc
    return prefix + "\n      " + desc


def overview(console: Console, registry: Registry, command_line: str = "ngm-panel") -> int:
    console.heading("Help · ภาพรวม")
    console.line(f"  usage: {command_line} <command> [args]   |   {command_line} run   |   {command_line} help <topic>")
    console.line(f"  คำสั่งทั้งหมด: {len(registry)} รายการ · หมวด: {len(registry.categories())} · "
                 f"generated families: {len(registry.families())}")
    from . import system

    if system.is_termux():
        console.line("  " + console.cyan("Termux mode") + console.dim(
            " · ตารางแบบ stacked · เริ่มที่ mobile.status และ mobile.doctor"))

    console.heading("หมวดคำสั่ง")
    families = registry.families()
    rows = []
    for category, count in registry.categories().items():
        family_count = sum(1 for family in families if family.startswith(category + "."))
        rows.append([category, count, CATEGORY_LABELS.get(category, "-"), family_count or "-"])
    console.table(["Category", "Commands", "Description", "Families"], rows)

    console.heading("เริ่มต้นเร็ว")
    console.table(["คำสั่ง", "ทำอะไร"], [[cmd, desc] for cmd, desc in QUICK_START])

    console.heading("ค้นหา / ดูรายละเอียด")
    console.line("  help <category>          รายการคำสั่งในหมวด")
    console.line("  help <family>            ขยายคำสั่งที่ generate ทั้งหมด")
    console.line("  help <command-name>      วิธีใช้ + ตัวอย่าง")
    console.line("  help search <คำ>          ค้นจากชื่อ/คำอธิบาย")
    console.line()
    console.sub("ทุกคำสั่งที่แตะเครือข่ายต้องอยู่ใน allowed_targets.json (ดู sec.scope)")
    return 0


def category_view(console: Console, registry: Registry, category: str) -> int:
    items = registry.by_category().get(category)
    if items is None:
        return search_view(console, registry, category)
    console.heading(f"Help · {category} — {CATEGORY_LABELS.get(category, '')}")
    hand_written = [command for command in items if not command.family]
    width = min(term_size().columns, 110)
    lines: List[str] = []
    if hand_written:
        lines.append("  " + console.bold("คำสั่งหลัก"))
        for command in hand_written:
            lines.append(_cmd_line(console, command, width))
            lines.append("")
    families = [family for family in registry.families() if family.startswith(category + ".")]
    if families:
        lines.append("  " + console.bold("ชุดคำสั่งที่ generate (ดูทั้งหมดด้วย help <family>)"))
        for family in families:
            members = registry.family_members(family)
            sample = members[0].name
            lines.append(
                f"  {console.cyan(family + '-…'):<34} {len(members):>4} คำสั่ง   "
                + console.dim(f"เช่น {sample}")
            )
    console.paginate(lines)
    return 0


def family_view(console: Console, registry: Registry, family: str) -> int:
    members = registry.family_members(family)
    if not members:
        return search_view(console, registry, family)
    console.heading(f"Help · {family} · {len(members)} คำสั่ง")
    console.sub(f"usage ตัวอย่าง: {members[0].usage}")
    names = [command.name for command in members]
    column_width = max(len(name) for name in names) + 3
    per_row = max(1, (min(term_size().columns, 120) - 2) // column_width)
    lines = []
    for index in range(0, len(names), per_row):
        lines.append("  " + "".join(name.ljust(column_width) for name in names[index : index + per_row]).rstrip())
    lines.append("")
    lines.append(console.dim("   รายละเอียดเต็ม: help <command-name>"))
    console.paginate(lines)
    return 0


def _family_columns(console: Console, registry: Registry, family: str) -> List[str]:
    members = registry.family_members(family)
    if not members:
        return []
    names = [command.name for command in members]
    column_width = max(len(name) for name in names) + 3
    per_row = max(1, (min(term_size().columns, 120) - 2) // column_width)
    lines = []
    for index in range(0, len(names), per_row):
        lines.append("  " + "".join(name.ljust(column_width) for name in names[index : index + per_row]).rstrip())
    return lines


def command_detail(console: Console, command: Command) -> int:
    console.heading(f"Help · {command.name}")
    console.keyvalue(
        [
            ("Category", command.category),
            ("Usage", command.usage),
            ("Description", command.description),
            ("Type", DANGER_LABELS.get(command.danger, command.danger)),
            ("Family", command.family or "-"),
        ]
    )
    if command.examples:
        console.heading("Examples")
        for example in command.examples:
            console.line("  " + example)
    if command.danger == "scope":
        console.heading("Scope")
        console.line("  ต้องมี host/domain อยู่ใน allowed_targets.json ก่อนรัน")
        console.line("  เพิ่ม: ngm-panel scope add <host> [--ports 80,443]")
    if command.danger == "active":
        console.heading("Safety")
        console.line("  ต้องยืนยันขอบเขต (หรือใช้ --yes) และจะถูกจำกัด rate/concurrency/duration ตาม scope")
        console.line("  หยุดทันทีได้ด้วย Ctrl+C")
    return 0


def search_view(console: Console, registry: Registry, query: str, limit: int = 60) -> int:
    matches = registry.search(query, limit=limit)
    if not matches:
        console.warn(f"ไม่พบคำสั่งที่ตรงกับ '{query}'")
        suggestions = registry.suggest(query)
        if suggestions:
            console.line("  อาจหมายถึง: " + ", ".join(suggestions))
        console.sub("ลอง 'help' เพื่อดูหมวดทั้งหมด")
        return 1
    console.heading(f"Help · search '{query}' · {len(matches)} ผลลัพธ์")
    lines = [
        f"  {console.cyan(f'{command.name:<34}')} {command.description}"
        for command in matches
    ]
    if len(matches) >= limit:
        lines.append(console.dim(f"   แสดงสูงสุด {limit} รายการ — ระบุคำค้นให้แคบลง"))
    console.paginate(lines)
    return 0


def show_help(console: Console, registry: Registry, args: List[str], command_line: str = "ngm-panel") -> int:
    if not args:
        return overview(console, registry, command_line)
    if args[0].lower() == "search":
        query = " ".join(args[1:]).strip()
        if not query:
            console.err("usage: help search <คำ>")
            return 2
        return search_view(console, registry, query)

    topic = args[0]
    command = registry.get(topic)
    if command is not None:
        code = command_detail(console, command)
        members = registry.family_members(command.name)
        if members:
            console.heading(f"Family · {command.name} · {len(members)} คำสั่ง")
            console.sub(f"   ตัวอย่าง: {members[0].usage}")
            console.paginate(_family_columns(console, registry, command.name))
        return code
    if topic.lower() in registry.categories():
        return category_view(console, registry, topic.lower())
    if registry.family_members(topic):
        return family_view(console, registry, topic)
    return search_view(console, registry, " ".join(args))


def list_names(console: Console, registry: Registry, category: Optional[str] = None) -> int:
    commands = registry.all()
    if category:
        commands = [command for command in commands if command.category == category]
        if not commands:
            console.err(f"ไม่รู้จักหมวด '{category}' (มี: {', '.join(registry.categories())})")
            return 2
    width = max((len(command.name) for command in commands), default=10) + 3
    per_row = max(1, (min(term_size().columns, 120) - 2) // width)
    lines = []
    for index in range(0, len(commands), per_row):
        chunk = commands[index : index + per_row]
        lines.append("  " + "".join(command.name.ljust(width) for command in chunk).rstrip())
    console.paginate(lines)
    return 0
