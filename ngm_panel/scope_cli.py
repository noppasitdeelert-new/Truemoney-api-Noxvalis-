"""`scope` sub-command implementation shared by the CLI and the interactive shell."""

from __future__ import annotations

from typing import List

from .console import Console
from .runner import parse_flags
from .scope_guard import ScopeError, ScopeGuard


def run_scope(console: Console, guard: ScopeGuard, argv: List[str], json_out: bool = False) -> int:
    action = argv[0].lower() if argv else "list"
    if action in {"list", "show", "ls"}:
        summary = guard.summary()
        console.heading("Authorized scope")
        console.keyvalue(
            [
                ("Scope file", summary["scope_file"]),
                ("Targets", len(summary["targets"])),
                ("Limits", f"{summary['limits']['max_rps']} rps · "
                            f"{summary['limits']['max_concurrency']} concurrency · "
                            f"{summary['limits']['request_cap']} requests cap"),
            ]
        )
        console.table(
            ["Host", "Ports", "Note"],
            [[t["host"], ", ".join(map(str, t["ports"])) if t["ports"] else "any", t["note"] or "-"]
             for t in summary["targets"]],
        )
        if json_out:
            console.json_out(summary)
        return 0

    if action == "path":
        console.line(guard.scope_path)
        return 0

    if action in {"add", "allow"}:
        if len(argv) < 2:
            console.err("usage: scope add <host> [--ports 80,443] [--note '...']")
            return 2
        _, flags = parse_flags(argv[2:], {"ports": "str", "note": "str"})
        try:
            target = guard.add_target(argv[1], ports=flags.get("ports"), note=str(flags.get("note") or ""))
        except ScopeError as exc:
            console.err(str(exc))
            return 1
        console.ok(f"เพิ่ม {target.host} เข้า scope แล้ว")
        console.sub(f"ไฟล์: {guard.scope_path}")
        return 0

    if action in {"remove", "rm", "delete"}:
        if len(argv) < 2:
            console.err("usage: scope remove <host>")
            return 2
        if guard.remove_target(argv[1]):
            console.ok(f"ลบ {argv[1]} ออกจาก scope แล้ว")
            return 0
        console.warn(f"ไม่พบ {argv[1]} ใน scope")
        return 1

    if action in {"check", "test"}:
        if len(argv) < 2:
            console.err("usage: scope check <host> [port]")
            return 2
        port = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else None
        try:
            host = guard.authorize(argv[1], port)
        except ScopeError as exc:
            console.err(str(exc))
            return 3
        console.ok(f"{host}" + (f":{port}" if port else "") + " อยู่ใน scope")
        return 0

    console.err("usage: scope <list|add|remove|check|path> …")
    return 2
