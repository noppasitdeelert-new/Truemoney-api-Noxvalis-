"""ngm-panel entry point — everything runs locally in this process."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import List, Optional, Tuple

from . import catalog, config, help_system, system
from .console import Console, configure_stdout
from .registry import Registry, RunOptions
from .runner import execute
from .scope_cli import run_scope
from .scope_guard import ScopeGuard
from .shell import Shell
from .updater import run_update

BUILTINS = {
    "run", "help", "list", "exec", "scope", "catalog", "doctor", "update", "version", "mobile",
    "--help", "-h", "help", "--version", "-V", "-v",
}


def build_context(color: Optional[bool] = None) -> Tuple[Registry, ScopeGuard, Console]:
    console = Console(color=color)
    registry = Registry().load()
    guard = ScopeGuard.load()
    return registry, guard, console


def _banner(console: Console, guard: ScopeGuard) -> None:
    console.banner(scope_path=guard.scope_path, subtitle="local-only · พิมพ์ help เพื่อเริ่ม")


def cmd_catalog(console: Console, registry: Registry, argv: List[str]) -> int:
    check_only = "--check" in argv
    console.heading(f"Command catalog · {len(registry)} commands")
    rows = [[category, count, help_system.CATEGORY_LABELS.get(category, "-")]
            for category, count in registry.categories().items()]
    console.table(["Category", "Commands", "Description"], rows)
    families = catalog.spec_summary(registry)
    if families:
        console.heading("Generated families")
        console.table(["Family", "Commands", "Description"], families)
    target = 5000
    for arg_index, token in enumerate(argv):
        if token == "--min" and arg_index + 1 < len(argv) and argv[arg_index + 1].isdigit():
            target = int(argv[arg_index + 1])
    result = registry.check(target)
    console.blank()
    if result["ok"]:
        console.ok(f"registry OK — {result['total']} คำสั่ง (ขั้นต่ำ {target})")
    else:
        console.err(f"registry ไม่ผ่าน ({result['total']} คำสั่ง, ขั้นต่ำ {target})")
        for problem in result["problems"]:
            console.line("  - " + str(problem))
    if check_only:
        return 0 if result["ok"] else 1
    return 0


def cmd_doctor(console: Console, guard: ScopeGuard, registry: Registry) -> int:
    from .console import term_size

    size = term_size()
    console.heading("Doctor · local environment")
    console.keyvalue(
        [
            ("ngm-panel", config.app_header()),
            ("Python", f"{platform.python_version()} ({sys.executable})"),
            ("Platform", f"{platform.platform()} · {system.platform_tag()}"),
            ("Termux", "yes" if system.is_termux() else "no"),
            ("Android", (system.android_release() or "-") if system.is_android() else "-"),
            ("Device", (system.android_model() or "-") if system.is_android() else "-"),
            ("Terminal", f"{size.columns}x{size.lines}" + (" · mobile layout" if size.columns < 64 else "")),
            ("Termux:API", "installed" if system.termux_api_exe("battery-status") else "not installed"),
            ("Config dir", str(config.ensure_home())),
            ("Scope file", str(config.user_scope_path())),
            ("Scope exists", "yes" if config.user_scope_path().exists() else "no"),
            ("Scope targets", len(guard.targets)),
            ("Commands loaded", len(registry)),
            ("Colour", "on" if console.color else "off"),
            ("Interactive tty", "yes" if console.is_tty else "no"),
            ("ngm-panel in PATH", shutil.which("ngm-panel") or "not found"),
        ]
    )
    console.heading("Checks")
    checks = []
    if system.is_termux():
        checks.append(("termux-api helpers", system.termux_api_exe("battery-status") is not None,
                       "pkg install termux-api + แอป Termux:API"))
    checks.append(("registry >= 5000 commands", len(registry) >= 5000, f"{len(registry)}"))
    checks.append(("scope file readable", config.user_scope_path().exists(), str(config.user_scope_path())))
    checks.append(("loopback allowed", any(t.host in {"localhost", "127.0.0.1", "::1"} for t in guard.targets),
                   "add one with: ngm-panel scope add 127.0.0.1"))
    for label, ok, detail in checks:
        (console.ok if ok else console.warn)(f"{label} — {detail}")
    console.blank()
    console.sub("ไม่มีการเชื่อมต่อเซิร์ฟเวอร์กลาง: ทุกคำสั่งทำงานในโปรเซสนี้บนเครื่องคุณ")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    configure_stdout()
    args = list(sys.argv[1:] if argv is None else argv)
    if "--no-color" in args:
        os.environ["NO_COLOR"] = "1"
        args = [arg for arg in args if arg != "--no-color"]

    registry, guard, console = build_context()

    if not args:
        _banner(console, guard)
        return help_system.overview(console, registry)

    head = args[0]
    rest = args[1:]

    if head in {"--version", "-V", "-v", "version"}:
        console.line(config.app_header())
        return 0
    if head in {"--help", "-h"}:
        return help_system.show_help(console, registry, rest)
    if head == "help":
        return help_system.show_help(console, registry, rest)
    if head == "list":
        return help_system.list_names(console, registry, rest[0] if rest else None)
    if head == "run":
        alt_screen = "--no-alt-screen" not in rest
        force_alt_screen = "--alt-screen" in rest
        return Shell(registry, guard, console, alt_screen=alt_screen,
                     force_alt_screen=force_alt_screen).run()
    if head == "exec":
        if not rest:
            console.err("usage: ngm-panel exec <command> [args...]")
            return 2
        return execute(registry, guard, console, rest[0], rest[1:], RunOptions())
    if head == "scope":
        json_out = "--json" in rest
        cleaned = [token for token in rest if token != "--json"]
        return run_scope(console, guard, cleaned, json_out=json_out)
    if head == "catalog":
        return cmd_catalog(console, registry, rest)
    if head == "doctor":
        return cmd_doctor(console, guard, registry)
    if head == "update":
        return run_update(console, rest)

    if head not in BUILTINS:
        return execute(registry, guard, console, head, rest, RunOptions())

    console.err(f"ไม่รู้จักคำสั่ง '{head}'")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
