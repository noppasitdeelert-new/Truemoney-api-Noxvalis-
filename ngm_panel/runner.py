"""Argument parsing and command execution shared by the CLI and the shell."""

from __future__ import annotations

from typing import Dict, List, Tuple

from .console import Console
from .registry import Context, Registry, RunOptions, UsageError
from .scope_guard import ScopeError

GLOBAL_FLAGS: Dict[str, str] = {
    "timeout": "float",
    "json": "bool",
    "yes": "bool",
    "dry-run": "bool",
    "limit": "int",
}

FLAG_ALIASES = {
    "t": "timeout",
    "y": "yes",
    "no-color": "no-color",
}


class UnknownCommand(UsageError):
    pass


def parse_options(argv: List[str]) -> Tuple[List[str], RunOptions]:
    """Strip known global flags out of argv; everything else stays for the handler."""
    options = RunOptions()
    positionals: List[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token.startswith("-") and token not in {"-", "--"} and not _looks_like_negative(token):
            raw = token.lstrip("-")
            name, _, inline = raw.partition("=")
            name = FLAG_ALIASES.get(name, name)
            if name in GLOBAL_FLAGS:
                kind = GLOBAL_FLAGS[name]
                if kind == "bool":
                    value = True
                    index += 1
                else:
                    if inline:
                        value = inline
                        index += 1
                    elif index + 1 < len(argv):
                        value = argv[index + 1]
                        index += 2
                    else:
                        raise UsageError(f"flag --{name} ต้องการค่า")
                    try:
                        value = int(value) if kind == "int" else float(value)
                    except (TypeError, ValueError):
                        raise UsageError(f"flag --{name} ต้องการค่าแบบ {kind}")
                if name == "timeout":
                    options.timeout = float(value)  # type: ignore[arg-type]
                elif name == "json":
                    options.json = bool(value)
                elif name == "yes":
                    options.yes = bool(value)
                elif name == "dry-run":
                    options.dry_run = bool(value)
                elif name == "limit":
                    options.limit = int(value)  # type: ignore[arg-type]
                continue
        positionals.append(token)
        index += 1
    return positionals, options


def _looks_like_negative(token: str) -> bool:
    return len(token) > 1 and token[1].isdigit()


def parse_flags(argv: List[str], spec: Dict[str, str]) -> Tuple[List[str], Dict[str, object]]:
    """Parse command-local flags.

    ``spec`` maps a flag name (no dashes) to 'int' | 'float' | 'str' | 'bool'.
    Both ``-x`` and ``--x`` are accepted; boolean flags need no value.
    """
    positionals: List[str] = []
    values: Dict[str, object] = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        if token.startswith("-") and token not in {"-", "--"} and not _looks_like_negative(token):
            raw = token.lstrip("-")
            name, sep, inline = raw.partition("=")
            if name in spec:
                kind = spec[name]
                if kind == "bool":
                    values[name] = True
                    index += 1
                    continue
                if sep:
                    index += 1
                elif index + 1 < len(argv):
                    inline = argv[index + 1]
                    index += 2
                else:
                    raise UsageError(f"flag --{name} ต้องการค่า")
                try:
                    values[name] = int(inline) if kind == "int" else float(inline) if kind == "float" else inline
                except ValueError:
                    raise UsageError(f"flag --{name} ต้องการค่าแบบ {kind}")
                continue
        positionals.append(token)
        index += 1
    return positionals, values


def execute(
    registry: Registry,
    guard,
    console: Console,
    name: str,
    argv: List[str],
    options: RunOptions,
) -> int:
    command = registry.get(name)
    if command is None:
        suggestions = registry.suggest(name)
        hint = f"\nคำแนะนำ: {', '.join(suggestions)}" if suggestions else ""
        console.err(f"ไม่รู้จักคำสั่ง '{name}'{hint}\nลอง 'help' เพื่อดูรายการคำสั่งทั้งหมด")
        return 2
    remaining, local_flags = parse_options(argv)
    options.timeout = local_flags.timeout or options.timeout
    options.json = options.json or local_flags.json
    options.yes = options.yes or local_flags.yes
    options.dry_run = options.dry_run or local_flags.dry_run
    options.limit = local_flags.limit or options.limit
    guard.auto_approve = guard.auto_approve or options.yes

    context = Context(registry, guard, console, options)
    try:
        return int(command.handler(context, remaining) or 0)
    except UsageError as exc:
        console.err(str(exc))
        if command.usage:
            console.sub(f"usage: {command.usage}")
        return 2
    except ScopeError as exc:
        console.err("Authorization guard: " + str(exc))
        return 3
    except KeyboardInterrupt:
        console.blank()
        console.warn("ยกเลิกคำสั่งด้วย Ctrl+C")
        return 130
