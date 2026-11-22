"""Command model, dispatch helpers and the auto-loading registry."""

from __future__ import annotations

import difflib
import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

Handler = Callable[["object", List[str]], int]


class UsageError(RuntimeError):
    """Raised by handlers when the user typed the command incorrectly."""


@dataclass
class Command:
    name: str
    category: str
    usage: str
    description: str
    handler: Handler
    danger: str = "safe"          # safe | scope | active
    family: Optional[str] = None  # generated families collapse in help
    examples: Tuple[str, ...] = field(default_factory=tuple)

    def summary(self) -> str:
        return f"{self.usage} — {self.description}"


def normalize(name: str) -> str:
    return (name or "").strip().lower().replace("_", "-")


@dataclass
class RunOptions:
    timeout: Optional[float] = None
    json: bool = False
    yes: bool = False
    dry_run: bool = False
    limit: int = 40


class Context:
    """Everything a handler needs: guard, console, parsed global options."""

    def __init__(self, registry: "Registry", guard, console, options: RunOptions) -> None:
        self.registry = registry
        self.guard = guard
        self.console = console
        self.options = options

    # shorthand used by nearly every handler
    @property
    def console_out(self):
        return self.console

    def timeout(self) -> float:
        return self.guard.clamp_timeout(self.options.timeout)

    def need(self, argv: List[str], index: int, usage: str, what: str = "argument") -> str:
        if len(argv) <= index or not str(argv[index]).strip():
            raise UsageError(f"ต้องระบุ {what}\nusage: {usage}")
        return str(argv[index]).strip()

    def print_json(self, payload: object) -> None:
        if self.options.json:
            self.console.json_out(payload)

    # small delegations so handlers can stay terse
    def line(self, text: str = "") -> None:
        self.console.line(text)

    def blank(self) -> None:
        self.console.blank()

    def heading(self, text: str) -> None:
        self.console.heading(text)

    def call(self, name: str, args: Optional[List[str]] = None) -> int:
        command = self.registry.get(name)
        if command is None:
            raise UsageError(f"unknown sub-command: {name}")
        return int(command.handler(self, list(args or [])) or 0)


class Registry:
    def __init__(self) -> None:
        self._commands: Dict[str, Command] = {}

    # ------------------------------------------------------------- mutation
    def register(self, command: Command) -> None:
        key = normalize(command.name)
        if not key:
            raise ValueError("command name must not be empty")
        if key in self._commands:
            raise ValueError(f"duplicate command: {command.name}")
        self._commands[key] = command

    def add(self, handler: Handler, **kwargs) -> Command:
        command = Command(handler=handler, **kwargs)
        self.register(command)
        return command

    # ---------------------------------------------------------------- lookup
    def get(self, name: str) -> Optional[Command]:
        return self._commands.get(normalize(name))

    def require(self, name: str) -> Command:
        command = self.get(name)
        if command is None:
            raise UsageError(f"ไม่รู้จักคำสั่ง: {name}")
        return command

    def all(self) -> List[Command]:
        return sorted(self._commands.values(), key=lambda command: (command.category, command.name))

    def __len__(self) -> int:
        return len(self._commands)

    def __iter__(self) -> Iterable[Command]:
        return iter(self.all())

    # ------------------------------------------------------------ aggregates
    def by_category(self) -> Dict[str, List[Command]]:
        grouped: Dict[str, List[Command]] = {}
        for command in self.all():
            grouped.setdefault(command.category, []).append(command)
        return grouped

    def categories(self) -> Dict[str, int]:
        return {category: len(items) for category, items in sorted(self.by_category().items())}

    def families(self) -> Dict[str, List[Command]]:
        grouped: Dict[str, List[Command]] = {}
        for command in self.all():
            if command.family:
                grouped.setdefault(command.family, []).append(command)
        return {key: sorted(items, key=lambda c: c.name) for key, items in sorted(grouped.items())}

    def family_members(self, family: str) -> List[Command]:
        key = normalize(family)
        for name, items in self.families().items():
            if normalize(name) == key:
                return items
        return []

    def search(self, query: str, limit: int = 60) -> List[Command]:
        needle = normalize(query)
        scored: List[Tuple[int, Command]] = []
        for command in self._commands.values():
            name = normalize(command.name)
            haystack = f"{name} {command.description} {command.usage}".lower()
            if needle in haystack:
                score = 0 if name.startswith(needle) else 1 if needle in name else 2
                scored.append((score, command))
        scored.sort(key=lambda pair: (pair[0], pair[1].category, pair[1].name))
        return [command for _, command in scored[:limit]]

    def suggest(self, name: str, limit: int = 5) -> List[str]:
        return difflib.get_close_matches(normalize(name), list(self._commands), n=limit, cutoff=0.55)

    # ---------------------------------------------------------------- loading
    def load(self) -> "Registry":
        from . import catalog, commands as commands_package

        for module_info in pkgutil.iter_modules(commands_package.__path__):
            module = importlib.import_module(f"{commands_package.__name__}.{module_info.name}")
            register = getattr(module, "register", None)
            if callable(register):
                register(self)
        catalog.register(self)
        return self

    def check(self, minimum: int = 1000) -> Dict[str, object]:
        """Self-validation used by `ngm-panel catalog --check` and the test suite."""
        problems: List[str] = []
        seen = set()
        for command in self._commands.values():
            key = normalize(command.name)
            if key in seen:
                problems.append(f"duplicate name: {command.name}")
            seen.add(key)
            if not command.category:
                problems.append(f"missing category: {command.name}")
            if not command.usage:
                problems.append(f"missing usage: {command.name}")
            if not command.description:
                problems.append(f"missing description: {command.name}")
            if not callable(command.handler):
                problems.append(f"handler not callable: {command.name}")
        return {
            "total": len(self._commands),
            "minimum": minimum,
            "ok": not problems and len(self._commands) >= minimum,
            "problems": problems[:25],
        }
