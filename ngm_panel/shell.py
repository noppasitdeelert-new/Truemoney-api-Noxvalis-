"""Interactive full-screen panel (`ngm-panel run`)."""

from __future__ import annotations

import os
import shlex
import sys
import time
from typing import List

from . import config, help_system
from .console import ALT_SCREEN_OFF, ALT_SCREEN_ON, CURSOR_SHOW, Console, clear_screen
from .registry import Registry, RunOptions
from .runner import execute
from .scope_cli import run_scope


def split_args(line: str) -> List[str]:
    try:
        if os.name == "nt":
            return [token.strip('"') for token in shlex.split(line, posix=False)]
        return shlex.split(line)
    except ValueError:
        return line.split()


class Shell:
    """Alternate-screen REPL: banner, prompt, local command execution."""

    def __init__(self, registry: Registry, guard, console: Console, alt_screen: bool = True,
                 force_alt_screen: bool = False) -> None:
        from . import system

        self.registry = registry
        self.guard = guard
        self.console = console
        # Termux keeps a stale alt-screen buffer (screen appears frozen after a
        # command), so phone users get the inline screen unless they ask for it.
        self.alt_screen = (
            alt_screen and console.is_tty and (force_alt_screen or not system.is_termux())
        )
        self._readline = None

    # ------------------------------------------------------------- lifecycle
    def run(self) -> int:
        self._setup_history()
        if self.alt_screen:
            sys.stdout.write(ALT_SCREEN_ON)
            sys.stdout.flush()
        try:
            self._welcome()
            while True:
                try:
                    raw = input(self.console.prompt_label())
                except KeyboardInterrupt:
                    self.console.line()
                    continue
                except EOFError:
                    self.console.line()
                    break
                if not raw.strip():
                    continue
                self._remember(raw)
                if self._dispatch(raw):
                    break
        finally:
            if self.alt_screen:
                sys.stdout.write(CURSOR_SHOW + ALT_SCREEN_OFF)
                sys.stdout.flush()
            else:
                self.console.blank()
            self._save_history()
        return 0

    def _welcome(self) -> None:
        from . import system

        clear_screen()
        self.console.banner(scope_path=self.guard.scope_path)
        back_to = "Termux shell" if system.is_termux() else "Windows shell"
        self.console.line(
            "  "
            + self.console.dim(f"{len(self.registry)} commands · {len(self.registry.families())} families · ")
            + self.console.cyan("help")
            + self.console.dim(" · ")
            + self.console.cyan("exit")
            + self.console.dim(f" → {back_to}")
        )
        if system.is_termux():
            self.console.line(
                "  " + self.console.dim("มือถือ: mobile.status · osint.username <name> · help osint")
            )
        self.console.hr()
        self.console.blank()
        self.console.flush()

    # -------------------------------------------------------------- dispatch
    def _dispatch(self, raw: str) -> bool:
        tokens = split_args(raw.strip())
        if not tokens:
            return False
        name = tokens[0].lower()
        rest = tokens[1:]

        if name in {"exit", "quit", ":q", "logout"}:
            self.console.ok("ออกจาก ngm-panel — กลับสู่ shell ปกติ")
            return True
        if name in {"clear", "cls"}:
            clear_screen()
            self.console.banner(scope_path=self.guard.scope_path)
            return False
        if name in {"help", "?", "man"}:
            help_system.show_help(self.console, self.registry, rest, command_line="ngm-panel")
            return False
        if name == "list":
            help_system.list_names(self.console, self.registry, rest[0] if rest else None)
            return False
        if name == "scope":
            run_scope(self.console, self.guard, rest)
            return False
        if name in {"version", "--version", "-v"}:
            self.console.line(config.app_header())
            return False
        if name == "banner":
            self.console.banner(scope_path=self.guard.scope_path)
            return False
        if name == "catalog":
            self._catalog(rest)
            return False
        if name == "update":
            from .updater import run_update

            code = run_update(self.console, rest)
            if code == 0 and "--run" in rest:
                clear_screen()
                self.console.banner(scope_path=self.guard.scope_path)
                self.console.warn(
                    "อัปเดตแล้ว — พิมพ์ exit แล้วเปิด ngm-panel ใหม่ หน้าจอจึงจะแสดงเวอร์ชันใหม่"
                )
            return False

        self.guard.auto_approve = False
        started = time.perf_counter()
        try:
            execute(self.registry, self.guard, self.console, tokens[0], rest, RunOptions())
        except SystemExit as exc:
            self.console.warn(f"ยกเลิก: {exc}")
        except Exception as exc:  # a broken handler must not kill the panel
            self.console.err(f"{type(exc).__name__}: {exc}")
        elapsed = (time.perf_counter() - started) * 1000
        if elapsed > 250:
            self.console.sub(f"  ⏱  {elapsed:.0f} ms")
        self.console.flush()
        return False

    def _catalog(self, argv: List[str]) -> None:
        from . import catalog

        self.console.heading(f"Catalog · {len(self.registry)} commands")
        self.console.table(
            ["Family", "Commands", "Description"],
            catalog.spec_summary(self.registry),
        )
        check = self.registry.check(1000)
        if check["ok"]:
            self.console.ok(f"registry ผ่านการตรวจ ({check['total']} คำสั่ง)")
        else:
            self.console.err(f"registry มีปัญหา: {check['problems']}")

    # --------------------------------------------------------------- history
    def _setup_history(self) -> None:
        try:
            import readline  # noqa: F401  (pyreadline3 provides this on older Windows)

            self._readline = readline
        except ImportError:
            self._readline = None
        if self._readline is None:
            return
        path = config.history_path()
        try:
            if path.exists():
                self._readline.read_history_file(str(path))
        except OSError:
            pass
        try:
            config.ensure_home()
            self._readline.set_history_length(500)
        except OSError:
            pass

    def _remember(self, line: str) -> None:
        if self._readline is None:
            return
        stripped = line.strip()
        if not stripped:
            return
        if self._readline.get_current_history_length() == 0 or self._readline.get_history_item(
            self._readline.get_current_history_length()
        ) != stripped:
            self._readline.add_history(stripped)

    def _save_history(self) -> None:
        if self._readline is None:
            return
        try:
            self._readline.write_history_file(str(config.history_path()))
        except OSError:
            pass
