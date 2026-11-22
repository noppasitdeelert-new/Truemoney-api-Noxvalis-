"""Terminal rendering: ANSI colour, tables, paging, banner.

Windows 10+ consoles support VT sequences once ENABLE_VIRTUAL_TERMINAL_PROCESSING
is switched on, which :func:`enable_vt` does. When colour is unavailable every
helper silently degrades to plain text.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from typing import Iterable, List, Optional, Sequence

from . import APP_NAME, __version__

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
ITALIC = "\x1b[3m"
UNDERLINE = "\x1b[4m"

RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
WHITE = "\x1b[37m"
GREY = "\x1b[90m"

ALT_SCREEN_ON = "\x1b[?1049h"
ALT_SCREEN_OFF = "\x1b[?1049l"
CURSOR_HIDE = "\x1b[?25l"
CURSOR_SHOW = "\x1b[?25h"

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

BANNER = r"""
  ███╗   ██╗ ██████╗ ███╗   ███╗
  ████╗  ██║██╔════╝ ████╗ ████║
  ██╔██╗ ██║██║  ███╗██╔████╔██║
  ██║╚██╗██║██║   ██║██║╚██╔╝██║
  ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
"""

# Termux on a phone is often 40-52 columns wide: the block banner wraps badly.
BANNER_COMPACT = r"""
  ┌─ N G M ─ P A N E L ─┐
  │  local · no server  │
  └─────────────────────┘
"""

NARROW_COLUMNS = 64


def narrow() -> bool:
    """True for phone-sized terminals (Termux) or very narrow windows."""
    try:
        return term_size().columns < NARROW_COLUMNS
    except Exception:
        return False


def mobile_layout() -> bool:
    from . import system

    return system.is_mobile() or narrow()


def enable_vt() -> None:
    """Enable ANSI escape processing on Windows consoles (best effort)."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def configure_stdout() -> None:
    """Force UTF-8 so Thai/box-drawing characters survive cp874 consoles."""
    enable_vt()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def clear_screen() -> None:
    sys.stdout.write("\x1b[2J\x1b[H")
    sys.stdout.flush()


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def term_size() -> "os.terminal_size":
    return shutil.get_terminal_size(fallback=(100, 30))


class Console:
    """Small output façade shared by every command handler."""

    RED = RED
    GREEN = GREEN
    YELLOW = YELLOW
    CYAN = CYAN
    BOLD = BOLD
    DIM = DIM
    GREY = GREY

    def __init__(self, color: Optional[bool] = None, stream=None) -> None:
        self.stream = stream or sys.stdout
        if color is None:
            color = bool(getattr(self.stream, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR")
        self.color = bool(color)

    # ---------------------------------------------------------------- styling
    @property
    def is_tty(self) -> bool:
        return bool(getattr(self.stream, "isatty", lambda: False)())

    def style(self, text: object, *codes: str) -> str:
        text = str(text)
        if not self.color or not codes:
            return text
        return "".join(codes) + text + RESET

    def bold(self, text: object) -> str:
        return self.style(text, BOLD)

    def dim(self, text: object) -> str:
        return self.style(text, DIM)

    def cyan(self, text: object) -> str:
        return self.style(text, CYAN)

    def green(self, text: object) -> str:
        return self.style(text, GREEN)

    def red(self, text: object) -> str:
        return self.style(text, RED)

    def yellow(self, text: object) -> str:
        return self.style(text, YELLOW)

    # ---------------------------------------------------------------- output
    def write(self, text: str = "") -> None:
        self.stream.write(text)

    def flush(self) -> None:
        try:
            self.stream.flush()
        except Exception:
            pass

    def line(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def blank(self) -> None:
        self.line()

    def heading(self, text: str) -> None:
        self.line()
        self.line(self.style(text, BOLD, CYAN))

    def sub(self, text: str) -> None:
        self.line(self.dim(text))

    def info(self, text: str) -> None:
        self.line(self.style("  i ", CYAN) + " " + text)

    def ok(self, text: str) -> None:
        self.line(self.style(" OK ", GREEN, BOLD) + " " + text)

    def warn(self, text: str) -> None:
        self.line(self.style(" !! ", YELLOW, BOLD) + " " + text)

    def err(self, text: str) -> None:
        self.line(self.style("ERR ", RED, BOLD) + " " + text)

    def hr(self, char: str = "─") -> None:
        self.line(self.dim(char * max(20, min(term_size().columns, 100))))

    # ---------------------------------------------------------------- layout
    def keyvalue(self, pairs: Iterable[Sequence[object]], indent: int = 2) -> None:
        pairs = [(str(k), str(v)) for k, v in pairs]
        if not pairs:
            return
        width = max(visible_len(k) for k, _ in pairs)
        pad = " " * indent
        for key, value in pairs:
            self.line(f"{pad}{self.cyan(key.ljust(width))}  {value}")

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[object]], indent: int = 2) -> None:
        rows = [[str(cell) for cell in row] for row in rows]
        if not rows:
            self.line(self.dim(" " * indent + "(no rows)"))
            return
        if narrow():
            self._table_stacked(headers, rows, indent)
            return
        widths = [visible_len(h) for h in headers]
        for row in rows:
            for index, cell in enumerate(row[: len(widths)]):
                widths[index] = max(widths[index], visible_len(cell))
        pad = " " * indent
        self.line(pad + "  ".join(self.bold(str(h).ljust(widths[i])) for i, h in enumerate(headers)))
        self.line(pad + self.dim("  ".join("─" * w for w in widths)))
        for row in rows:
            cells = []
            for index, width in enumerate(widths):
                cell = row[index] if index < len(row) else ""
                cells.append(cell + " " * max(0, width - visible_len(cell)))
            self.line(pad + "  ".join(cells))

    def _table_stacked(self, headers: Sequence[str], rows: List[List[str]], indent: int = 2) -> None:
        """Phone layout: one labelled card per row instead of a wide table."""
        pad = " " * indent
        header_width = max([visible_len(str(header)) for header in headers] or [0])
        for index, row in enumerate(rows):
            if index:
                self.blank()
            for position, header in enumerate(headers):
                cell = row[position] if position < len(row) else ""
                self.line(f"{pad}{self.cyan(str(header).ljust(header_width))}  {cell}")

    def bar(self, value: float, width: int = 24, char: str = "█") -> str:
        value = max(0.0, min(1.0, value))
        filled = int(round(value * width))
        return char * filled + self.dim("·" * (width - filled))

    def paginate(self, lines: List[str], interactive: Optional[bool] = None) -> None:
        if interactive is None:
            interactive = self.is_tty
        # On a phone the soft keyboard eats the bottom of the screen.
        reserve = 8 if mobile_layout() else 4
        per_page = max(6, term_size().lines - reserve)
        per_page = max(4, min(per_page, 22)) if narrow() else per_page
        if not interactive or len(lines) <= per_page:
            for line in lines:
                self.line(line)
            return
        index = 0
        while index < len(lines):
            for line in lines[index : index + per_page]:
                self.line(line)
            index += per_page
            if index >= len(lines):
                break
            try:
                answer = input(self.dim(f"  ── more ── Enter=next, q=quit ({index}/{len(lines)}) "))
            except (EOFError, KeyboardInterrupt):
                self.blank()
                break
            if answer.strip().lower() in {"q", "quit", "exit"}:
                break

    # ---------------------------------------------------------------- banner
    def banner(self, scope_path: str = "", subtitle: str = "") -> None:
        from . import system

        accent = (CYAN, BOLD) if self.color else ()
        art = BANNER_COMPACT if narrow() else BANNER
        for line in art.strip("\n").splitlines():
            self.line(self.style(line, *accent) if accent else line)
        self.line()
        self.line(
            "  "
            + self.bold(f"{APP_NAME} v{__version__}")
            + self.dim("  ·  100% local · no central server")
        )
        if system.is_termux():
            version = system.android_release()
            self.line(
                "  " + self.dim("Termux · Android" + (" " + version if version else ""))
                + self.dim(" · mobile layout")
            )
        if subtitle:
            self.line("  " + self.dim(subtitle))
        if scope_path:
            self.line("  " + self.dim("scope: ") + self.cyan(scope_path))
        self.line()

    def prompt_label(self) -> str:
        if narrow():
            return self.style("ngm", BOLD, CYAN) + self.style("› ", DIM)
        return self.style("ngm-panel", BOLD, CYAN) + self.style(" › ", DIM)

    def confirm(self, question: str, default: bool = False) -> bool:
        suffix = " [Y/n] " if default else " [y/N] "
        try:
            answer = input(self.style("  ? ", YELLOW) + question + self.dim(suffix))
        except (EOFError, KeyboardInterrupt):
            self.blank()
            return False
        answer = answer.strip().lower()
        if not answer:
            return default
        return answer in {"y", "yes", "ใช่", "ตกลง"}

    def link(self, label: str, url: str) -> None:
        """Print a labelled link; Termux users can long-press to copy/open."""
        self.line("  " + self.cyan(label.ljust(18) if not narrow() else label) + "  " + url)

    def json_out(self, payload: object) -> None:
        import json

        self.line(json.dumps(payload, indent=2, ensure_ascii=False))
