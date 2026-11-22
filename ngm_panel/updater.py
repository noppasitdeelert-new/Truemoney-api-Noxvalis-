"""Self-update planning: winget on Windows, pkg/git/pip in Termux.

Nothing is downloaded unless the user passes ``--run``. Without it the command
only prints the exact commands for this platform, so the same panel works on a
phone and on Windows without a central server.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from typing import List, Tuple

from . import __version__, system
from .runner import parse_flags

WINGET_ID = "NGM.NgmPanel"


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def is_git_checkout(root: str = "") -> bool:
    root = root or project_root()
    # .git can be a directory or a gitfile/worktree pointer.
    return os.path.exists(os.path.join(root, ".git")) and os.path.isfile(
        os.path.join(root, "pyproject.toml")
    )


def plan() -> List[Tuple[str, List[str]]]:
    """Return ``[(label, argv)]`` for the current platform, in execution order."""
    root = project_root()
    checkout = is_git_checkout(root)
    if system.is_windows():
        return [
            ("winget source update", ["winget", "source", "update"]),
            (
                "winget upgrade",
                [
                    "winget", "upgrade", "--id", WINGET_ID, "-e", "--silent",
                    "--accept-source-agreements", "--accept-package-agreements",
                ],
            ),
        ]
    if system.is_termux():
        steps: List[Tuple[str, List[str]]] = [
            ("pkg update", ["pkg", "update", "-y"]),
            ("pkg upgrade", ["pkg", "upgrade", "-y"]),
        ]
        if checkout:
            steps.append(("git pull", ["git", "-C", root, "pull", "--ff-only"]))
            steps.append(("pip install -e", [sys.executable, "-m", "pip", "install", "-e", root]))
        else:
            steps.append(
                ("pip upgrade", [sys.executable, "-m", "pip", "install", "--upgrade", "ngm-panel"])
            )
        return steps
    if checkout:
        return [
            ("git pull", ["git", "-C", root, "pull", "--ff-only"]),
            ("pip install -e", [sys.executable, "-m", "pip", "install", "-e", root]),
        ]
    return [("pip upgrade", [sys.executable, "-m", "pip", "install", "--upgrade", "ngm-panel"])]


def method() -> str:
    if system.is_windows():
        return "winget"
    if system.is_termux():
        return "pkg + git/pip"
    return "git/pip"


def _quote(argv: List[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return " ".join(shlex.quote(part) for part in argv)


def run_update(console, argv: List[str]) -> int:
    _positionals, flags = parse_flags(argv, {"run": "bool", "check": "bool", "json": "bool"})
    steps = plan()
    console.heading("Update · ngm-panel")
    console.keyvalue(
        [
            ("Installed", __version__),
            ("Platform", system.platform_tag()),
            ("Method", method()),
        ]
    )
    console.heading("คำสั่งอัปเดตเครื่องนี้")
    for label, command in steps:
        console.line("  " + console.cyan(label.ljust(18)) + "  " + _quote(command))
    console.heading("คำสั่งติดตั้ง/อัปเดตด้วยมือ")
    console.line("  winget upgrade --id " + WINGET_ID + " -e")
    console.line("  winget install --id " + WINGET_ID + " -e --silent")
    console.line("  winget uninstall --id " + WINGET_ID + " -e")
    console.line("  pkg update -y && pkg upgrade -y")
    console.line("  bash packaging/termux/install-termux.sh")
    console.line("  python -m pip install --upgrade ngm-panel")

    failures = 0
    if flags.get("run"):
        console.heading("Running")
        for label, command in steps:
            if not os.path.isabs(command[0]) and shutil.which(command[0]) is None:
                console.warn(f"ข้าม {label}: ไม่พบ {command[0]} ใน PATH")
                failures += 1
                continue
            console.line("  ▶ " + _quote(command))
            console.flush()
            try:
                code = subprocess.call(command)
            except OSError as exc:
                console.err(f"{label}: {exc}")
                failures += 1
                continue
            if code:
                console.warn(f"{label} ออกด้วยรหัส {code}")
                failures += 1
            else:
                console.ok(label)
        if failures:
            console.warn(f"มี {failures} ขั้นที่ล้มเหลว — ตรวจ output ด้านบนก่อนลองใหม่")
        else:
            console.ok("อัปเดตครบทุกขั้น — เปิด ngm-panel ใหม่เพื่อใช้เวอร์ชันล่าสุด")
    else:
        console.sub("ยังไม่รันอะไร: เติม --run เพื่ออัปเดตทันที หรือคัดลอกคำสั่งด้านบนไปรันเอง")

    console.json_out(
        {
            "installed": __version__,
            "platform": system.platform_tag(),
            "method": method(),
            "steps": [{"label": label, "command": _quote(command)} for label, command in steps],
            "ran": bool(flags.get("run")),
            "failures": failures,
        }
    )
    return 0 if failures == 0 else 1
