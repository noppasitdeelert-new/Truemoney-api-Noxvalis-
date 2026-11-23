"""Self-update planning: winget on Windows, pkg + git/pip in Termux.

Nothing is downloaded unless the user passes ``--run``. Without it the command
only prints the exact commands for this platform, so the same panel works on a
phone and on Windows without a central server.

The package is not published on PyPI, so a machine that is not already a git
checkout bootstraps one from :data:`REPO_URL` into ``~/ngm-panel`` and installs
it in editable mode. That keeps ``ngm-panel update --run`` usable on a fresh
Termux install as well as in a development checkout.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from typing import Dict, List, Tuple

from . import __version__, system
from .runner import parse_flags

WINGET_ID = "NGM.NgmPanel"
PACKAGE_NAME = "ngm-panel"
REPO_URL = "https://github.com/noppasitdeelert-new/Truemoney-api-Noxvalis-"
WINGET_MANIFEST_URL = REPO_URL + "/tree/main/packaging/winget/manifests/n/NGM/NgmPanel"


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def clone_dir() -> str:
    """Where ``update --run`` bootstraps a checkout when there is none."""
    return os.path.join(os.path.expanduser("~"), PACKAGE_NAME)


def is_git_checkout(root: str = "") -> bool:
    root = root or project_root()
    # .git can be a directory or a gitfile/worktree pointer.
    return os.path.exists(os.path.join(root, ".git")) and os.path.isfile(
        os.path.join(root, "pyproject.toml")
    )


def _git_steps(root: str) -> List[Tuple[str, List[str]]]:
    """Pull an existing checkout, or clone + install one when there is none."""
    if is_git_checkout(root):
        return [
            ("git pull", ["git", "-C", root, "pull", "--ff-only"]),
            ("pip install -e", [sys.executable, "-m", "pip", "install", "-e", root]),
        ]
    return [
        ("git clone", ["git", "clone", "--depth", "1", REPO_URL, root]),
        ("pip install -e", [sys.executable, "-m", "pip", "install", "-e", root]),
    ]


def plan() -> List[Tuple[str, List[str]]]:
    """Return ``[(label, argv)]`` for the current platform, in execution order."""
    root = project_root()
    target = root if is_git_checkout(root) else clone_dir()
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
        return [
            ("pkg update", ["pkg", "update", "-y"]),
            ("pkg upgrade", ["pkg", "upgrade", "-y"]),
            ("pkg install", ["pkg", "install", "-y", "python", "git"]),
        ] + _git_steps(target)
    return _git_steps(target)


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


def _tool(command: List[str]) -> Tuple[str, str]:
    """``(tool, resolved path or "")`` for one step's executable."""
    program = command[0]
    if os.path.isabs(program):
        return program, program if os.path.exists(program) else ""
    return program, shutil.which(program) or ""


def check(steps: List[Tuple[str, List[str]]]) -> List[Tuple[str, str, bool]]:
    """Report which tools each step needs and whether they exist."""
    report: List[Tuple[str, str, bool]] = []
    seen: Dict[str, bool] = {}
    for label, command in steps:
        tool, found = _tool(command)
        if tool not in seen:
            seen[tool] = bool(found)
            report.append((label, tool, bool(found)))
    return report


def _step_problem(label: str, command: List[str]) -> str:
    """Reasons a step cannot run, checked before touching the system."""
    if command[:2] == ["git", "clone"] and len(command) == 6:
        destination = command[-1]
        if os.path.exists(destination):
            return (
                f"ปลายทาง {destination} มีอยู่แล้วแต่ไม่ใช่ git checkout — "
                "ย้าย/ลบโฟลเดอร์นั้นหรือรันจาก checkout เดิม"
            )
    tool, found = _tool(command)
    if not found:
        return f"ไม่พบ {tool} ใน PATH"
    return ""


def run_update(console, argv: List[str]) -> int:
    _positionals, flags = parse_flags(argv, {"run": "bool", "check": "bool", "json": "bool"})
    root = project_root()
    steps = plan()
    checkout = is_git_checkout(root)
    console.heading("Update · ngm-panel")
    console.keyvalue(
        [
            ("Installed", __version__),
            ("Platform", system.platform_tag()),
            ("Method", method()),
            ("Repo", "checkout " + root if checkout else "clone → " + clone_dir()),
        ]
    )

    if flags.get("check"):
        console.heading("ตรวจความพร้อมของเครื่องมือ")
        ready = True
        for label, tool, found in check(steps):
            if found:
                console.ok(tool)
            else:
                ready = False
                console.err(f"{tool} — ต้องมีสำหรับขั้น {label}")
        if ready:
            console.sub("ครบทุกเครื่องมือ: เติม --run เพื่ออัปเดตทันที")
        else:
            console.sub("ติดตั้งเครื่องมือที่ขาดก่อน (winget / pkg / git / python -m pip)")

    console.heading("คำสั่งอัปเดตเครื่องนี้")
    for label, command in steps:
        console.line("  " + console.cyan(label.ljust(18)) + "  " + _quote(command))
    console.heading("คำสั่งติดตั้ง/อัปเดตด้วยมือ")
    console.line("  winget upgrade --id " + WINGET_ID + " -e")
    console.line("  winget install --id " + WINGET_ID + " -e --silent")
    console.line("  winget uninstall --id " + WINGET_ID + " -e")
    console.line("  winget install --manifest packaging\\winget\\manifests\\n\\NGM\\NgmPanel\\" + __version__)
    console.line("  pkg update -y && pkg upgrade -y && pkg install -y python git")
    console.line("  bash packaging/termux/install-termux.sh")
    console.line("  git clone " + REPO_URL + " ~/" + PACKAGE_NAME)
    console.line("  python -m pip install -e .")
    console.line("  " + WINGET_MANIFEST_URL)

    failures = 0
    if flags.get("run"):
        console.heading("Running")
        for label, command in steps:
            problem = _step_problem(label, command)
            if problem:
                console.warn(f"ข้าม {label}: {problem}")
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
            "repo": root,
            "checkout": checkout,
            "clone_dir": clone_dir(),
            "steps": [{"label": label, "command": _quote(command)} for label, command in steps],
            "tools": [{"tool": tool, "found": found, "step": label} for label, tool, found in check(steps)],
            "ran": bool(flags.get("run")),
            "failures": failures,
        }
    )
    console.flush()
    return 0 if failures == 0 else 1
