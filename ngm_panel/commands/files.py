"""Local file management helpers: listing, search, hashing, sizes."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import List

from ..registry import Registry
from ..runner import parse_flags
from .common import human_bytes

SKIP_DIRS = {
    "$recycle.bin", "system volume information", "node_modules", ".git", "__pycache__",
    "windows", "appdata", ".venv", "venv", "dist", "build",
}


def _expand(raw: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(raw))).resolve()


def cmd_ls(ctx, argv: List[str]) -> int:
    target = _expand(argv[0] if argv else ".")
    if not target.exists():
        ctx.console.err(f"ไม่พบ path: {target}")
        return 1
    if target.is_file():
        ctx.console.keyvalue([("Path", str(target)), ("Size", human_bytes(target.stat().st_size))])
        return 0
    ctx.console.heading(f"Directory · {target}")
    rows = []
    try:
        entries = sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except PermissionError:
        ctx.console.err("ไม่มีสิทธิ์อ่านโฟลเดอร์นี้")
        return 1
    for entry in entries:
        try:
            stat = entry.stat()
            kind = "DIR" if entry.is_dir() else "FILE"
            rows.append([kind, entry.name, human_bytes(stat.st_size), _mtime(stat.st_mtime)])
        except OSError:
            rows.append(["?", entry.name, "-", "-"])
    ctx.console.table(["Type", "Name", "Size", "Modified"], rows)
    return 0


def _mtime(value: float) -> str:
    import time

    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value))


def cmd_find(ctx, argv: List[str]) -> int:
    root = _expand(argv[0] if argv else ".")
    pattern = argv[1] if len(argv) > 1 else "*"
    _, flags = parse_flags(argv[2:], {"ext": "str", "max": "int"})
    limit = int(flags.get("max") or 200)
    if flags.get("ext"):
        needle = str(flags["ext"]).lower().lstrip(".")
        pattern = f"*.{needle}"
    ctx.console.heading(f"Search · {root} · {pattern}")
    matches: List[List[str]] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith("$")]
        for name in files:
            if Path(name).match(pattern):
                full = Path(current) / name
                try:
                    size = full.stat().st_size
                except OSError:
                    size = 0
                matches.append([str(full), human_bytes(size)])
                if len(matches) >= limit:
                    break
        if len(matches) >= limit:
            break
    if not matches:
        ctx.console.warn("ไม่พบไฟล์ที่ตรงกัน")
        return 1
    ctx.console.table(["Path", "Size"], matches)
    if len(matches) >= limit:
        ctx.console.sub(f"แสดงสูงสุด {limit} รายการ (ใช้ --max N เพื่อเพิ่ม)")
    return 0


def find_by_extension(ctx, root: str, extension: str) -> int:
    return cmd_find(ctx, [root, f"*.{extension.lstrip('.')}"])


def make_extension_command(extension: str):
    def handler(ctx, argv: List[str]) -> int:
        root = argv[0] if argv else "."
        return find_by_extension(ctx, root, extension)

    return handler


ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "blake2b", "blake2s", "sha3_256", "sha3_512")


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 512), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cmd_hash(ctx, argv: List[str]) -> int:
    target = _expand(ctx.need(argv, 0, "file.hash <path> [-a sha256]", "path"))
    _, flags = parse_flags(argv[1:], {"a": "str", "algo": "str"})
    algorithm = str(flags.get("a") or flags.get("algo") or "sha256").lower()
    if algorithm not in ALGORITHMS:
        ctx.console.err(f"ไม่รองรับ {algorithm} (ใช้: {', '.join(ALGORITHMS)})")
        return 2
    if not target.is_file():
        ctx.console.err(f"ไม่ใช่ไฟล์: {target}")
        return 1
    digest = hash_file(target, algorithm)
    ctx.console.heading(f"{algorithm.upper()} · {target.name}")
    ctx.console.line("  " + digest)
    ctx.console.sub(f"size: {human_bytes(target.stat().st_size)}")
    ctx.print_json({"path": str(target), "algorithm": algorithm, "digest": digest})
    return 0


def dir_size(path: Path) -> int:
    total = 0
    for current, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for name in files:
            try:
                total += (Path(current) / name).stat().st_size
            except OSError:
                pass
    return total


def cmd_size(ctx, argv: List[str]) -> int:
    target = _expand(argv[0] if argv else ".")
    if not target.exists():
        ctx.console.err(f"ไม่พบ path: {target}")
        return 1
    size = target.stat().st_size if target.is_file() else dir_size(target)
    ctx.console.heading("Size")
    ctx.console.keyvalue([("Path", str(target)), ("Size", f"{human_bytes(size)} ({size:,} bytes)")])
    ctx.print_json({"path": str(target), "bytes": size})
    return 0


def cmd_tree(ctx, argv: List[str]) -> int:
    root = _expand(argv[0] if argv else ".")
    _, flags = parse_flags(argv[1:], {"d": "int", "depth": "int"})
    max_depth = int(flags.get("d") or flags.get("depth") or 2)
    if not root.is_dir():
        ctx.console.err(f"ไม่ใช่โฟลเดอร์: {root}")
        return 1
    ctx.console.heading(f"Tree · {root} (depth {max_depth})")
    base_depth = len(root.parts)
    count = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS][:20]
        depth = len(Path(current).parts) - base_depth
        if depth > max_depth:
            dirs[:] = []
            continue
        ctx.console.line("  " * depth + ctx.console.cyan(Path(current).name + "/"))
        for name in files[:20]:
            ctx.console.line("  " * (depth + 1) + name)
            count += 1
            if count > 400:
                ctx.console.sub("... (ตัดรายการ)")
                return 0
    return 0


def cmd_which(ctx, argv: List[str]) -> int:
    import shutil as _shutil

    name = ctx.need(argv, 0, "file.which <executable>", "ชื่อโปรแกรม")
    path = _shutil.which(name)
    if not path:
        ctx.console.warn(f"ไม่พบ {name} ใน PATH")
        return 1
    ctx.console.ok(path)
    return 0


def cmd_stat(ctx, argv: List[str]) -> int:
    import time

    target = _expand(ctx.need(argv, 0, "file.stat <path>", "path"))
    try:
        stat = target.stat()
    except OSError as exc:
        ctx.console.err(str(exc))
        return 1
    ctx.console.keyvalue(
        [
            ("Path", str(target)),
            ("Type", "directory" if target.is_dir() else "file"),
            ("Size", f"{stat.st_size:,} bytes"),
            ("Created", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_ctime))),
            ("Modified", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))),
            ("Accessed", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_atime))),
        ]
    )
    return 0


def register(registry: Registry) -> None:
    registry.add(cmd_ls, name="file.ls", category="file", usage="file.ls [path]",
                 description="รายการไฟล์/โฟลเดอร์พร้อมขนาดและเวลาแก้ไข")
    registry.add(cmd_find, name="file.find", category="file", usage="file.find [root] [pattern] [--max N]",
                 description="ค้นหาไฟล์ด้วย glob pattern ภายใต้โฟลเดอร์ที่กำหนด")
    registry.add(cmd_hash, name="file.hash", category="file", usage="file.hash <path> [-a sha256]",
                 description=f"คำนวณ hash ของไฟล์ ({', '.join(ALGORITHMS)})")
    registry.add(cmd_size, name="file.size", category="file", usage="file.size [path]",
                 description="ขนาดไฟล์หรือขนาดรวมของโฟลเดอร์")
    registry.add(cmd_tree, name="file.tree", category="file", usage="file.tree [path] [-d depth]",
                 description="แสดงโครงสร้างโฟลเดอร์แบบต้นไม้")
    registry.add(cmd_which, name="file.which", category="file", usage="file.which <executable>",
                 description="ค้นหา executable ใน PATH")
    registry.add(cmd_stat, name="file.stat", category="file", usage="file.stat <path>",
                 description="ข้อมูล metadata ของไฟล์/โฟลเดอร์")
