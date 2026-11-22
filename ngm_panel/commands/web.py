"""Web inspection commands: headers, security headers, TLS and polite path probes."""

from __future__ import annotations

import re
from typing import List

from .. import net_utils
from ..registry import Registry
from ..runner import parse_flags
from .common import authorize

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def fetch(ctx, url: str, method: str = "GET"):
    host = authorize(ctx, url)
    result = net_utils.http_request(url, method=method, timeout=ctx.timeout(), max_body=32768)
    ctx.print_json(
        {
            "url": result.url,
            "host": host,
            "ok": result.ok,
            "status": result.status,
            "reason": result.reason,
            "elapsed_ms": round(result.elapsed_ms, 2),
            "http_version": result.http_version,
            "headers": result.headers,
            "error": result.error,
        }
    )
    return result


def _title(body: bytes) -> str:
    match = _TITLE_RE.search(body.decode("utf-8", "replace"))
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""


def cmd_scan(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "web.scan <url>", "URL")
    ctx.console.heading(f"Web scan · {url}")
    result = fetch(ctx, url)
    if not result.ok:
        ctx.console.err(result.error or "request failed")
        return 1
    title = _title(result.body)
    ctx.console.keyvalue(
        [
            ("Status", f"{result.status} {result.reason}".strip()),
            ("Protocol", result.http_version),
            ("Response time", f"{result.elapsed_ms:.1f} ms"),
            ("Server", result.header("server") or "-"),
            ("Content-Type", result.header("content-type") or "-"),
            ("Powered by", result.header("x-powered-by") or "-"),
            ("Title", title or "-"),
        ]
    )

    ctx.console.heading("Selected response headers")
    rows = [[name, result.header(name)] for name in net_utils.COMMON_HEADERS if result.header(name)]
    ctx.console.table(["Header", "Value"], rows or [["-", "(none of the tracked headers)"]])

    report = net_utils.security_header_report(result.headers)
    ctx.console.heading("Security headers")
    ctx.console.table(
        ["Header", "State", "Purpose"],
        [[item["header"], "present" if item["present"] else "MISSING", item["purpose"]] for item in report],
    )
    missing = [item["header"] for item in report if not item["present"]]
    if missing:
        ctx.console.warn(f"ขาด {len(missing)} security header: {', '.join(missing)}")
    else:
        ctx.console.ok("มี security header ครบทั้งชุดที่ตรวจ")

    if result.url.startswith("https://"):
        ctx.console.heading("TLS")
        host, _, port_text, _ = net_utils.split_url(result.url)
        info = net_utils.tls_inspect(host, int(port_text), timeout=ctx.timeout())
        if info.ok:
            ctx.console.keyvalue(
                [
                    ("Protocol", info.version),
                    ("Cipher", info.cipher),
                    ("Issuer", info.issuer),
                    ("Valid until", info.not_after),
                    ("Verified", "yes" if info.verified else "NO"),
                ]
            )
        else:
            ctx.console.warn(info.error or "TLS inspection failed")
    return 0


def cmd_security(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "web.security <url>", "URL")
    ctx.console.heading(f"Security headers · {url}")
    result = fetch(ctx, url)
    if not result.ok:
        ctx.console.err(result.error or "request failed")
        return 1
    report = net_utils.security_header_report(result.headers)
    for item in report:
        exists = item["present"]
        ctx.console.line(
            "  " + (ctx.console.green("✔") if exists else ctx.console.red("✘")) + " "
            + ctx.console.bold(f"{str(item['header']):<30}") + " " + ctx.console.dim(str(item["purpose"]))
        )
        if exists:
            ctx.console.line("      " + ctx.console.dim(str(item["value"])[:110]))
    present = sum(1 for item in report if item["present"])
    ctx.blank()
    ctx.console.line(
        "  " + ctx.console.bar(present / len(report)) + f"  {present}/{len(report)} headers"
    )
    return 0


def show_header_result(ctx, result, header: str) -> int:
    if not result.ok:
        ctx.console.err(result.error or "request failed")
        return 1
    value = result.header(header)
    if value:
        ctx.console.ok(f"{header}: {value}")
        return 0
    ctx.console.warn(f"{header}: ไม่พบใน response (status {result.status})")
    return 1


def make_header_command(header: str):
    def handler(ctx, argv: List[str]) -> int:
        url = ctx.need(argv, 0, f"web.header-{header.lower()} <url>", "URL")
        ctx.console.heading(f"Header {header} · {url}")
        return show_header_result(ctx, fetch(ctx, url, "HEAD"), header)

    return handler


def cmd_check_header(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "web.check-header <url> <header>", "URL")
    header = ctx.need(argv, 1, "web.check-header <url> <header>", "ชื่อ header")
    return show_header_result(ctx, fetch(ctx, url, "HEAD"), header)


def cmd_method(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "web.method <url> <verb>", "URL")
    verb = ctx.need(argv, 1, "web.method <url> <verb>", "HTTP method").upper()
    if verb not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}:
        ctx.console.err(f"ไม่รองรับ method: {verb}")
        return 2
    cache = net_utils.normalize_host(url)
    authorize(ctx, url)
    ctx.console.heading(f"HTTP {verb} · {url}")
    headers = None
    if verb in {"POST", "PUT", "PATCH"}:
        headers = {"Content-Type": "text/plain", "Content-Length": "0"}
    result = net_utils.http_request(url, method=verb, timeout=ctx.timeout(), max_body=4096, extra_headers=headers)
    if not result.ok:
        ctx.console.err(result.error or "request failed")
        return 1
    ctx.console.keyvalue(
        [
            ("Status", f"{result.status} {result.reason}".strip()),
            ("Response time", f"{result.elapsed_ms:.1f} ms"),
            ("Allow", result.header("allow") or "-"),
            ("Content-Length", result.header("content-length") or "-"),
            ("Host checked", cache),
        ]
    )
    ctx.print_json({"url": url, "method": verb, "status": result.status, "elapsed_ms": result.elapsed_ms,
                    "headers": result.headers})
    return 0


def make_method_command(verb: str):
    def handler(ctx, argv: List[str]) -> int:
        url = ctx.need(argv, 0, f"web.method-{verb.lower()} <url>", "URL")
        return cmd_method(ctx, [url, verb])

    return handler


def cmd_path(ctx, argv: List[str]) -> int:
    base = ctx.need(argv, 0, "web.path <base-url> <path>", "base URL")
    path = ctx.need(argv, 1, "web.path <base-url> <path>", "path")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    url = base + path
    authorize(ctx, url)
    ctx.console.heading(f"Path probe · {url}")
    result = net_utils.http_request(url, method="GET", timeout=ctx.timeout(), max_body=2048)
    if not result.ok:
        ctx.console.err(result.error or "request failed")
        return 1
    ctx.console.keyvalue(
        [
            ("Status", f"{result.status} {result.reason}".strip()),
            ("Response time", f"{result.elapsed_ms:.1f} ms"),
            ("Content-Type", result.header("content-type") or "-"),
            ("Length", result.header("content-length") or str(len(result.body))),
        ]
    )
    if result.body:
        preview = result.body[:400].decode("utf-8", "replace").strip()
        if preview:
            ctx.console.heading("Preview")
            for line in preview.splitlines()[:8]:
                ctx.console.line("  " + line[:120])
    ctx.print_json({"url": url, "status": result.status, "elapsed_ms": result.elapsed_ms,
                    "content_type": result.header("content-type"), "length": len(result.body)})
    return 0 if result.status < 400 else 1


def make_path_command(path: str):
    def handler(ctx, argv: List[str]) -> int:
        base = ctx.need(argv, 0, f"web.path-{path.strip('/').replace('/', '-') or 'root'} <base-url>", "base URL")
        return cmd_path(ctx, [base, path])

    return handler


def register(registry: Registry) -> None:
    registry.add(cmd_scan, name="web.scan", category="web", usage="web.scan <url>",
                 description="ตรวจ HTTP headers, security headers, TLS และข้อมูลพื้นฐานของเว็บ", danger="scope",
                 examples=("web.scan https://example.com",))
    registry.add(cmd_security, name="web.security", category="web", usage="web.security <url>",
                 description="เช็กลิสต์ security headers พร้อมค่าและคำอธิบาย", danger="scope")
    registry.add(cmd_check_header, name="web.check-header", category="web", usage="web.check-header <url> <header>",
                 description="ตรวจ header เดี่ยวใน response", danger="scope")
    registry.add(cmd_method, name="web.method", category="web", usage="web.method <url> <GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE>",
                 description="ยิง HTTP method เดียวอย่างควบคุม", danger="scope")
    registry.add(cmd_path, name="web.path", category="web", usage="web.path <base-url> <path>",
                 description="ตรวจเส้นทางเดี่ยวบนเว็บที่ได้รับอนุญาต", danger="scope",
                 examples=("web.path https://example.com /robots.txt",))
