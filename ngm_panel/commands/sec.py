"""Security posture checks for authorized web targets, plus local scope review."""

from __future__ import annotations

from typing import List

from .. import net_utils
from ..registry import Registry
from .common import authorize


def cmd_scope(ctx, argv: List[str]) -> int:
    summary = ctx.guard.summary()
    ctx.console.heading("Authorized scope")
    ctx.console.keyvalue(
        [
            ("Scope file", summary["scope_file"]),
            ("Targets", len(summary["targets"])),
            ("Max RPS", summary["limits"]["max_rps"]),
            ("Max concurrency", summary["limits"]["max_concurrency"]),
            ("Timeout", f"{summary['limits']['timeout_seconds']} s"),
            ("Request cap", summary["limits"]["request_cap"]),
            ("Max duration", f"{summary['limits']['max_duration_seconds']} s"),
            ("Private networks", "allowed" if summary["allow_private_networks"] else "blocked"),
        ]
    )
    rows = [[t["host"], ", ".join(map(str, t["ports"])) if t["ports"] else "any", t["note"] or "-"]
            for t in summary["targets"]]
    ctx.console.heading("Targets")
    ctx.console.table(["Host", "Ports", "Note"], rows)
    ctx.console.sub("เพิ่ม/ลบ: ngm-panel scope add <host> [--ports 80,443] · ngm-panel scope remove <host>")
    ctx.print_json(summary)
    return 0


def cmd_audit(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "sec.audit <url>", "URL")
    authorize(ctx, url)
    ctx.console.heading(f"Security audit · {url}")
    result = net_utils.http_request(url, timeout=ctx.timeout(), max_body=4096)
    if not result.ok:
        ctx.console.err(result.error or "request failed")
        return 1
    findings: List[List[str]] = []
    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}

    def add(severity: str, title: str, detail: str) -> None:
        findings.append([severity.upper(), title, detail])

    add("info", "HTTP status", f"{result.status} {result.reason}".strip())
    if result.url.startswith("http://"):
        add("high", "ไม่ใช้ HTTPS", "ข้อมูลเดินทางแบบไม่เข้ารหัส")
    report = net_utils.security_header_report(result.headers)
    for item in report:
        if item["present"]:
            add("info", str(item["header"]), "present")
        else:
            severity = "high" if item["header"] in {"Strict-Transport-Security", "Content-Security-Policy"} else "medium"
            add(severity, str(item["header"]), "missing — " + str(item["purpose"]))
    if result.header("server"):
        add("low", "Server banner", f"เปิดเผยเวอร์ชัน: {result.header('server')}")
    if result.header("x-powered-by"):
        add("low", "X-Powered-By", f"เปิดเผย stack: {result.header('x-powered-by')}")
    if result.header("set-cookie"):
        cookies = result.header("set-cookie") or ""
        if "httponly" not in cookies.lower():
            add("medium", "Cookie flags", "Set-Cookie ไม่มี HttpOnly")
        if "secure" not in cookies.lower() and result.url.startswith("https://"):
            add("medium", "Cookie flags", "Set-Cookie ไม่มี Secure")
    if result.url.startswith("https://"):
        host, _, port_text, _ = net_utils.split_url(result.url)
        tls = net_utils.tls_inspect(host, int(port_text), timeout=ctx.timeout())
        if tls.ok:
            if not tls.verified:
                add("high", "TLS certificate", tls.error or "certificate not trusted")
            if tls.version in {"TLSv1", "TLSv1.1", "SSLv3"}:
                add("high", "TLS version", f"ใช้ {tls.version} ซึ่งล้าสมัย")
            days = tls.days_left()
            if days is not None and 0 <= days < 21:
                add("medium", "TLS expiry", f"เหลือ {days} วัน")
        else:
            add("high", "TLS", tls.error or "inspection failed")

    findings.sort(key=lambda row: severity_rank.get(row[0].lower(), 9))
    ctx.console.table(["Severity", "Item", "Detail"], findings)
    counts = {}
    for row in findings:
        counts[row[0]] = counts.get(row[0], 0) + 1
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)
    score = max(0, 100 - high * 20 - medium * 8)
    ctx.console.blank()
    ctx.console.line("  " + ctx.console.bar(score / 100) + f"  score {score}/100 · {high} high · {medium} medium")
    ctx.print_json({"url": url, "status": result.status, "score": score, "findings": findings})
    return 0 if high == 0 else 1


def cmd_tls_grade(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "sec.tls-grade <host> [port]", "host")
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 443
    host = authorize(ctx, host, port)
    ctx.console.heading(f"TLS grade · {host}:{port}")
    info = net_utils.tls_inspect(host, port, timeout=ctx.timeout())
    if not info.ok:
        ctx.console.err(info.error or "เชื่อมต่อ TLS ไม่ได้")
        return 1
    reasons: List[str] = []
    score = 100
    if not info.verified:
        score -= 40
        reasons.append("certificate ไม่ผ่านการตรวจสอบ")
    if info.version == "TLSv1.3":
        reasons.append("ใช้ TLS 1.3 (ดีที่สุด)")
    elif info.version == "TLSv1.2":
        score -= 5
        reasons.append("ใช้ TLS 1.2 (ยอมรับได้)")
    else:
        score -= 35
        reasons.append(f"ใช้ {info.version} ซึ่งไม่ปลอดภัย")
    days = info.days_left()
    if days is not None:
        if days < 0:
            score -= 50
            reasons.append("ใบรับรองหมดอายุ")
        elif days < 21:
            score -= 10
            reasons.append(f"ใบรับรองใกล้หมดอายุ ({days} วัน)")
        else:
            reasons.append(f"ใบรับรองเหลือ {days} วัน")
    if "AES" in info.cipher or "CHACHA20" in info.cipher:
        reasons.append("cipher เป็น AEAD")
    else:
        score -= 15
        reasons.append(f"cipher ไม่ใช่ AEAD: {info.cipher}")
    score = max(0, min(100, score))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    ctx.console.keyvalue(
        [
            ("Grade", grade),
            ("Score", f"{score}/100"),
            ("Protocol", info.version),
            ("Cipher", info.cipher),
            ("Issuer", info.issuer),
            ("Valid until", info.not_after),
        ]
    )
    ctx.console.heading("Reasons")
    for reason in reasons:
        ctx.console.line("  • " + reason)
    ctx.print_json({"host": host, "port": port, "grade": grade, "score": score, "protocol": info.version,
                    "cipher": info.cipher, "reasons": reasons})
    return 0


def register(registry: Registry) -> None:
    registry.add(cmd_scope, name="sec.scope", category="sec", usage="sec.scope",
                 description="แสดง authorized scope และขีดจำกัดความปลอดภัยปัจจุบัน")
    registry.add(cmd_audit, name="sec.audit", category="sec", usage="sec.audit <url>",
                 description="ตรวจ security posture (headers/TLS/cookies) พร้อมคะแนน", danger="scope")
    registry.add(cmd_tls_grade, name="sec.tls-grade", category="sec", usage="sec.tls-grade <host> [port]",
                 description="ให้เกรด TLS จาก protocol/cipher/อายุใบรับรอง", danger="scope")
