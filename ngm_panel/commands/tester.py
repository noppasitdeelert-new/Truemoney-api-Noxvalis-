"""Controlled load testing: L7 (HTTP), L4 (TCP) and rate-limited HTTP benchmark.

Every mode is bounded by the scope file: rate, concurrency, duration and a hard
request cap. Ctrl+C stops workers immediately and still prints partial results.
"""

from __future__ import annotations

import socket
import time
from typing import List

from .. import net_utils
from ..loadgen import LoadConfig, LoadRunner, RequestOutcome
from ..registry import Registry
from ..runner import parse_flags
from .common import authorize, resolve_checked

TEST_FLAGS = {"n": "int", "c": "int", "d": "float", "duration": "float",
              "r": "float", "rps": "float", "cap": "int"}


def _build_config(ctx, flags) -> LoadConfig:
    limits = ctx.guard.limits
    concurrency = int(flags.get("n") or flags.get("c") or 5)
    duration = float(flags.get("d") or flags.get("duration") or 10.0)
    rps = float(flags.get("r") or flags.get("rps") or min(5.0, limits.max_rps))
    cap = int(flags.get("cap") or limits.request_cap)
    clamped = LoadConfig(
        concurrency=ctx.guard.clamp_concurrency(concurrency),
        duration=ctx.guard.clamp_duration(duration),
        rps=ctx.guard.clamp_rps(rps),
        timeout=ctx.timeout(),
        request_cap=min(cap, limits.request_cap),
    )
    if (clamped.concurrency, clamped.duration, clamped.rps) != (concurrency, duration, rps):
        ctx.console.warn(
            f"ปรับค่าตามขีดจำกัดความปลอดภัย: concurrency {concurrency}→{clamped.concurrency}, "
            f"duration {duration}→{clamped.duration}s, rps {rps}→{clamped.rps}"
        )
    if clamped.request_cap < 1:
        clamped.request_cap = 1
    return clamped


def _announce(ctx, config: LoadConfig, target: str) -> bool:
    ctx.console.heading("Load test plan")
    ctx.console.keyvalue(
        [
            ("Target", target),
            ("Concurrency", config.concurrency),
            ("Duration", f"{config.duration:.1f} s"),
            ("Requested RPS", config.rps),
            ("Request cap", config.request_cap),
            ("Timeout", f"{config.timeout:.1f} s"),
        ]
    )
    ctx.console.blank()
    if ctx.options.dry_run:
        ctx.console.info("--dry-run: แสดงแผนอย่างเดียว ไม่ได้ยิงคำขอ")
        return False
    approved = ctx.guard.require_confirmation(
        ctx.console,
        f"ทดสอบโหลดไปยัง {target}",
        f"concurrency={config.concurrency}, duration={config.duration:.0f}s, rps={config.rps}, cap={config.request_cap}",
    )
    if not approved:
        from ..scope_guard import ScopeError

        raise ScopeError("ผู้ใช้ไม่ยืนยันขอบเขต — ยกเลิกการทดสอบ")
    return True


def cmd_l7(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "web.test-l7 <url> [-n concurrency] [-d seconds] [-r rps] [--cap N]", "URL")
    remaining, flags = parse_flags(argv[1:], TEST_FLAGS)
    if remaining:
        ctx.console.warn(f"มองข้าม argument: {' '.join(remaining)}")
    authorize(ctx, url)
    config = _build_config(ctx, flags)
    if not _announce(ctx, config, url):
        return 0

    def action() -> RequestOutcome:
        started = time.perf_counter()
        result = net_utils.http_request(url, timeout=config.timeout, max_body=1024)
        elapsed = (time.perf_counter() - started) * 1000
        if not result.ok:
            return RequestOutcome(False, elapsed, None, result.error.split(":", 1)[0] or "error")
        ok = result.status < 400
        return RequestOutcome(ok, elapsed, result.status, "" if ok else f"HTTP {result.status}")

    runner = LoadRunner(config, ctx.console)
    snapshot = runner.run(action, "L7")
    LoadRunner.summarize(ctx.console, snapshot, "L7 summary (HTTP/HTTPS)")
    ctx.print_json(snapshot)
    return 0 if snapshot["failures"] == 0 else 1


def cmd_l4(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "web.test-l4 <host> <port> [-n] [-d] [-r]", "host")
    port_text = ctx.need(argv, 1, "web.test-l4 <host> <port> [-n] [-d] [-r]", "พอร์ต")
    if not port_text.isdigit():
        ctx.console.err("พอร์ตต้องเป็นตัวเลข")
        return 2
    port = int(port_text)
    _, flags = parse_flags(argv[2:], TEST_FLAGS)
    host = authorize(ctx, host, port)
    addresses = resolve_checked(ctx, host)
    target_ip = addresses[0] if addresses else host
    config = _build_config(ctx, flags)
    if not _announce(ctx, config, f"tcp://{target_ip}:{port}"):
        return 0

    def action() -> RequestOutcome:
        started = time.perf_counter()
        try:
            with socket.create_connection((target_ip, port), timeout=config.timeout):
                return RequestOutcome(True, (time.perf_counter() - started) * 1000)
        except OSError as exc:
            return RequestOutcome(False, (time.perf_counter() - started) * 1000, None, type(exc).__name__)

    runner = LoadRunner(config, ctx.console)
    snapshot = runner.run(action, "L4")
    LoadRunner.summarize(ctx.console, snapshot, f"L4 summary (TCP {target_ip}:{port})")
    ctx.print_json(snapshot)
    return 0 if snapshot["failures"] == 0 else 1


def cmd_flood(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "web.test-flood <url> [-n] [-d] [-r] [--cap N]", "URL")
    ctx.console.line(ctx.console.yellow("  โหมดนี้คือ controlled load benchmark — ไม่ใช่การยิงถล่มแบบไม่มีขอบเขต"))
    return cmd_l7(ctx, argv)


def register(registry: Registry) -> None:
    registry.add(cmd_l7, name="web.test-l7", category="web",
                 usage="web.test-l7 <url> [-n concurrency] [-d seconds] [-r rps] [--cap N]",
                 description="โหมด 1: ทดสอบระดับ Application (HTTP) วัด status/latency/throughput", danger="active",
                 examples=("web.test-l7 https://example.com -n 5 -d 10 -r 5",))
    registry.add(cmd_l4, name="web.test-l4", category="web",
                 usage="web.test-l4 <host> <port> [-n concurrency] [-d seconds] [-r rps]",
                 description="โหมด 2: ทดสอบระดับ Transport (TCP connect) วัดอัตราสำเร็จ/latency", danger="active",
                 examples=("web.test-l4 127.0.0.1 8000 -n 4 -d 10 -r 5",))
    registry.add(cmd_flood, name="web.test-flood", category="web",
                 usage="web.test-flood <url> [-n concurrency] [-d seconds] [-r rps] [--cap N]",
                 description="โหมด 3: HTTP/HTTPS controlled load benchmark พร้อมสถิติและหยุดด้วย Ctrl+C", danger="active",
                 examples=("web.test-flood https://example.com -n 10 -d 15 -r 10",))
