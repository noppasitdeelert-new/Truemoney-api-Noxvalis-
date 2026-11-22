"""Bounded load-test engine used by the L7 / L4 / flood benchmark commands."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from .ratelimit import RateLimiter, Stats


@dataclass
class LoadConfig:
    concurrency: int = 5
    duration: float = 10.0
    rps: float = 5.0
    timeout: float = 5.0
    request_cap: int = 2000


@dataclass
class RequestOutcome:
    ok: bool
    latency_ms: float
    status: Optional[int] = None
    error: str = ""


class LoadRunner:
    """Threads + shared limiter + deadline + request cap + cooperative stop."""

    def __init__(self, config: LoadConfig, console) -> None:
        self.config = config
        self.console = console
        self.stats = Stats()
        self.limiter = RateLimiter(config.rps)
        self.stop = threading.Event()
        self.started_at = 0.0

    def run(self, action: Callable[[], RequestOutcome], label: str) -> Dict[str, object]:
        config = self.config
        self.started_at = time.monotonic()
        deadline = self.started_at + config.duration
        issued = {"count": 0, "lock": threading.Lock()}

        def worker() -> None:
            while not self.stop.is_set():
                if time.monotonic() >= deadline:
                    break
                with issued["lock"]:
                    if issued["count"] >= config.request_cap:
                        break
                    issued["count"] += 1
                self.limiter.acquire()
                if self.stop.is_set() or time.monotonic() >= deadline:
                    break
                try:
                    outcome = action()
                except Exception as exc:  # network backends raise arbitrary errors
                    outcome = RequestOutcome(False, 0.0, None, type(exc).__name__)
                self.stats.record(outcome.ok, outcome.latency_ms, outcome.error, outcome.status)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(config.concurrency)]
        for thread in threads:
            thread.start()

        progress_stop = threading.Event()

        def progress() -> None:
            while not progress_stop.wait(1.0):
                snapshot = self.stats.snapshot()
                line = (
                    f"  {label}  t={time.monotonic() - self.started_at:5.1f}s  "
                    f"req={snapshot['total']:<6} ok={snapshot['success']:<6} "
                    f"avg={snapshot['avg_ms']:.0f}ms  p95={snapshot['p95_ms']:.0f}ms"
                )
                if self.console.color and self.console.is_tty:
                    self.console.write("\r" + line + " " * 6)
                    self.console.flush()

        reporter = None
        if self.console.is_tty:
            reporter = threading.Thread(target=progress, daemon=True)
            reporter.start()

        interrupted = False
        try:
            while any(thread.is_alive() for thread in threads):
                for thread in threads:
                    thread.join(timeout=0.2)
                if time.monotonic() >= deadline + config.timeout + 2:
                    self.stop.set()
                    break
        except KeyboardInterrupt:
            interrupted = True
            self.stop.set()
            self.console.blank()
            self.console.warn("Ctrl+C — กำลังหยุด worker อย่างปลอดภัย...")
            for thread in threads:
                thread.join(timeout=2.0)
        finally:
            progress_stop.set()
            if reporter is not None:
                reporter.join(timeout=1.0)
                self.console.write("\r" + " " * 100 + "\r")

        elapsed = max(0.001, time.monotonic() - self.started_at)
        snapshot = self.stats.snapshot()
        snapshot["elapsed_seconds"] = elapsed
        snapshot["rps_actual"] = snapshot["total"] / elapsed
        snapshot["interrupted"] = interrupted
        snapshot["concurrency"] = config.concurrency
        snapshot["requested_rps"] = config.rps
        return snapshot

    @staticmethod
    def summarize(console, snapshot: Dict[str, object], title: str) -> None:
        console.heading(title)
        console.keyvalue(
            [
                ("Elapsed", f"{snapshot['elapsed_seconds']:.2f} s"),
                ("Concurrency", snapshot["concurrency"]),
                ("Total requests", snapshot["total"]),
                ("Success", f"{snapshot['success']} ({snapshot['success_rate']:.1f}%)"),
                ("Errors", snapshot["failures"]),
                ("RPS (actual)", f"{snapshot['rps_actual']:.2f}"),
                ("Latency avg", f"{snapshot['avg_ms']:.1f} ms"),
                ("Latency p50/p95/p99", f"{snapshot['p50_ms']:.1f} / {snapshot['p95_ms']:.1f} / {snapshot['p99_ms']:.1f} ms"),
                ("Latency max", f"{snapshot['max_ms']:.1f} ms"),
                ("Stopped by user", "yes" if snapshot.get("interrupted") else "no"),
            ]
        )
        statuses = snapshot.get("statuses") or {}
        if statuses:
            console.heading("Status codes")
            console.table(["Status", "Count"], sorted(statuses.items()))
        errors = snapshot.get("errors") or {}
        if errors:
            console.heading("Errors")
            console.table(["Error", "Count"], sorted(errors.items(), key=lambda item: -item[1])[:10])
        console.blank()
        if snapshot.get("interrupted"):
            console.warn("ผลลัพธ์เป็นค่าบางส่วน (ผู้ใช้หยุดการทดสอบ)")
        elif snapshot["total"] == 0:
            console.warn("ไม่มีคำขอสำเร็จ — ตรวจสอบ scope/เครือข่าย/timeout")
        else:
            console.ok(
                f"สรุป: {snapshot['success']}/{snapshot['total']} สำเร็จ · "
                f"{snapshot['rps_actual']:.2f} req/s · avg {snapshot['avg_ms']:.1f} ms"
            )
