"""Rate limiting, concurrency gating and load-test statistics."""

from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Dict, List, Optional


class RateLimiter:
    """Token-bucket-ish pacing: guarantees at most ``rps`` acquisitions per second."""

    def __init__(self, rps: float) -> None:
        self.rps = max(0.0, float(rps))
        self._interval = 1.0 / self.rps if self.rps > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if self._next <= now:
                self._next = now + self._interval
                wait = 0.0
            else:
                wait = self._next - now
                self._next += self._interval
        if wait > 0:
            time.sleep(wait)


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.failures = 0
        self.latencies: List[float] = []
        self.errors: Counter = Counter()
        self.statuses: Counter = Counter()

    def record(self, ok: bool, latency_ms: float, error: str = "", status: Optional[int] = None) -> None:
        with self._lock:
            self.total += 1
            if ok:
                self.success += 1
            else:
                self.failures += 1
                self.errors[error or "error"] += 1
            if status:
                self.statuses[status] += 1
            if len(self.latencies) < 500000:
                self.latencies.append(latency_ms)

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            latencies = sorted(self.latencies)
            total = self.total
            success = self.success
            failures = self.failures
            errors = dict(self.errors)
            statuses = dict(self.statuses)
        def pct(p: float) -> float:
            if not latencies:
                return 0.0
            index = min(len(latencies) - 1, int(round((p / 100.0) * (len(latencies) - 1))))
            return latencies[index]

        return {
            "total": total,
            "success": success,
            "failures": failures,
            "success_rate": (success / total * 100.0) if total else 0.0,
            "avg_ms": (sum(latencies) / len(latencies)) if latencies else 0.0,
            "min_ms": latencies[0] if latencies else 0.0,
            "max_ms": latencies[-1] if latencies else 0.0,
            "p50_ms": pct(50),
            "p95_ms": pct(95),
            "p99_ms": pct(99),
            "errors": errors,
            "statuses": statuses,
        }
