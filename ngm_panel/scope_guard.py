"""Authorization scope guard.

Every command that talks to a host/URL must call :meth:`ScopeGuard.authorize`
first. Scope lives in ``allowed_targets.json`` (bundled defaults + the user's
copy in ``~/.ngm-panel``). Private / loopback / link-local addresses are blocked
unless ``allow_private_networks`` is true, and hard limits cap rate, concurrency
and duration of any load test.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config, net_utils


class ScopeError(RuntimeError):
    """Raised when a target is outside the authorized scope."""


@dataclass
class Target:
    host: str
    ports: Optional[List[int]] = None
    note: str = ""

    def allows_port(self, port: Optional[int]) -> bool:
        if port is None:
            return True
        if not self.ports:
            return True
        return int(port) in self.ports


@dataclass
class Limits:
    max_rps: float = 5.0
    max_concurrency: int = 20
    timeout_seconds: float = 5.0
    request_cap: int = 2000
    max_duration_seconds: float = 120.0


SCOPE_HELP = (
    "เพิ่มเป้าหมายที่คุณเป็นเจ้าของ/ได้รับอนุญาตก่อน:\n"
    "    ngm-panel scope add <host-or-domain> [--ports 80,443]\n"
    "หรือแก้ไฟล์: {path}"
)


def _parse_ports(value: Any) -> Optional[List[int]]:
    if value in (None, "", []):
        return None
    if isinstance(value, int):
        return [value]
    ports: List[int] = []
    for item in value if isinstance(value, (list, tuple)) else str(value).split(","):
        text = str(item).strip()
        if text.isdigit():
            port = int(text)
            if 0 < port < 65536:
                ports.append(port)
    return ports or None


class ScopeGuard:
    def __init__(
        self,
        targets: List[Target],
        limits: Optional[Limits] = None,
        allow_private: bool = True,
        require_confirmation: bool = True,
        auto_approve: bool = False,
        scope_path: Optional[str] = None,
    ) -> None:
        self.targets = targets
        self.limits = limits or Limits()
        self.allow_private = allow_private
        self.confirm_required = require_confirmation
        self.auto_approve = auto_approve
        self.scope_path = scope_path or str(config.user_scope_path())
        self._last_request = 0.0

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, auto_approve: bool = False) -> "ScopeGuard":
        path = config.ensure_user_scope()
        data = config.load_json(path)
        if not data.get("targets"):
            data = config.read_bundled_scope()
        limits_data = data.get("limits") or {}
        limits = Limits(
            max_rps=float(limits_data.get("max_rps", 5.0)),
            max_concurrency=int(limits_data.get("max_concurrency", 20)),
            timeout_seconds=float(limits_data.get("timeout_seconds", 5.0)),
            request_cap=int(limits_data.get("request_cap", 2000)),
            max_duration_seconds=float(limits_data.get("max_duration_seconds", 120.0)),
        )
        if limits.max_rps <= 0:
            limits.max_rps = 1.0
        targets: List[Target] = []
        for entry in data.get("targets", []):
            if isinstance(entry, str):
                targets.append(Target(host=entry.strip().lower()))
            elif isinstance(entry, dict) and entry.get("host"):
                targets.append(
                    Target(
                        host=str(entry["host"]).strip().lower(),
                        ports=_parse_ports(entry.get("ports")),
                        note=str(entry.get("note", "")),
                    )
                )
        return cls(
            targets=targets,
            limits=limits,
            allow_private=bool(data.get("allow_private_networks", True)),
            require_confirmation=bool(data.get("require_confirmation", True)),
            auto_approve=auto_approve,
            scope_path=str(path),
        )

    # --------------------------------------------------------------- checks
    @staticmethod
    def _host_matches(host: str, pattern: str) -> bool:
        pattern = pattern.strip().lower()
        if pattern == host:
            return True
        if pattern.startswith("*."):
            return host.endswith(pattern[1:])
        if "/" in pattern and net_utils.is_ip(host):
            return net_utils.ip_in_cidr(host, pattern)
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(host, pattern)
        return False

    def matching_targets(self, host: str) -> List[Target]:
        return [target for target in self.targets if self._host_matches(host, target.host)]

    def authorize(self, host_or_url: str, port: Optional[int] = None) -> str:
        """Validate a host against the scope and return the normalized host."""
        host = net_utils.normalize_host(host_or_url)
        if not host:
            raise ScopeError("ไม่ได้ระบุ host")
        matches = self.matching_targets(host)
        if not matches:
            raise ScopeError(
                f"'{host}' ไม่ได้อยู่ใน authorized scope\n" + SCOPE_HELP.format(path=self.scope_path)
            )
        if port is not None and not any(target.allows_port(port) for target in matches):
            allowed = sorted({p for target in matches for p in (target.ports or [])})
            raise ScopeError(
                f"พอร์ต {port} ไม่ได้รับอนุญาตสำหรับ '{host}' (อนุญาต: {', '.join(map(str, allowed)) or '-'})\n"
                + SCOPE_HELP.format(path=self.scope_path)
            )
        return host

    def check_ip(self, address: str) -> str:
        """Reject private/reserved addresses when the scope forbids them."""
        if self.allow_private:
            return address
        if net_utils.is_ip(address) and not net_utils.ip_is_public(address):
            raise ScopeError(
                f"IP {address} เป็น private/loopback/reserved และไฟล์ scope ตั้งค่า "
                "allow_private_networks=false"
            )
        return address

    def authorized_hosts(self) -> List[str]:
        return [target.host for target in self.targets]

    # ------------------------------------------------------- limits & gates
    def clamp_rps(self, requested: float) -> float:
        return max(0.1, min(float(requested), self.limits.max_rps))

    def clamp_concurrency(self, requested: int) -> int:
        return max(1, min(int(requested), self.limits.max_concurrency))

    def clamp_duration(self, requested: float) -> float:
        return max(0.5, min(float(requested), self.limits.max_duration_seconds))

    def clamp_timeout(self, requested: Optional[float]) -> float:
        if requested is None or requested <= 0:
            return self.limits.timeout_seconds
        return max(0.5, min(float(requested), 60.0))

    def enforce_request_cap(self, concurrency: int, duration: float, rps: float) -> int:
        estimate = int(rps * duration) if rps > 0 else 10**9
        return max(1, min(self.limits.request_cap, max(concurrency, estimate)))

    def require_confirmation(self, console, action: str, detail: str) -> bool:
        """Explicit human confirmation for active tests (skippable with --yes)."""
        console.blank()
        console.line(console.style("  ⚠  Authorized-scope confirmation", console.YELLOW))
        console.line("     " + action)
        console.line("     " + console.dim(detail))
        if self.auto_approve:
            console.sub("     auto-approved via --yes")
            return True
        if not console.is_tty:
            raise ScopeError("โหมด non-interactive ต้องยืนยันด้วย --yes ก่อนรัน load test")
        return console.confirm("ยืนยันว่าคุณได้รับอนุญาตให้ทดสอบเป้าหมายนี้?", default=False)

    # ------------------------------------------------------------- mutators
    def _scope_file(self) -> Path:
        path = Path(self.scope_path)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            bundled = config.read_bundled_scope() if path == config.user_scope_path() else {"version": 1, "targets": []}
            config.save_json(path, bundled)
        return path

    def add_target(self, host: str, ports: Optional[str] = None, note: str = "") -> Target:
        normalized = net_utils.normalize_host(host) or host.strip().lower()
        if not normalized:
            raise ScopeError("host ว่าง")
        path = self._scope_file()
        data = config.load_json(path)
        if not data.get("targets"):
            data["targets"] = []
        new_target = Target(host=normalized, ports=_parse_ports(ports), note=note)
        for entry in data["targets"]:
            entry_host = entry if isinstance(entry, str) else str(entry.get("host", ""))
            if entry_host.strip().lower() == normalized:
                raise ScopeError(f"'{normalized}' มีอยู่ใน scope แล้ว")
        payload: Dict[str, Any] = {"host": normalized}
        if new_target.ports:
            payload["ports"] = new_target.ports
        if note:
            payload["note"] = note
        data["targets"].append(payload)
        config.save_json(path, data)
        self.targets.append(new_target)
        return new_target

    def remove_target(self, host: str) -> bool:
        normalized = net_utils.normalize_host(host) or host.strip().lower()
        path = self._scope_file()
        data = config.load_json(path)
        before = len(data.get("targets", []))
        kept = []
        for entry in data.get("targets", []):
            entry_host = entry if isinstance(entry, str) else str(entry.get("host", ""))
            if entry_host.strip().lower() != normalized:
                kept.append(entry)
        data["targets"] = kept
        config.save_json(path, data)
        self.targets = [target for target in self.targets if target.host != normalized]
        return len(kept) != before

    def summary(self) -> Dict[str, Any]:
        return {
            "scope_file": self.scope_path,
            "targets": [
                {"host": t.host, "ports": t.ports, "note": t.note} for t in self.targets
            ],
            "limits": {
                "max_rps": self.limits.max_rps,
                "max_concurrency": self.limits.max_concurrency,
                "timeout_seconds": self.limits.timeout_seconds,
                "request_cap": self.limits.request_cap,
                "max_duration_seconds": self.limits.max_duration_seconds,
            },
            "allow_private_networks": self.allow_private,
        }
