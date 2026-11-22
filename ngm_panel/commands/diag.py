"""Diagnostics: ping, traceroute, HTTP timing breakdown, resolver checks, MTU."""

from __future__ import annotations

import socket
import ssl
import time
from typing import List

from .. import dnsmini, net_utils, system
from ..registry import Registry
from ..runner import parse_flags
from .common import authorize, resolve_checked

PORT_PROFILES = {
    "web": [80, 443, 8080, 8443],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "database": [1433, 1521, 3306, 5432, 6379, 27017],
    "remote": [22, 23, 3389, 5900],
    "windows": [135, 139, 445, 3389, 5985, 5986],
    "dev": [3000, 3001, 4200, 5000, 5173, 8000, 8080, 8888],
    "dns": [53, 853],
    "file": [21, 22, 139, 445, 2049],
    "container": [2375, 2376, 6443, 10250],
}


def ping_host(ctx, host: str, count: int = 4, size: int = 32) -> int:
    host = authorize(ctx, host)
    ctx.console.heading(f"Ping · {host} (count={count}, size={size})")
    if system.is_windows():
        args = ["ping", "-n", str(count), "-l", str(size), "-w", str(int(ctx.timeout() * 1000)), host]
    else:
        args = ["ping", "-c", str(count), "-s", str(size), "-W", str(max(1, int(ctx.timeout()))), host]
    if not system.have("ping"):
        ctx.console.warn("ไม่พบคำสั่ง ping ในเครื่อง")
        return 1
    output = system.run_text(args, timeout=count * (ctx.timeout() + 1) + 5)
    ctx.console.line(output or "(no output)")
    ctx.print_json({"host": host, "count": count, "size": size, "raw": output})
    return 0 if output else 1


def cmd_ping(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "diag.ping <host> [-c count]", "host")
    _, flags = parse_flags(argv[1:], {"c": "int", "count": "int"})
    count = int(flags.get("c") or flags.get("count") or 4)
    return ping_host(ctx, host, count=max(1, min(count, 20)))


def make_ping_size_command(size: int):
    def handler(ctx, argv: List[str]) -> int:
        host = ctx.need(argv, 0, f"diag.ping-size-{size} <host> [-c count]", "host")
        _, flags = parse_flags(argv[1:], {"c": "int"})
        return ping_host(ctx, host, count=int(flags.get("c") or 4), size=size)

    return handler


def cmd_traceroute(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "diag.traceroute <host>", "host")
    host = authorize(ctx, host)
    ctx.console.heading(f"Traceroute · {host}")
    if system.is_windows():
        args = ["tracert", "-h", "15", "-w", str(int(ctx.timeout() * 1000)), host]
    else:
        args = ["traceroute", "-m", "15", host] if system.have("traceroute") else ["tracepath", host]
    output = system.run_text(args, timeout=60)
    ctx.console.line(output or "(no output)")
    return 0 if output else 1


def cmd_dns_server(ctx, argv: List[str]) -> int:
    server = ctx.need(argv, 0, "diag.dns-server <resolver-ip> <name>", "resolver IP")
    name = ctx.need(argv, 1, "diag.dns-server <resolver-ip> <name>", "ชื่อโดเมน")
    authorize(ctx, name)
    ctx.console.heading(f"DNS via {server} · {name}")
    try:
        records = dnsmini.query(name, "A", server=server, timeout=ctx.timeout())
    except dnsmini.DnsError as exc:
        ctx.console.err(str(exc))
        return 1
    if not records:
        ctx.console.warn("ไม่พบ A record")
        return 1
    ctx.console.table(["Name", "TTL", "Value"], [[r["name"], r["ttl"], r["value"]] for r in records])
    return 0


def cmd_http_timing(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "diag.http-timing <url>", "URL")
    authorize(ctx, url)
    scheme, host, port, path = net_utils.split_url(url)
    ctx.console.heading(f"HTTP timing · {url}")

    start = time.perf_counter()
    addresses = resolve_checked(ctx, host)
    dns_ms = (time.perf_counter() - start) * 1000
    if not addresses:
        ctx.console.err("resolve DNS ไม่ได้")
        return 1
    address = addresses[0]

    start = time.perf_counter()
    try:
        raw = socket.create_connection((address, port), timeout=ctx.timeout())
    except OSError as exc:
        ctx.console.err(f"เชื่อมต่อไม่สำเร็จ: {exc}")
        return 1
    tcp_ms = (time.perf_counter() - start) * 1000

    tls_ms = 0.0
    stream = raw
    try:
        if scheme == "https":
            start = time.perf_counter()
            context = ssl.create_default_context()
            stream = context.wrap_socket(raw, server_hostname=host)
            tls_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {net_utils.USER_AGENT}\r\nConnection: close\r\n\r\n"
        stream.sendall(request.encode("ascii"))
        first = stream.recv(1)
        ttfb_ms = (time.perf_counter() - start) * 1000
        total_start = start
        stream.close()
    except (OSError, ssl.SSLError) as exc:
        ctx.console.err(f"request ไม่สำเร็จ: {exc}")
        raw.close()
        return 1
    finally:
        try:
            raw.close()
        except Exception:
            pass

    ctx.console.table(
        ["Phase", "Time"],
        [
            ["DNS resolution", f"{dns_ms:.1f} ms"],
            ["TCP connect", f"{tcp_ms:.1f} ms"],
            ["TLS handshake", f"{tls_ms:.1f} ms" if scheme == "https" else "-"],
            ["Time to first byte", f"{ttfb_ms:.1f} ms"],
            ["Total (to first byte)", f"{dns_ms + tcp_ms + tls_ms + ttfb_ms:.1f} ms"],
        ],
    )
    ctx.console.sub(f"IP: {address} · first byte: {'yes' if first else 'no'}")
    ctx.print_json(
        {
            "url": url, "ip": address, "dns_ms": dns_ms, "tcp_ms": tcp_ms,
            "tls_ms": tls_ms, "ttfb_ms": ttfb_ms,
        }
    )
    return 0


def cmd_mtu(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "diag.mtu <host>", "host")
    host = authorize(ctx, host)
    ctx.console.heading(f"Path MTU probe · {host}")
    sizes = [1500, 1472, 1460, 1400, 1300, 1200]
    best = None
    for size in sizes:
        payload = size - 28
        if system.is_windows():
            args = ["ping", "-n", "1", "-f", "-l", str(payload), "-w", "1500", host]
        else:
            args = ["ping", "-c", "1", "-M", "do", "-s", str(payload), "-W", "2", host]
        output = system.run_text(args, timeout=8).lower()
        success = ("reply from" in output or "bytes from" in output) and "fragmented" not in output
        ctx.console.line(f"  {size:>5} bytes  " + (ctx.console.green("OK") if success else ctx.console.dim("no")))
        if success and best is None:
            best = size
    if best:
        ctx.console.ok(f"MTU ที่น่าจะผ่าน: {best} (payload {best - 28})")
    else:
        ctx.console.warn("ตรวจ MTU ไม่สำเร็จ (ICMP อาจถูกบล็อก)")
    return 0


def cmd_port_profile(ctx, argv: List[str]) -> int:
    profile = ctx.need(argv, 0, "diag.port-profile <name> <host>", "ชื่อ profile").lower()
    host = ctx.need(argv, 1, "diag.port-profile <name> <host>", "host")
    if profile not in PORT_PROFILES:
        ctx.console.err(f"ไม่รู้จัก profile '{profile}' (มี: {', '.join(PORT_PROFILES)})")
        return 2
    from .net import check_ports

    ports = PORT_PROFILES[profile]
    ctx.console.heading(f"Profile {profile} · {host} · {len(ports)} ports")
    check_ports(ctx, host, ports)
    return 0


def register(registry: Registry) -> None:
    registry.add(cmd_ping, name="diag.ping", category="diag", usage="diag.ping <host> [-c count]",
                 description="ping ไปยัง host ที่ได้รับอนุญาต", danger="scope")
    registry.add(cmd_traceroute, name="diag.traceroute", category="diag", usage="diag.traceroute <host>",
                 description="trace เส้นทางเครือข่ายด้วย tracert/traceroute", danger="scope")
    registry.add(cmd_dns_server, name="diag.dns-server", category="diag",
                 usage="diag.dns-server <resolver-ip> <name>",
                 description="ทดสอบ resolver ที่ระบุด้วยคำถาม A record", danger="scope")
    registry.add(cmd_http_timing, name="diag.http-timing", category="diag", usage="diag.http-timing <url>",
                 description="แยกเวลาต่อ phase: DNS/TCP/TLS/TTFB", danger="scope")
    registry.add(cmd_mtu, name="diag.mtu", category="diag", usage="diag.mtu <host>",
                 description="ประมาณค่า Path MTU ด้วย ping แบบ DF", danger="scope")
    registry.add(cmd_port_profile, name="diag.port-profile", category="diag",
                 usage="diag.port-profile <name> <host>",
                 description=f"ตรวจกลุ่มพอร์ตสำเร็จรูป ({', '.join(PORT_PROFILES)})", danger="scope")
