"""Networking commands: DNS/IP lookups, TCP checks, local interfaces, listeners."""

from __future__ import annotations

import os
import socket
from typing import List

from .. import dnsmini, net_utils, system
from ..registry import Registry
from .common import authorize, human_bytes, listening_ports, pid_name, resolve_checked


def cmd_ip(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "net.ip <host>", "host")
    host = authorize(ctx, host)
    a_records = resolve_checked(ctx, host, "A")
    aaaa_records = resolve_checked(ctx, host, "AAAA")
    ctx.console.heading(f"IP addresses · {host}")
    ctx.console.table(
        ["Type", "Address", "Scope"],
        [[kind, address, "public" if net_utils.ip_is_public(address) else "private/reserved"]
         for kind, records in (("A", a_records), ("AAAA", aaaa_records)) for address in records],
    )
    if not a_records and not aaaa_records:
        ctx.console.warn("ไม่พบ A/AAAA record (ชื่ออาจไม่มีอยู่หรือ DNS ล่ม)")
    for address in (a_records + aaaa_records)[:3]:
        names = net_utils.reverse_dns(address, timeout=ctx.timeout())
        if names:
            ctx.console.sub(f"PTR {address} → {', '.join(names)}")
    ctx.print_json({"host": host, "A": a_records, "AAAA": aaaa_records})
    return 0


def cmd_dns(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "net.dns <name> [type] [--server IP]", "ชื่อโดเมน")
    record_type = (argv[1].upper() if len(argv) > 1 else "A")
    from ..runner import parse_flags

    _, flags = parse_flags(argv[2:], {"server": "str"})
    host = authorize(ctx, host)
    server = flags.get("server")
    ctx.console.heading(f"DNS {record_type} · {host}")
    try:
        if server is None and record_type in {"A", "AAAA"}:
            values = net_utils.resolve(host, record_type)
            records = [{"name": host, "type": record_type, "ttl": "-", "value": v} for v in values]
        else:
            records = dnsmini.query(host, record_type, server=str(server) if server else None, timeout=ctx.timeout())
    except dnsmini.DnsError as exc:
        ctx.console.err(str(exc))
        return 1
    if not records:
        ctx.console.warn("ไม่พบ record")
    else:
        ctx.console.table(
            ["Name", "Type", "TTL", "Value"],
            [[r["name"], r["type"], r["ttl"], r["value"]] for r in records],
        )
    ctx.print_json({"name": host, "type": record_type, "records": records})
    return 0


def port_list(raw: str) -> List[int]:
    ports: List[int] = []
    for chunk in raw.replace(" ", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            if start.isdigit() and end.isdigit():
                ports.extend(range(int(start), int(end) + 1))
            continue
        if chunk.isdigit():
            ports.append(int(chunk))
    return sorted({port for port in ports if 0 < port < 65536})


def check_ports(ctx, host: str, ports: List[int], allow_private_ok: bool = True) -> List[dict]:
    host = authorize(ctx, host)
    addresses = resolve_checked(ctx, host)
    connect_host = addresses[0] if addresses else host
    results = []
    for port in ports:
        result = net_utils.tcp_connect(connect_host, port, timeout=ctx.timeout())
        results.append(
            {"host": host, "ip": connect_host, "port": port, "open": result.ok,
             "latency_ms": round(result.latency_ms, 2), "error": result.error}
        )
        ctx.console.write(
            f"  {ctx.console.cyan(f'{host:<28}')} {connect_host:<39} :{port:<6} "
            + (ctx.console.green("OPEN ") if result.ok else ctx.console.red("CLOSED"))
            + f"  {result.latency_ms:7.1f} ms"
            + (f"  {ctx.console.dim(result.error)}" if result.error else "")
            + "\n"
        )
        ctx.console.flush()
    ctx.print_json({"target": host, "ip": connect_host, "results": results})
    return results


def cmd_tcp(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "net.tcp <host> <port[,port|range]>", "host")
    ports_raw = ctx.need(argv, 1, "net.tcp <host> <port[,port|range]>", "พอร์ต")
    ports = port_list(ports_raw)
    if not ports:
        ctx.console.err("รูปแบบพอร์ตไม่ถูกต้อง (ตัวอย่าง: 80,443,8000-8010)")
        return 2
    if len(ports) > 64:
        ctx.console.err("ตรวจได้สูงสุด 64 พอร์ตต่อครั้ง (ข้อจำกัดเพื่อความสุภาพ)")
        return 2
    ctx.console.heading(f"TCP connect · {host} ({len(ports)} ports)")
    results = check_ports(ctx, host, ports)
    open_ports = [r for r in results if r["open"]]
    ctx.blank()
    ctx.console.ok(f"เปิด {len(open_ports)}/{len(results)} พอร์ต")
    return 0


def cmd_reverse(ctx, argv: List[str]) -> int:
    address = ctx.need(argv, 0, "net.reverse <ip>", "IP")
    ctx.guard.check_ip(address) if net_utils.is_ip(address) else None
    ctx.console.heading(f"Reverse DNS · {address}")
    names = net_utils.reverse_dns(address, timeout=ctx.timeout())
    if names:
        for name in names:
            ctx.console.line("  " + name)
    else:
        ctx.console.warn("ไม่พบ PTR record")
    ctx.print_json({"ip": address, "names": names})
    return 0


def cmd_local(ctx, argv: List[str]) -> int:
    ctx.console.heading("Local network")
    hostname = socket.gethostname()
    ctx.console.keyvalue(
        [
            ("Hostname", hostname),
            ("FQDN", socket.getfqdn()),
            ("Platform", f"{system.is_windows() and 'Windows' or os.uname().sysname} / {os.name}"),
        ]
    )
    addresses = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
    except OSError as exc:
        ctx.console.warn(f"resolve local hostname ไม่ได้: {exc}")
    ctx.console.heading("Local addresses")
    ctx.console.table(
        ["Family", "Address"],
        [("IPv6" if ":" in address else "IPv4", address) for address in addresses],
    )
    try:
        interfaces = socket.if_nameindex()
    except OSError:
        interfaces = []
    if interfaces:
        ctx.console.heading("Interfaces")
        ctx.console.table(["Index", "Name"], [[index, name] for index, name in interfaces])
    ctx.print_json({"hostname": hostname, "addresses": addresses})
    return 0


def cmd_listen(ctx, argv: List[str]) -> int:
    ctx.console.heading("Listening TCP ports (local machine)")
    entries = listening_ports()
    if not entries:
        ctx.console.warn("อ่านรายการ listening ports ไม่ได้บนระบบนี้")
        return 1
    rows = []
    for entry in entries:
        port = entry["port"]
        rows.append([entry["address"] or "*", port, entry["proto"], entry["pid"], pid_name(entry["pid"])])
    ctx.console.table(["Address", "Port", "Proto", "PID", "Process"], sorted(rows, key=lambda row: int(row[1]) if row[1].isdigit() else 0))
    ctx.print_json({"listening": entries})
    return 0


def cmd_tls(ctx, argv: List[str]) -> int:
    host = ctx.need(argv, 0, "net.tls <host> [port]", "host")
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 443
    host = authorize(ctx, host, port)
    ctx.console.heading(f"TLS certificate · {host}:{port}")
    info = net_utils.tls_inspect(host, port, timeout=ctx.timeout())
    if not info.ok:
        ctx.console.err(info.error or "เชื่อมต่อ TLS ไม่ได้")
        return 1
    days = info.days_left()
    ctx.console.keyvalue(
        [
            ("Protocol", info.version),
            ("Cipher", info.cipher),
            ("Verified", "yes" if info.verified else "NO — certificate problem"),
            ("Subject", info.subject),
            ("Issuer", info.issuer),
            ("Valid from", info.not_before),
            ("Valid until", f"{info.not_after} ({days} days left)" if days is not None else info.not_after),
        ]
    )
    if info.subject_alt_names:
        ctx.console.heading("Subject alternative names")
        ctx.console.line("  " + ", ".join(info.subject_alt_names[:20]))
    if days is not None and days < 0:
        ctx.console.err("ใบรับรองหมดอายุแล้ว")
    elif days is not None and days < 14:
        ctx.console.warn(f"ใบรับรองใกล้หมดอายุใน {days} วัน")
    ctx.print_json(
        {
            "host": host, "port": port, "protocol": info.version, "cipher": info.cipher,
            "verified": info.verified, "subject": info.subject, "issuer": info.issuer,
            "not_before": info.not_before, "not_after": info.not_after,
            "days_left": days, "san": info.subject_alt_names,
        }
    )
    return 0


def make_port_command(port: int, service: str = ""):
    def handler(ctx, argv: List[str]) -> int:
        host = ctx.need(argv, 0, f"net.tcp-{port} <host>", "host")
        ctx.console.heading(f"TCP {port}{(' · ' + service) if service else ''} · {host}")
        check_ports(ctx, host, [port])
        return 0

    return handler


def register(registry: Registry) -> None:
    registry.add(cmd_ip, name="net.ip", category="net", usage="net.ip <host>",
                 description="แปลงโดเมนเป็น A/AAAA และตรวจ PTR", danger="scope")
    registry.add(cmd_dns, name="net.dns", category="net", usage="net.dns <name> [A|AAAA|MX|TXT|NS|CNAME|SOA|PTR|SRV|CAA] [--server IP]",
                 description="สอบถาม DNS record ผ่าน UDP ตรงไปยัง resolver", danger="scope")
    registry.add(cmd_tcp, name="net.tcp", category="net", usage="net.tcp <host> <port[,port|range]>",
                 description="ตรวจสถานะพอร์ต TCP พร้อม latency (สูงสุด 64 พอร์ต/ครั้ง)", danger="scope",
                 examples=("net.tcp example.com 80,443", "net.tcp 127.0.0.1 8000-8010"))
    registry.add(cmd_reverse, name="net.reverse", category="net", usage="net.reverse <ip>",
                 description="ค้นหา PTR record ของ IP", danger="scope")
    registry.add(cmd_local, name="net.local", category="net", usage="net.local",
                 description="แสดงชื่อเครื่อง ที่อยู่ IP และ network interface ภายในเครื่อง")
    registry.add(cmd_listen, name="net.listen", category="net", usage="net.listen",
                 description="แสดงพอร์ต TCP ที่เปิดรับการเชื่อมต่อในเครื่อง พร้อม PID/process")
    registry.add(cmd_tls, name="net.tls", category="net", usage="net.tls <host> [port]",
                 description="ตรวจใบรับรอง TLS/SSL เบื้องต้น (protocol, cipher, อายุ)", danger="scope")
