"""Minimal DNS client (stdlib only) for A / AAAA / MX / TXT / NS / CNAME / SOA / PTR / SRV / CAA.

Why not dnspython? ngm-panel ships as a single .exe with zero runtime
dependencies: a compact wire-format client keeps that promise.
"""

from __future__ import annotations

import os
import random
import socket
import struct
from typing import Dict, List, Optional, Tuple

QTYPES: Dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "CAA": 257,
}

TYPE_NAMES = {value: key for key, value in QTYPES.items()}


class DnsError(RuntimeError):
    pass


def _system_resolver() -> Optional[str]:
    env = os.environ.get("NGM_PANEL_DNS")
    if env:
        return env
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return None


def _encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("idna") if any(ord(ch) > 127 for ch in label) else label.encode()
        if len(raw) > 63:
            raise DnsError(f"label too long: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    next_offset = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise DnsError("truncated DNS name")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 64:
                raise DnsError("DNS compression loop")
            continue
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        label = data[offset + 1 : offset + 1 + length]
        labels.append(label.decode("utf-8", "replace"))
        offset += 1 + length
        if not jumped:
            next_offset = offset
    return ".".join(labels), next_offset


def _parse_rdata(data: bytes, rtype: int, offset: int, rdlength: int, packet: bytes) -> str:
    end = offset + rdlength
    try:
        if rtype == 1 and rdlength == 4:
            return socket.inet_ntop(socket.AF_INET, data[offset:end])
        if rtype == 28 and rdlength == 16:
            return socket.inet_ntop(socket.AF_INET6, data[offset:end])
        if rtype in (2, 5, 12):
            name, _ = _read_name(packet, offset)
            return name
        if rtype == 15:
            preference = struct.unpack(">H", data[offset : offset + 2])[0]
            name, _ = _read_name(packet, offset + 2)
            return f"{preference} {name}"
        if rtype == 16:
            parts: List[str] = []
            cursor = offset
            while cursor < end:
                chunk_len = data[cursor]
                cursor += 1
                parts.append(data[cursor : cursor + chunk_len].decode("utf-8", "replace"))
                cursor += chunk_len
            return "".join(parts)
        if rtype == 6:
            mname, cursor = _read_name(packet, offset)
            rname, cursor = _read_name(packet, cursor)
            serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[cursor : cursor + 20])
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        if rtype == 33:
            priority, weight, port = struct.unpack(">HHH", data[offset : offset + 6])
            name, _ = _read_name(packet, offset + 6)
            return f"{priority} {weight} {port} {name}"
        if rtype == 257:
            flags = data[offset]
            tag_len = data[offset + 1]
            tag = data[offset + 2 : offset + 2 + tag_len].decode("ascii", "replace")
            value = data[offset + 2 + tag_len : end].decode("utf-8", "replace")
            return f'{flags} {tag} "{value}"'
    except (struct.error, IndexError):
        return "<unparsable>"
    return data[offset:end].hex()


def query(
    name: str,
    qtype: str = "A",
    server: Optional[str] = None,
    timeout: float = 5.0,
    port: int = 53,
) -> List[Dict[str, object]]:
    """Send one UDP query and return the answer records.

    Raises :class:`DnsError` on network or protocol failure.
    """
    qtype_key = qtype.upper()
    if qtype_key not in QTYPES:
        raise DnsError(f"unsupported record type: {qtype} (use {', '.join(QTYPES)})")
    resolved_server = server or _system_resolver() or "1.1.1.1"
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    packet = header + _encode_name(name) + struct.pack(">HH", QTYPES[qtype_key], 1)

    family = socket.AF_INET6 if ":" in resolved_server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (resolved_server, port))
            response, _ = sock.recvfrom(4096)
        except socket.timeout as exc:
            raise DnsError(f"timeout querying {resolved_server} for {name} {qtype_key}") from exc
        except OSError as exc:
            raise DnsError(f"{resolved_server}: {exc}") from exc

    if len(response) < 12:
        raise DnsError("short DNS response")
    resp_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", response[:12])
    if resp_id != query_id:
        raise DnsError("DNS transaction id mismatch")
    rcode = flags & 0x000F
    if rcode == 3:
        return []
    if rcode != 0:
        raise DnsError(f"DNS server returned rcode={rcode}")

    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(response, offset)
        offset += 4

    records: List[Dict[str, object]] = []
    for _ in range(ancount):
        owner, offset = _read_name(response, offset)
        if offset + 10 > len(response):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", response[offset : offset + 10])
        offset += 10
        value = _parse_rdata(response, rtype, offset, rdlength, response)
        offset += rdlength
        records.append(
            {
                "name": owner,
                "type": TYPE_NAMES.get(rtype, str(rtype)),
                "ttl": ttl,
                "value": value,
            }
        )
    return records


def resolve_name(name: str, qtype: str = "A") -> List[str]:
    """Convenience: A/AAAA records as plain strings via the system resolver."""
    if qtype.upper() in {"A", "AAAA"}:
        family = socket.AF_INET if qtype.upper() == "A" else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        seen: List[str] = []
        for info in infos:
            address = info[4][0]
            if address not in seen:
                seen.append(address)
        return seen
    return [str(record["value"]) for record in query(name, qtype)]
