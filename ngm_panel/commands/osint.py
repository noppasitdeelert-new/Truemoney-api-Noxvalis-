"""OSINT commands: passive research helpers that run entirely on your machine.

Design rules
------------
* Building links, parsing identifiers, hashing, EXIF/PDF metadata, JWT/UA
  decoding and phone/TLD normalisation are **offline** and always available.
* Anything that actually contacts a third party only happens with an explicit
  flag (``--check``, ``--rdap``) and still goes through the Authorization Guard,
  so a host must be in ``allowed_targets.json`` first.
* Nothing is uploaded to ngm-panel: there is no central service.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import struct
import time
import urllib.parse
import uuid
from typing import Dict, List, Optional, Tuple

from .. import net_utils
from ..registry import Registry, UsageError
from ..runner import parse_flags
from ..scope_guard import ScopeError
from .. import osint_data as data
from .. import osint_platforms as platforms
from .. import osint_sources as sources
from .. import osint_tools as tools

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

MAGIC = [
    (b"\xff\xd8\xff", "JPEG image", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "image/png"),
    (b"GIF87a", "GIF image", "image/gif"),
    (b"GIF89a", "GIF image", "image/gif"),
    (b"%PDF-", "PDF document", "application/pdf"),
    (b"PK\x03\x04", "ZIP / OOXML / APK / JAR", "application/zip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar"),
    (b"\x1f\x8b", "Gzip stream", "application/gzip"),
    (b"BZh", "Bzip2 archive", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "XZ archive", "application/x-xz"),
    (b"SQLite format 3\x00", "SQLite database", "application/vnd.sqlite3"),
    (b"\x7fELF", "ELF executable", "application/x-elf"),
    (b"MZ", "PE executable (Windows)", "application/vnd.microsoft.portable-executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class", "application/octet-stream"),
    (b"OggS", "Ogg container", "application/ogg"),
    (b"fLaC", "FLAC audio", "audio/flac"),
    (b"ID3", "MP3 audio", "audio/mpeg"),
    (b"\x1aE\xdf\xa3", "Matroska / WebM", "video/x-matroska"),
    (b"wOFF", "WOFF font", "font/woff"),
    (b"wOF2", "WOFF2 font", "font/woff2"),
    (b"\x00\x01\x00\x00", "TrueType font", "font/ttf"),
    (b"OTTO", "OpenType font", "font/otf"),
]


# --------------------------------------------------------------------- helpers
def _links(ctx, title: str, rows: List[Tuple[str, str]], empty: str = "ไม่มีรายการ") -> None:
    ctx.console.heading(title)
    if not rows:
        ctx.console.warn(empty)
        return
    for label, url in rows:
        ctx.console.line("  " + ctx.console.cyan(str(label).ljust(18 if not _narrow() else len(str(label)))) + "  " + url)


def _narrow() -> bool:
    from ..console import narrow

    return narrow()


def _clean(value: str) -> str:
    return urllib.parse.quote(str(value).strip(), safe="")


def _in_scope(ctx, url: str) -> bool:
    try:
        ctx.guard.authorize(url)
        return True
    except ScopeError:
        return False


def _fetch_json(ctx, url: str, max_body: int = 65536):
    result = net_utils.http_request(url, timeout=ctx.timeout(), max_body=max_body,
                                    extra_headers={"Accept": "application/rdap+json, application/json"})
    if not result.ok:
        return None, result
    try:
        return json.loads(result.body.decode("utf-8", "replace")), result
    except ValueError:
        return None, result


def _digest(algorithm: str, payload: bytes) -> str:
    try:
        func = getattr(hashlib, algorithm)
    except AttributeError:
        return ""
    try:
        if algorithm.startswith("shake_"):
            return func(payload).hexdigest(32)
        return func(payload).hexdigest()
    except (ValueError, TypeError):
        return ""


def _country_by_tld(tld: str):
    tld = tld.lower().lstrip(".")
    for row in data.COUNTRY_ROWS:
        if len(row) >= 4 and row[3].lower() == tld:
            return row
    return None


def _country_by_dial(text: str):
    best = None
    for row in data.COUNTRY_ROWS:
        if len(row) >= 3 and text.startswith(row[2]) and (best is None or len(row[2]) > len(best[2])):
            best = row
    return best


# ----------------------------------------------------------------------- about
def cmd_about(ctx, argv: List[str]) -> int:
    rows = [
        ("Username platforms", len(platforms.USERNAME_PLATFORMS)),
        ("Email providers", len(data.EMAIL_TEXT.split())),
        ("Domains (gTLD + ccTLD)", len(data.GTLD_TEXT.split()) + len(data.COUNTRY_ROWS)),
        ("Dork recipes", len(data.DORK_ENGINES) * len(data.DORK_TOPICS)),
        ("IP intelligence services", len(sources.IP_SERVICES)),
        ("Country profiles", len(data.COUNTRY_ROWS)),
        ("Phone formats", len(data.COUNTRY_ROWS)),
        ("Blockchain explorers", len(sources.CRYPTO_CHAINS)),
        ("User-agent presets", len(data.UA_BROWSERS) * len(data.UA_PLATFORMS)),
        ("File/EXIF formats", len(data.META_FORMATS) + len(tools.EXIF_TAGS)),
        ("OSINT tools", len(tools.OSINT_TOOLS)),
        ("Public data sources", len(tools.DATA_SOURCES)),
        ("Subdomain sources", len(data.SUBDOMAIN_SOURCES)),
        ("Breach/intel sources", len(data.BREACH_SOURCES)),
        ("Hash algorithms", len(data.HASH_ALGORITHMS)),
    ]
    ctx.console.heading("OSINT coverage (offline tables)")
    ctx.console.table(["Dataset", "Entries"], rows)
    total = sum(count for _, count in rows)
    ctx.console.blank()
    ctx.console.ok(f"รวม {total} รายการอ้างอิง + คำสั่ง hand-written")
    ctx.console.heading("หลักการ")
    ctx.console.line("  • สร้างลิงก์/วิเคราะห์ในเครื่องก่อน — ไม่มีข้อมูลส่งออกไปที่ใด")
    ctx.console.line("  • คำสั่งที่ยิงเน็ตจริงต้องมี --check/--rdap และ host ต้องอยู่ใน authorized scope")
    ctx.console.line("  • ใช้กับเป้าหมายที่คุณได้รับอนุญาต หรือข้อมูลสาธารณะเท่านั้น")
    ctx.console.sub("ดูทั้งหมด: help osint · แยกหมวด: help osint.username / osint.dork / osint.tool")
    ctx.print_json({"datasets": {name: count for name, count in rows}, "total": total})
    return 0


# -------------------------------------------------------------------- username
def cmd_username(ctx, argv: List[str]) -> int:
    positionals, flags = parse_flags(argv, {"check": "bool", "limit": "int", "all": "bool"})
    username = ctx.need(positionals, 0, "osint.username <username> [--check] [--limit N]", "username")
    if not USERNAME_RE.match(username):
        ctx.console.err("username ควรเป็น A-Z a-z 0-9 . _ - ความยาว 1-64")
        return 2
    limit = int(flags.get("limit", 0 if flags.get("all") else 30))
    selected = platforms.USERNAME_PLATFORMS if limit <= 0 else platforms.USERNAME_PLATFORMS[:limit]
    ctx.console.heading(f"Username · {username} · {len(selected)}/{len(platforms.USERNAME_PLATFORMS)} platforms")
    checked = 0
    found = 0
    skipped = 0
    results = []
    for slug, name, template in selected:
        url = template.replace("{u}", username)
        status = ""
        if flags.get("check"):
            if _in_scope(ctx, url):
                check = net_utils.http_request(url, method="HEAD", timeout=ctx.timeout(), max_body=512)
                checked += 1
                if check.ok and check.status < 400:
                    status = "FOUND"
                    found += 1
                elif check.ok:
                    status = f"HTTP {check.status}"
                else:
                    status = "error"
            else:
                status = "skipped (นอก scope)"
                skipped += 1
        results.append({"platform": slug, "name": name, "url": url, "status": status})
        suffix = ""
        if status == "FOUND":
            suffix = "  " + ctx.console.green("[FOUND]")
        elif status:
            suffix = "  " + ctx.console.dim(f"[{status}]")
        ctx.console.line("  " + _pad(name, 22) + " " + url + suffix)
    ctx.blank()
    if flags.get("check"):
        ctx.console.ok(f"ตรวจ {checked} Host · พบ {found} · ข้าม {skipped} (เพิ่ม host ด้วย scope add)")
        ctx.console.sub("ผล HEAD อาจเป็น false positive/negative — เปิดลิงก์ยืนยันด้วยตาอีกครั้ง")
    else:
        ctx.console.sub("ยังไม่ยิงเน็ต: เพิ่ม --check เพื่อทดสอบเฉพาะ host ที่อยู่ใน scope")
    ctx.print_json({"username": username, "results": results})
    return 0


def make_username_command(name: str, template: str):
    def handler(ctx, argv: List[str]) -> int:
        username = ctx.need(argv, 0, f"osint.username-{name.lower().replace(' ', '-')} <username>", "username")
        if not USERNAME_RE.match(username):
            ctx.console.err("username ควรเป็น A-Z a-z 0-9 . _ -")
            return 2
        url = template.replace("{u}", username)
        ctx.console.heading(f"{name} · {username}")
        ctx.console.link("Profile", url)
        if "--check" in argv or ctx.options.yes:
            if _in_scope(ctx, url):
                result = net_utils.http_request(url, method="HEAD", timeout=ctx.timeout(), max_body=512)
                state = "FOUND" if (result.ok and result.status < 400) else (
                    f"HTTP {result.status}" if result.ok else "error")
                (ctx.console.ok if state == "FOUND" else ctx.console.warn)(f"{name}: {state}")
            else:
                ctx.console.warn("host นี้ไม่อยู่ใน authorized scope — สร้างลิงก์ให้เท่านั้น")
        ctx.print_json({"platform": name, "username": username, "url": url})
        return 0

    return handler


def _pad(text: str, width: int) -> str:
    return text if len(text) >= width else text + " " * (width - len(text))


# ----------------------------------------------------------------------- email
def cmd_email(ctx, argv: List[str]) -> int:
    address = ctx.need(argv, 0, "osint.email <address>", "อีเมล")
    if not EMAIL_RE.match(address):
        ctx.console.err("รูปแบบอีเมลไม่ถูกต้อง")
        return 2
    local, _, domain = address.rpartition("@")
    domain = domain.lower()
    hashed = hashlib.md5(address.strip().lower().encode("utf-8")).hexdigest()
    provider = domain
    disposable = domain in {
        "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org", "yopmail.com",
        "sharklasers.com", "trashmail.com", "maildrop.cc", "getnada.com", "tempmail.net",
        "fakeinbox.com", "disroot.org", "mailnesia.com",
    }
    ctx.console.heading(f"Email · {address}")
    ctx.console.keyvalue(
        [
            ("Local part", local),
            ("Domain", domain),
            ("Provider", provider),
            ("Disposable", "yes" if disposable else "no (ตามรายการที่ฝังไว้)"),
            ("Gravatar hash", hashed),
            ("Gravatar", f"https://gravatar.com/{hashed}"),
        ]
    )
    mx: List[str] = []
    if _in_scope(ctx, domain):
        try:
            from .. import dnsmini

            mx = [record["value"] for record in dnsmini.query(domain, "MX", timeout=ctx.timeout())]
        except Exception as exc:  # DNS is best effort here
            ctx.console.warn(f"MX lookup ไม่สำเร็จ: {exc}")
    else:
        ctx.console.sub("MX lookup ข้าม: โดเมนนี้ไม่อยู่ใน scope (เพิ่มด้วย scope add " + domain + ")")
    if mx:
        ctx.console.heading("MX records")
        for host in mx:
            ctx.console.line("  " + host)
    _links(
        ctx,
        "Account / breach checks (เปิดในเบราว์เซอร์)",
        [
            ("Have I Been Pwned", f"https://haveibeenpwned.com/account/{urllib.parse.quote(address)}"),
            ("HIBP passwords", f"https://haveibeenpwned.com/Passwords"),
            ("DeHashed", f"https://dehashed.com/search?query={urllib.parse.quote(address)}"),
            ("LeakCheck", "https://leakcheck.io/"),
            ("Epieos", f"https://epieos.com/?q={urllib.parse.quote(address)}"),
            ("Hunter.io", f"https://hunter.io/search/{domain}"),
            ("EmailRep", f"https://emailrep.io/{urllib.parse.quote(address)}"),
            ("Google", "https://www.google.com/search?q=" + urllib.parse.quote(f'"{address}"')),
            ("Gravatar", f"https://gravatar.com/{hashed}"),
            ("Password reset", f"https://www.google.com/search?q=" + urllib.parse.quote(f"{domain} password reset")),
        ],
    )
    ctx.console.heading("แนะนำการยืนยัน")
    ctx.console.line("  1) ส่งอีเมลทดสอบไปที่อยู่นี้แล้วดู bounce (เฉพาะเมื่อได้รับอนุญาต)")
    ctx.console.line("  2) ตรวจ MX/SPF/DMARC ของโดเมนด้วย: osint.domain " + domain)
    ctx.console.line("  3) อย่าส่งรหัสผ่านหรือข้อมูลส่วนตัวเข้าเว็บตรวจ breach ที่ไม่น่าเชื่อถือ")
    ctx.print_json(
        {
            "email": address, "local": local, "domain": domain, "disposable": disposable,
            "gravatar_md5": hashed, "mx": mx,
        }
    )
    return 0


def make_email_command(domain: str):
    def handler(ctx, argv: List[str]) -> int:
        local = ctx.need(argv, 0, f"osint.email-{domain.replace('.', '-')} <local-part>", "ชื่อก่อน @")
        if not re.match(r"^[A-Za-z0-9._%+\-]{1,64}$", local):
            ctx.console.err("local-part ไม่ถูกต้อง")
            return 2
        address = f"{local}@{domain}"
        ctx.console.heading(f"{domain} · {address}")
        ctx.console.keyvalue(
            [
                ("Email", address),
                ("Webmail", f"https://{domain}"),
                ("Login", f"https://{domain}/login"),
                ("Password reset", f"https://{domain}/password/reset"),
                ("Account recovery", f"https://{domain}/account/recovery"),
                ("Gravatar", f"https://gravatar.com/{hashlib.md5(address.lower().encode()).hexdigest()}"),
                ("HIBP", f"https://haveibeenpwned.com/account/{urllib.parse.quote(address)}"),
                ("MX target", domain),
            ]
        )
        ctx.console.sub("ลิงก์ login/reset เป็นรูปแบบทั่วไปของผู้ให้บริการ — ตรวจ path จริงก่อนใช้")
        ctx.print_json({"provider": domain, "email": address,
                        "links": {"webmail": f"https://{domain}", "hibp":
                                  f"https://haveibeenpwned.com/account/{urllib.parse.quote(address)}"}})
        return 0

    return handler


# ---------------------------------------------------------------------- domain
def cmd_domain(ctx, argv: List[str]) -> int:
    positionals, flags = parse_flags(argv, {"rdap": "bool"})
    raw = ctx.need(positionals, 0, "osint.domain <domain> [--rdap]", "โดเมน")
    domain = net_utils.normalize_host(raw)
    if "." not in domain or not re.match(r"^[a-z0-9.\-]+$", domain):
        ctx.console.err("รูปแบบโดเมนไม่ถูกต้อง")
        return 2
    labels = domain.split(".")
    tld = labels[-1]
    country = _country_by_tld(tld)
    ctx.console.heading(f"Domain · {domain}")
    ctx.console.keyvalue(
        [
            ("Length", len(domain)),
            ("Labels", " · ".join(labels)),
            ("TLD", "." + tld + (f" ({country[1]})" if country else " (generic / new gTLD)")),
            ("ccTLD", "yes" if country else "no"),
            ("IDN (punycode)", domain.encode("idna").decode("ascii") if domain.isascii() else "-"),
        ]
    )
    ctx.console.heading("Registered-name candidates")
    for label in labels[:-1]:
        ctx.console.line(f"  {label:<24} osint.username-{label[:16]} {label}")
    _links(
        ctx,
        "Passive lookup",
        [
            ("RDAP", f"https://rdap.org/domain/{domain}"),
            ("IANA TLD", f"https://www.iana.org/domains/root/db/{tld}.html"),
            ("ICANN lookup", f"https://lookup.icann.org/en/lookup?name={domain}"),
            ("Whois", f"https://www.whois.com/whois/{domain}"),
            ("DNS", f"https://dns.google/query?name={domain}&type=A"),
            ("crt.sh", f"https://crt.sh/?q=%25.{domain}"),
            ("urlscan", f"https://urlscan.io/domain/{domain}"),
            ("Shodan", f"https://www.shodan.io/search?query=hostname%3A{domain}"),
            ("SecurityTrails", f"https://securitytrails.com/domain/{domain}/dns"),
            ("Wayback", f"https://web.archive.org/web/*/{domain}"),
            ("Google", "https://www.google.com/search?q=" + urllib.parse.quote(f"site:{domain}")),
        ],
    )
    if flags.get("rdap"):
        if not _in_scope(ctx, "https://rdap.org/domain/" + domain):
            ctx.console.warn("--rdap ต้องมี rdap.org อยู่ใน scope: ngm-panel scope add rdap.org --ports 443")
        else:
            payload, result = _fetch_json(ctx, f"https://rdap.org/domain/{domain}")
            ctx.console.heading("RDAP response")
            if payload is None:
                ctx.console.err(f"RDAP ล้มเหลว: {result.error or result.status}")
            else:
                events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events", [])}
                ctx.console.keyvalue(
                    [
                        ("Handle", payload.get("handle", "-")),
                        ("Status", ", ".join(payload.get("status", [])) or "-"),
                        ("Registrar", ", ".join(
                            entity.get("vcardArray", [None, []])[1][1][3]
                            for entity in payload.get("entities", [])
                            if entity.get("roles") == ["registrar"] and len(entity.get("vcardArray", [])) == 2
                            and len(entity["vcardArray"][1]) > 1) or "-"),
                        ("Registered", events.get("registration", "-")),
                        ("Expires", events.get("expiration", "-")),
                        ("Updated", events.get("last changed", "-")),
                        ("Nameservers", ", ".join(server.get("ldhName", "") for server in payload.get("nameservers", [])) or "-"),
                    ]
                )
                ctx.print_json(payload)
    return 0


def make_domain_command(tld: str, name: str = "", country: str = ""):
    def handler(ctx, argv: List[str]) -> int:
        label = ctx.need(argv, 0, f"osint.domain-{tld} <name>", "ชื่อโดเมน (ไม่ต้องมี ." + tld + ")")
        label = label.strip().rstrip(".")
        domain = label if label.lower().endswith("." + tld) else f"{label}.{tld}"
        if not re.match(r"^[a-z0-9.\-]+$", domain.lower()):
            ctx.console.err("ชื่อโดเมนไม่ถูกต้อง")
            return 2
        ctx.console.heading(f"{'.' + tld} · {domain}" + (f" · {country}" if country else ""))
        _links(
            ctx,
            "Lookup",
            [
                ("RDAP", f"https://rdap.org/domain/{domain}"),
                ("IANA", f"https://www.iana.org/domains/root/db/{tld}.html"),
                ("Whois", f"https://www.whois.com/whois/{domain}"),
                ("DNS A", f"https://dns.google/query?name={domain}&type=A"),
                ("DNS MX", f"https://dns.google/query?name={domain}&type=MX"),
                ("DNS TXT", f"https://dns.google/query?name={domain}&type=TXT"),
                ("crt.sh", f"https://crt.sh/?q=%25.{domain}"),
                ("Wayback", f"https://web.archive.org/web/*/{domain}"),
            ],
        )
        if country:
            ctx.console.sub(f"ccTLD ของ {country}: ข้อกำหนดการจดทะเบียนขึ้นกับ registry ท้องถิ่น")
        ctx.print_json({"domain": domain, "tld": tld, "country": country})
        return 0

    return handler


# -------------------------------------------------------------------------- ip
def cmd_ip(ctx, argv: List[str]) -> int:
    value = ctx.need(argv, 0, "osint.ip <ip>", "IP address")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        ctx.console.err("IP ไม่ถูกต้อง")
        return 2
    ctx.guard.check_ip(str(address))
    network = ipaddress.ip_network(f"{address}/24", strict=False) if address.version == 4 else None
    ctx.console.heading(f"IP intelligence · {address}")
    ctx.console.keyvalue(
        [
            ("Version", f"IPv{address.version}"),
            ("Scope", "public" if address.is_global else "private/reserved"),
            ("Integer", int(address)),
            ("Hex", hex(int(address))),
            ("Reverse name", f"{address.reverse_pointer}"),
            ("/24 network", str(network) if network else "-"),
            ("Multicast", "yes" if address.is_multicast else "no"),
            ("Loopback", "yes" if address.is_loopback else "no"),
        ]
    )
    names = net_utils.reverse_dns(str(address), timeout=ctx.timeout())
    if names:
        ctx.console.line(f"  {'PTR':<16}  {', '.join(names)}")
    encoded = urllib.parse.quote(str(address))
    _links(
        ctx,
        "Services",
        [
            ("Shodan", f"https://www.shodan.io/host/{encoded}"),
            ("Censys", f"https://search.censys.io/hosts/{encoded}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{encoded}"),
            ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{encoded}"),
            ("GreyNoise", f"https://viz.greynoise.io/query/{encoded}"),
            ("IPinfo", f"https://ipinfo.io/{encoded}"),
            ("BGPView", f"https://bgpview.io/ip/{encoded}"),
            ("RDAP", f"https://rdap.org/ip/{encoded}"),
            ("urlscan", f"https://urlscan.io/ip/{encoded}"),
            ("MxToolbox", f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{encoded}"),
        ],
    )
    ctx.print_json({"ip": str(address), "version": address.version, "public": address.is_global,
                    "int": int(address), "ptr": names, "reverse": address.reverse_pointer})
    return 0


def make_ip_command(slug: str, name: str, template: str):
    def handler(ctx, argv: List[str]) -> int:
        query = ctx.need(argv, 0, f"osint.ip-{slug} <ip|domain|asn>", "ค่าเป้าหมาย")
        url = template.replace("{q}", urllib.parse.quote(query.strip()))
        ctx.console.heading(f"{name} · {query}")
        ctx.console.link("Lookup", url)
        ctx.console.sub("เปิดในเบราว์เซอร์ หรือใช้ curl เองเมื่อคุณมีสิทธิ์เข้าถึง API")
        ctx.print_json({"service": name, "query": query, "url": url})
        return 0

    return handler


# ------------------------------------------------------------------------ hash
def cmd_hash(ctx, argv: List[str]) -> int:
    text = " ".join(argv).strip()
    if not text:
        ctx.console.err("usage: osint.hash <text> [--json]")
        return 2
    payload = text.encode("utf-8")
    rows = []
    for algorithm in data.HASH_ALGORITHMS:
        digest = _digest(algorithm, payload)
        if digest:
            rows.append([algorithm, digest])
    ctx.console.heading(f"Hashes · {len(text)} chars")
    ctx.console.table(["Algorithm", "Digest"], rows)
    ctx.console.line("  " + ctx.console.bold("Base64") + "          " + base64.b64encode(payload).decode())
    ctx.console.line("  " + ctx.console.bold("Base64URL") + "       " + base64.urlsafe_b64encode(payload).decode())
    ctx.console.line("  " + ctx.console.bold("Base32") + "          " + base64.b32encode(payload).decode())
    ctx.console.heading("Links")
    ctx.console.line("  CrackStation     https://crackstation.net/")
    ctx.console.line("  Hashes.com       https://hashes.com/en/decrypt/hash")
    ctx.print_json({"input": text, "hashes": {row[0]: row[1] for row in rows},
                    "base64": base64.b64encode(payload).decode()})
    return 0


def cmd_identify_hash(ctx, argv: List[str]) -> int:
    value = ctx.need(argv, 0, "osint.identify-hash <hash>", "ค่า hash").strip()
    candidates: List[Tuple[str, str]] = []
    if re.match(r"^[a-fA-F0-9]+$", value):
        length_map = {
            8: "CRC-32 / FNV-1a-32", 16: "MySQL323 / CRC-64", 32: "MD5 / NTLM / MD4",
            40: "SHA-1 / MySQL5 / RIPEMD-160", 56: "SHA-224 / SHA3-224",
            64: "SHA-256 / SHA3-256 / BLAKE2s", 96: "SHA-384 / SHA3-384",
            128: "SHA-512 / SHA3-512 / BLAKE2b / Whirlpool",
        }
        candidates.append((length_map.get(len(value), f"hex ยาว {len(value)}"), "hex"))
    if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
        candidates.append(("bcrypt", "crypt"))
    if value.startswith("$argon2"):
        candidates.append(("Argon2 (i/d/id)", "crypt"))
    if value.startswith("$1$"):
        candidates.append(("md5crypt", "crypt"))
    if value.startswith("$5$"):
        candidates.append(("sha256crypt", "crypt"))
    if value.startswith("$6$"):
        candidates.append(("sha512crypt", "crypt"))
    if value.startswith("$y$"):
        candidates.append(("yescrypt", "crypt"))
    if value.startswith("{SSHA}") or value.startswith("{SHA}"):
        candidates.append(("LDAP SSHA/SHA", "ldap"))
    if value.startswith("eyJ"):
        candidates.append(("JWT (base64url JSON)", "token"))
    if not candidates:
        ctx.console.warn("ระบุชนิดไม่ได้จากรูปแบบ")
        ctx.console.sub("ลองใช้: hashid, haiti หรือแจกแจงด้วย osint.hash")
        return 1
    ctx.console.heading(f"Hash identification · {len(value)} chars")
    ctx.console.table(["Candidate", "Family"], [[name, family] for name, family in candidates])
    ctx.console.sub("ความยาวซ้ำกันหลายอัลกอริทึม — ต้องทดสอบกับ hash ที่รู้คำตอบจึงยืนยันได้")
    ctx.print_json({"hash": value, "candidates": [{"name": n, "family": f} for n, f in candidates]})
    return 0


def make_hash_command(algorithm: str):
    def handler(ctx, argv: List[str]) -> int:
        text = " ".join(argv).strip()
        if not text:
            raise UsageError(f"usage: osint.hash-{algorithm} <text>")
        digest = _digest(algorithm, text.encode("utf-8"))
        if not digest:
            ctx.console.err(f"Python build นี้ไม่มี {algorithm}")
            return 1
        ctx.console.heading(f"{algorithm} · {len(text)} chars")
        ctx.console.line("  " + digest)
        ctx.print_json({"algorithm": algorithm, "input": text, "digest": digest})
        return 0

    return handler


# ------------------------------------------------------------------------- jwt
def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def cmd_jwt(ctx, argv: List[str]) -> int:
    token = ctx.need(argv, 0, "osint.jwt <token>", "JWT")
    parts = token.split(".")
    if len(parts) < 2:
        ctx.console.err("ไม่ใช่ JWT (ต้องมีอย่างน้อย header.payload)")
        return 2
    decoded = []
    for segment in parts[:2]:
        try:
            decoded.append(json.loads(_b64url_decode(segment).decode("utf-8", "replace")))
        except (binascii.Error, ValueError) as exc:
            ctx.console.err(f"decode ไม่ได้: {exc}")
            return 1
    header, payload = decoded[0], decoded[1]
    ctx.console.heading("JWT · header")
    ctx.console.keyvalue([(key, json.dumps(value, ensure_ascii=False)) for key, value in header.items()])
    ctx.console.heading("JWT · payload")
    for key, value in payload.items():
        rendered = value
        if key in {"exp", "iat", "nbf", "auth_time"} and isinstance(value, (int, float)):
            rendered = f"{value} ({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(value))})"
        ctx.console.line(f"  {ctx.console.cyan(str(key).ljust(16))}  {rendered}")
    warnings = []
    if str(header.get("alg", "")).lower() == "none":
        warnings.append("alg=none — token ไม่มีลายเซ็น ( 매우อันตราย)")
    if "exp" in payload and isinstance(payload["exp"], (int, float)) and payload["exp"] < time.time():
        warnings.append("token หมดอายุแล้ว")
    if any(key.lower() in {"password", "secret", "token", "api_key"} for key in payload):
        warnings.append("payload มี field ที่อาจเป็นความลับ — JWT ไม่ได้เข้ารหัส")
    if len(parts) == 2:
        warnings.append("ไม่มี signature segment")
    ctx.console.heading("Notes")
    if warnings:
        for warning in warnings:
            ctx.console.warn(warning)
    else:
        ctx.console.ok("ไม่พบปัญหาพื้นฐาน (ยังไม่ได้ตรวจลายเซ็น)")
    ctx.console.sub("คำสั่งนี้ถอดรหัสเท่านั้น ไม่ตรวจสอบ signature กับ JWKS")
    ctx.print_json({"header": header, "payload": payload, "segments": len(parts), "warnings": warnings})
    return 0


# -------------------------------------------------------------------------- ua
BROWSER_PATTERNS = [
    ("Edg", "Edge"), ("OPR", "Opera"), ("SamsungBrowser", "Samsung Internet"), ("FxiOS", "Firefox iOS"),
    ("CriOS", "Chrome iOS"), ("Chrome", "Chrome"), ("Firefox", "Firefox"), ("Version", "Safari"),
    ("curl", "curl"), ("python-requests", "python-requests"), ("Googlebot", "Googlebot"),
    ("bingbot", "Bingbot"), ("bot", "bot/crawler"),
]


def cmd_ua(ctx, argv: List[str]) -> int:
    ua = " ".join(argv).strip()
    if not ua:
        ctx.console.err('usage: osint.ua "<user-agent string>"')
        return 2
    browser = next((label for token, label in BROWSER_PATTERNS if token.lower() in ua.lower()), "unknown")
    version = ""
    match = re.search(r"(?:Chrome|Firefox|Version|Edg|OPR|SamsungBrowser)/([0-9.]+)", ua)
    if match:
        version = match.group(1)
    os_name = "unknown"
    for token, label in (
        ("Windows NT 10.0", "Windows 10/11"), ("Windows NT 6.3", "Windows 8.1"),
        ("Windows NT 6.1", "Windows 7"), ("Android", "Android"), ("iPhone", "iOS"),
        ("iPad", "iPadOS"), ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux"),
    ):
        if token in ua:
            os_name = label
            break
    device = "mobile" if re.search(r"Mobile|Android|iPhone", ua) else "desktop"
    if "iPad" in ua or "Tablet" in ua:
        device = "tablet"
    if "bot" in ua.lower() or "crawler" in ua.lower() or "spider" in ua.lower():
        device = "bot"
    ctx.console.heading("User agent")
    ctx.console.keyvalue(
        [
            ("Browser", f"{browser} {version}".strip()),
            ("OS", os_name),
            ("Device class", device),
            ("Length", len(ua)),
            ("Suspicious", "yes" if re.search(r"HeadlessChrome|PhantomJS|Selenium|puppeteer", ua) else "no"),
        ]
    )
    ctx.console.line("  " + ctx.console.dim(ua))
    ctx.print_json({"user_agent": ua, "browser": browser, "version": version, "os": os_name, "device": device})
    return 0


def make_ua_command(browser: str, browser_label: str, template: str, platform: str, platform_label: str, token: str):
    def handler(ctx, argv: List[str]) -> int:
        ua = template.replace("{platform}", token).replace("{mac}", token)
        ctx.console.heading(f"UA preset · {browser_label} on {platform_label}")
        ctx.console.line("  " + ua)
        ctx.console.sub("ใช้กับ curl -A หรือ DevTools เพื่อทดสอบการตอบสนองของเว็บ")
        ctx.print_json({"browser": browser, "platform": platform, "user_agent": ua})
        return 0

    return handler


# ------------------------------------------------------------------------- url
def cmd_url(ctx, argv: List[str]) -> int:
    raw = ctx.need(argv, 0, "osint.url <url>", "URL")
    parts = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    ctx.console.heading("URL breakdown")
    ctx.console.keyvalue(
        [
            ("Scheme", parts.scheme or "(none)"),
            ("Host", parts.hostname or "-"),
            ("Port", parts.port or "default"),
            ("Path", parts.path or "/"),
            ("Query", parts.query or "-"),
            ("Fragment", parts.fragment or "-"),
            ("Userinfo", "PRESENT — ตรวจสอบว่าไม่ใช่ credential" if parts.username else "none"),
            ("Length", len(raw)),
        ]
    )
    if query:
        ctx.console.heading(f"Query parameters · {len(query)}")
        for key, value in query:
            ctx.console.line(f"  {ctx.console.cyan(key.ljust(22))}  {value or '(empty)'}")
    _links(
        ctx,
        "Archive / reputation",
        [
            ("Wayback", "https://web.archive.org/web/*/" + raw),
            ("archive.today", "https://archive.ph/newest/" + raw),
            ("urlscan", "https://urlscan.io/liveshot/?url=" + urllib.parse.quote(raw, safe="")),
            ("VirusTotal", "https://www.virustotal.com/gui/url/" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")),
            ("Google cache", "https://www.google.com/search?q=" + urllib.parse.quote(f'"{raw}"')),
            ("Shodan hostname", "https://www.shodan.io/search?query=hostname%3A" + (parts.hostname or "")),
        ],
    )
    ctx.print_json({"url": raw, "scheme": parts.scheme, "host": parts.hostname, "port": parts.port,
                    "path": parts.path, "query": query, "fragment": parts.fragment})
    return 0


# ------------------------------------------------------------- encode / decode
def _encode(scheme: str, text: str) -> str:
    payload = text.encode("utf-8")
    if scheme == "base64":
        return base64.b64encode(payload).decode()
    if scheme == "base64url":
        return base64.urlsafe_b64encode(payload).decode().rstrip("=")
    if scheme == "base32":
        return base64.b32encode(payload).decode()
    if scheme == "hex":
        return binascii.hexlify(payload).decode()
    if scheme == "url":
        return urllib.parse.quote(text, safe="")
    if scheme == "rot13":
        return codecs.encode(text, "rot13")
    if scheme == "html":
        return html.escape(text)
    if scheme == "binary":
        return " ".join(f"{byte:08b}" for byte in payload)
    if scheme == "unicode-escape":
        return text.encode("unicode_escape").decode()
    raise UsageError("scheme ที่รองรับ: " + ", ".join(name for name, _ in data.ENCODINGS))


def _decode(scheme: str, text: str) -> str:
    if scheme == "base64":
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True).decode("utf-8", "replace")
    if scheme == "base64url":
        return _b64url_decode(text).decode("utf-8", "replace")
    if scheme == "base32":
        return base64.b32decode(text.upper() + "=" * (-len(text) % 8)).decode("utf-8", "replace")
    if scheme == "hex":
        return binascii.unhexlify(re.sub(r"\s+", "", text)).decode("utf-8", "replace")
    if scheme == "url":
        return urllib.parse.unquote(text)
    if scheme == "rot13":
        return codecs.decode(text, "rot13")
    if scheme == "html":
        return html.unescape(text)
    if scheme == "binary":
        bits = re.sub(r"\s+", "", text)
        return bytes(int(bits[index : index + 8], 2) for index in range(0, len(bits), 8)).decode("utf-8", "replace")
    if scheme == "unicode-escape":
        return text.encode().decode("unicode_escape")
    raise UsageError("scheme ที่รองรับ: " + ", ".join(name for name, _ in data.ENCODINGS))


def cmd_encode(ctx, argv: List[str]) -> int:
    if len(argv) < 2:
        ctx.console.err("usage: osint.encode <scheme> <text>")
        ctx.console.sub("schemes: " + ", ".join(name for name, _ in data.ENCODINGS))
        return 2
    scheme = argv[0].lower()
    text = " ".join(argv[1:])
    result = _encode(scheme, text)
    ctx.console.heading(f"Encode · {scheme}")
    ctx.console.line("  " + result)
    ctx.print_json({"scheme": scheme, "input": text, "output": result})
    return 0


def cmd_decode(ctx, argv: List[str]) -> int:
    if len(argv) < 2:
        ctx.console.err("usage: osint.decode <scheme> <text>")
        ctx.console.sub("schemes: " + ", ".join(name for name, _ in data.ENCODINGS))
        return 2
    scheme = argv[0].lower()
    text = " ".join(argv[1:])
    try:
        result = _decode(scheme, text)
    except (binascii.Error, ValueError, UnicodeError) as exc:
        ctx.console.err(f"decode ไม่ได้: {exc}")
        return 1
    ctx.console.heading(f"Decode · {scheme}")
    ctx.console.line("  " + result)
    ctx.print_json({"scheme": scheme, "input": text, "output": result})
    return 0


# ------------------------------------------------------------------------ dork
def cmd_dork(ctx, argv: List[str]) -> int:
    positionals, flags = parse_flags(argv, {"engine": "str", "all": "bool"})
    query = ctx.need(positionals, 0, "osint.dork <query> [--engine google|bing|...] [--all]", "คำค้น")
    engine_slug = str(flags.get("engine", "")).lower()
    engines = [row for row in data.DORK_ENGINES if not engine_slug or row[0] == engine_slug]
    if not engines:
        ctx.console.err("ไม่รู้จัก engine: " + engine_slug)
        ctx.console.sub("มี: " + ", ".join(row[0] for row in data.DORK_ENGINES))
        return 2
    encoded = urllib.parse.quote(query, safe='"')
    ctx.console.heading(f"Dork · {query}")
    for engine_slug_name, label, template in engines:
        ctx.console.line("  " + ctx.console.cyan(label.ljust(20)) + "  " + template.format(q=encoded))
    ctx.print_json({"query": query, "engines": [{"slug": slug, "url": tpl.format(q=encoded)}
                                              for slug, _, tpl in engines]})
    return 0


def make_dork_command(engine_slug: str, query: str, label: str, template: str, topic_label: str):
    def handler(ctx, argv: List[str]) -> int:
        extra = " ".join(argv).strip()
        dork = query.replace("{u}", extra) if "{u}" in query else (query + (" " + extra if extra else ""))
        ctx.console.heading(f"Dork · {topic_label} · {engine_slug}")
        ctx.console.keyvalue([("Dork", dork), ("Engine", engine_slug)])
        url = template.format(q=urllib.parse.quote(dork, safe=':"'))
        ctx.console.link("Open", url)
        ctx.console.sub("แทน {u} ได้โดยใส่ argument: " + f"osint.dork-{engine_slug}-{label} <username>")
        ctx.print_json({"engine": engine_slug, "dork": dork, "url": url})
        return 0

    return handler


# ------------------------------------------------------------------------ tlds
def cmd_tld(ctx, argv: List[str]) -> int:
    raw = ctx.need(argv, 0, "osint.tld <tld>", "TLD")
    tld = raw.lower().lstrip(".")
    gtlds = set(data.GTLD_TEXT.split())
    country = _country_by_tld(tld)
    ctx.console.heading(f"TLD · .{tld}")
    if tld in gtlds:
        ctx.console.ok("generic / new gTLD")
    elif country:
        ctx.console.ok(f"ccTLD ของ {country[1]} (dial +{country[2]})")
    else:
        ctx.console.warn("ไม่พบในตารางที่ฝังไว้ (อาจเป็น brand/geo TLD ใหม่)")
    _links(
        ctx,
        "Registry",
        [
            ("IANA", f"https://www.iana.org/domains/root/db/{tld}.html"),
            ("RDAP bootstrap", f"https://rdap.org/domain/example.{tld}"),
            ("Whois", f"https://www.whois.com/whois/example.{tld}"),
            ("List of TLDs", "https://www.iana.org/domains/root/db"),
        ],
    )
    ctx.print_json({"tld": tld, "generic": tld in gtlds,
                    "country": {"iso2": country[0], "name": country[1], "dial": country[2]} if country else None})
    return 0


# ----------------------------------------------------------------------- phone
def cmd_phone(ctx, argv: List[str]) -> int:
    raw = ctx.need(argv, 0, "osint.phone <number>", "หมายเลขโทรศัพท์")
    digits = re.sub(r"[^\d+]", "", raw)
    if not digits:
        ctx.console.err("ไม่พบตัวเลขในหมายเลข")
        return 2
    international = digits.startswith("+")
    bare = digits.lstrip("+")
    country = _country_by_dial(bare)
    if country is None and not international:
        ctx.console.warn("ไม่รู้รหัสประเทศ — ใส่ +<รหัสประเทศ> เพื่อความแม่นยำ")
    ctx.console.heading("Phone number")
    if country:
        dial = country[2]
        national = bare[len(dial):] if bare.startswith(dial) else bare
        e164 = f"+{dial}{national}"
        ctx.console.keyvalue(
            [
                ("Country", f"{country[1]} ({country[0]})"),
                ("Dial code", f"+{dial}"),
                ("National", national),
                ("E.164", e164),
                ("ccTLD", "." + country[3]),
                ("Digits", len(national)),
            ]
        )
        query = urllib.parse.quote(e164)
        _links(
            ctx,
            "Lookup",
            [
                ("NumLookup", f"https://www.numlookup.com/?number={query}"),
                ("Truecaller", f"https://www.truecaller.com/search/{country[0].lower()}/{national}"),
                ("Google", "https://www.google.com/search?q=" + urllib.parse.quote(f'"{e164}"')),
                ("WhatsApp", f"https://wa.me/{dial}{national}"),
                ("Telegram", f"https://t.me/+{dial}{national}"),
                ("PhoneInfoga", "https://github.com/sundowndev/phoneinfoga"),
            ],
        )
        ctx.print_json({"input": raw, "e164": e164, "country": country[1], "iso2": country[0], "dial": dial})
    else:
        ctx.console.line("  digits: " + bare)
        ctx.print_json({"input": raw, "digits": bare})
    return 0


def make_phone_command(iso2: str, name: str, dial: str, tld: str):
    def handler(ctx, argv: List[str]) -> int:
        number = ctx.need(argv, 0, f"osint.phone-{iso2.lower()} <number>", "หมายเลขภายในประเทศ")
        digits = re.sub(r"\D", "", number).lstrip("0")
        e164 = f"+{dial}{digits}"
        ctx.console.heading(f"{name} · {e164}")
        ctx.console.keyvalue(
            [
                ("Country", f"{name} ({iso2})"),
                ("Dial code", f"+{dial}"),
                ("National", digits),
                ("E.164", e164),
                ("Trunk prefix", "0"),
                ("ccTLD", "." + tld),
            ]
        )
        ctx.console.link("Google", "https://www.google.com/search?q=" + urllib.parse.quote(f'"{e164}"'))
        ctx.console.link("Truecaller", f"https://www.truecaller.com/search/{iso2.lower()}/{digits}")
        ctx.print_json({"iso2": iso2, "country": name, "dial": dial, "e164": e164})
        return 0

    return handler


def make_geo_command(iso2: str, name: str, dial: str, tld: str):
    def handler(ctx, argv: List[str]) -> int:
        ctx.console.heading(f"{name} · {iso2}")
        ctx.console.keyvalue(
            [
                ("ISO 3166-1 alpha-2", iso2),
                ("Country", name),
                ("Dial code", f"+{dial}"),
                ("ccTLD", "." + tld),
                ("Internet users / data", f"https://datareportal.com/search?q={urllib.parse.quote(name)}"),
            ]
        )
        _links(
            ctx,
            "Country sources",
            [
                ("Wikidata", "https://www.wikidata.org/wiki/Special:EntityData/Q0"),
                ("World Bank", f"https://data.worldbank.org/country/{iso2.lower()}"),
                ("UN Data", "https://data.un.org/"),
                ("CIA World Factbook", f"https://www.cia.gov/the-world-factbook/countries/{name.lower().replace(' ', '-')}/"),
                ("OpenStreetMap", f"https://www.openstreetmap.org/search?query={urllib.parse.quote(name)}"),
                ("Wikipedia", "https://en.wikipedia.org/wiki/" + urllib.parse.quote(name.replace(" ", "_"))),
            ],
        )
        ctx.print_json({"iso2": iso2, "country": name, "dial": dial, "tld": tld})
        return 0

    return handler


# ------------------------------------------------------------------------ files
def _read_head(path: str, size: int = 4 * 1024 * 1024) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(size)


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = [0] * 256
    for byte in payload:
        counts[byte] += 1
    total = len(payload)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _detect_type(head: bytes) -> Tuple[str, str]:
    for signature, label, mime in MAGIC:
        if head.startswith(signature):
            return label, mime
    if all(32 <= byte < 127 or byte in (9, 10, 13) for byte in head[:256]) and head:
        return "text (ASCII/UTF-8)", "text/plain"
    return "unknown binary", "application/octet-stream"


def _jpeg_exif(payload: bytes) -> Dict[str, str]:
    """Minimal EXIF reader: Make/Model/Software/DateTime/Copyright + GPS."""
    if not payload.startswith(b"\xff\xd8"):
        return {}
    index = 2
    while index + 4 <= len(payload):
        if payload[index] != 0xFF:
            index += 1
            continue
        marker = payload[index + 1]
        if marker in (0xD8, 0xD9):
            index += 2
            continue
        if index + 4 > len(payload):
            break
        length = struct.unpack(">H", payload[index + 2 : index + 4])[0]
        segment = payload[index + 4 : index + 2 + length]
        if marker == 0xE1 and segment.startswith(b"Exif\x00\x00"):
            return _tiff_tags(segment[6:])
        index += 2 + length
    return {}


def _tiff_tags(tiff: bytes) -> Dict[str, str]:
    if len(tiff) < 8:
        return {}
    endian = "<" if tiff[:2] == b"II" else ">"
    try:
        offset = struct.unpack(endian + "I", tiff[4:8])[0]
    except struct.error:
        return {}
    names = {
        0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation", 0x0131: "Software",
        0x0132: "DateTime", 0x8298: "Copyright", 0x9003: "DateTimeOriginal",
        0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
    }
    gps_names = {0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude", 0x0003: "GPSLongitudeRef",
                 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef", 0x0006: "GPSAltitude"}

    def read_ifd(position: int) -> Dict[str, str]:
        values: Dict[str, str] = {}
        if position + 2 > len(tiff):
            return values
        try:
            count = struct.unpack(endian + "H", tiff[position : position + 2])[0]
        except struct.error:
            return values
        for entry_index in range(min(count, 128)):
            start = position + 2 + entry_index * 12
            if start + 12 > len(tiff):
                break
            tag, kind, amount = struct.unpack(endian + "HHI", tiff[start : start + 8])
            raw = tiff[start + 8 : start + 12]
            name = names.get(tag) or gps_names.get(tag)
            if not name:
                continue
            if kind == 2:  # ASCII
                if amount <= 4:
                    text = raw[:amount]
                else:
                    pointer = struct.unpack(endian + "I", raw)[0]
                    text = tiff[pointer : pointer + amount]
                values[name] = text.split(b"\x00", 1)[0].decode("utf-8", "replace")
            elif kind == 5 and amount:  # RATIONAL
                pointer = struct.unpack(endian + "I", raw)[0]
                parts = []
                for part_index in range(min(amount, 3)):
                    start_r = pointer + part_index * 8
                    if start_r + 8 > len(tiff):
                        break
                    numerator, denominator = struct.unpack(endian + "II", tiff[start_r : start_r + 8])
                    parts.append(numerator / denominator if denominator else 0)
                values[name] = ", ".join(f"{value:.6f}" for value in parts)
            elif kind in (3, 4) and amount == 1:
                fmt = endian + ("H" if kind == 3 else "I")
                values[name] = str(struct.unpack(fmt, raw[:2 if kind == 3 else 4])[0])
        return values

    tags = read_ifd(offset)
    try:
        gps_offset = None
        count = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
        for entry_index in range(min(count, 128)):
            start = offset + 2 + entry_index * 12
            tag, kind, amount = struct.unpack(endian + "HHI", tiff[start : start + 8])
            if tag == 0x8825:
                gps_offset = struct.unpack(endian + "I", tiff[start + 8 : start + 12])[0]
                break
        if gps_offset:
            tags.update(read_ifd(gps_offset))
    except (struct.error, IndexError):
        pass
    return tags


def _png_text(payload: bytes) -> Dict[str, str]:
    values: Dict[str, str] = {}
    index = 8
    while index + 8 <= len(payload):
        length = struct.unpack(">I", payload[index : index + 4])[0]
        kind = payload[index + 4 : index + 8]
        data_start = index + 8
        data_end = min(data_start + length, len(payload))
        if kind in (b"tEXt", b"iTXt"):
            chunk = payload[data_start:data_end]
            key, _, value = chunk.partition(b"\x00")
            values[key.decode("latin-1", "replace")] = value.decode("utf-8", "replace")[:200]
        index = data_end + 4
    return values


def cmd_file(ctx, argv: List[str]) -> int:
    path = ctx.need(argv, 0, "osint.file <path>", "พาธไฟล์")
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        ctx.console.err(f"ไม่พบไฟล์: {path}")
        return 1
    stat = os.stat(path)
    with open(path, "rb") as handle:
        payload = handle.read(min(stat.st_size, 8 * 1024 * 1024))
    label, mime = _detect_type(payload)
    ctx.console.heading(f"File · {os.path.basename(path)}")
    ctx.console.keyvalue(
        [
            ("Path", os.path.abspath(path)),
            ("Size", f"{stat.st_size:,} bytes"),
            ("Type", label),
            ("MIME (guess)", mime),
            ("Modified", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))),
            ("Entropy", f"{_entropy(payload[:65536]):.2f} bits/byte"),
            ("MD5", hashlib.md5(payload).hexdigest()),
            ("SHA1", hashlib.sha1(payload).hexdigest()),
            ("SHA256", hashlib.sha256(payload).hexdigest()),
        ]
    )
    if _entropy(payload[:65536]) > 7.5:
        ctx.console.warn("entropy สูง — ไฟล์อาจถูกบีบอัด/เข้ารหัส/แพ็ก")
    ctx.print_json({"path": os.path.abspath(path), "size": stat.st_size, "type": label, "mime": mime,
                    "md5": hashlib.md5(payload).hexdigest(), "sha256": hashlib.sha256(payload).hexdigest()})
    return 0


def cmd_exif(ctx, argv: List[str]) -> int:
    path = ctx.need(argv, 0, "osint.exif <image>", "พาธรูปภาพ")
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        ctx.console.err(f"ไม่พบไฟล์: {path}")
        return 1
    payload = _read_head(path)
    tags: Dict[str, str] = {}
    if payload.startswith(b"\xff\xd8"):
        tags = _jpeg_exif(payload)
    elif payload.startswith(b"\x89PNG\r\n\x1a\n"):
        tags = _png_text(payload)
    else:
        label, _ = _detect_type(payload)
        ctx.console.warn(f"ยังไม่รองรับ metadata เชิงลึกของ {label} — ใช้ exiftool")
    ctx.console.heading(f"Metadata · {os.path.basename(path)}")
    if tags:
        ctx.console.table(["Tag", "Value"], [[key, value] for key, value in tags.items()])
    else:
        ctx.console.warn("ไม่พบ EXIF/PNG text metadata")
    if "GPSLatitude" in tags or "GPSLongitude" in tags:
        lat = tags.get("GPSLatitude", "")
        lon = tags.get("GPSLongitude", "")
        ctx.console.warn(f"พบพิกัด GPS: {lat} {tags.get('GPSLatitudeRef', '')}, {lon} {tags.get('GPSLongitudeRef', '')}")
        ctx.console.line("  แผนที่: https://www.google.com/maps?q=" + urllib.parse.quote(f"{lat},{lon}"))
    ctx.console.sub("ลบ metadata ก่อนเผยแพร่: exiftool -all= file.jpg · mat2 file")
    _links(ctx, "Related", [("ExifTool", "https://exiftool.org/"), ("mat2", "https://0xacab.org/jvoisin/mat2")])
    ctx.print_json({"file": os.path.abspath(path), "tags": tags})
    return 0


def make_meta_command(ext: str, label: str, fields: str):
    def handler(ctx, argv: List[str]) -> int:
        ctx.console.heading(f"Metadata · .{ext} · {label}")
        ctx.console.keyvalue([("Format", label), ("Extension", "." + ext), ("Fields", fields)])
        if argv:
            return cmd_exif(ctx, argv)
        ctx.console.sub("ใส่พาธไฟล์เพื่ออ่าน metadata จริง: " + f"osint.meta-{ext} <file>")
        ctx.console.line("  exiftool -a -G1 -s " + f"file.{ext}")
        ctx.print_json({"extension": ext, "format": label, "fields": [f.strip() for f in fields.split(",")]})
        return 0

    return handler


def make_exif_tag_command(slug: str, tag: str, description: str):
    def handler(ctx, argv: List[str]) -> int:
        ctx.console.heading(f"EXIF tag · {tag}")
        ctx.console.keyvalue([("Tag", tag), ("Meaning", description), ("Family", slug)])
        ctx.console.line("  exiftool -" + tag + " <file>")
        if argv:
            return cmd_exif(ctx, argv)
        ctx.print_json({"tag": tag, "description": description})
        return 0

    return handler


# ------------------------------------------------------------------------- misc
def cmd_mac(ctx, argv: List[str]) -> int:
    raw = ctx.need(argv, 0, "osint.mac <mac-address>", "MAC address")
    hexonly = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(hexonly) not in {12, 16}:
        ctx.console.err("MAC ต้องมี 12 hex digits (หรือ 16 สำหรับ EUI-64)")
        return 2
    octets = [hexonly[index : index + 2].upper() for index in range(0, 12, 2)]
    first = int(octets[0], 16)
    ctx.console.heading(f"MAC · {':'.join(octets)}")
    ctx.console.keyvalue(
        [
            ("Normalised", ":".join(octets)),
            ("Cisco style", ".".join("".join(octets[index : index + 2]) for index in range(0, 6, 2))),
            ("OUI", ":".join(octets[:3])),
            ("NIC specific", ":".join(octets[3:])),
            ("Multicast", "yes" if first & 1 else "no"),
            ("Locally administered", "yes" if first & 2 else "no"),
        ]
    )
    query = ":".join(octets[:3])
    _links(ctx, "Vendor lookup", [
        ("macvendors", f"https://macvendors.com/query/{query}"),
        ("maclookup", f"https://maclookup.app/search/result?mac={query}"),
        ("Wireshark OUI", f"https://www.wireshark.org/tools/oui-lookup.html"),
        ("IEEE registry", "https://standards-oui.ieee.org/oui/oui.txt"),
    ])
    ctx.console.sub("vendor ต้องเทียบกับฐาน OUI — ไม่มีฐานฝังใน ngm-panel เพื่อไม่ให้ข้อมูลเก่า")
    ctx.print_json({"mac": ":".join(octets), "oui": query, "multicast": bool(first & 1),
                    "local": bool(first & 2)})
    return 0


def cmd_guid(ctx, argv: List[str]) -> int:
    raw = ctx.need(argv, 0, "osint.guid <uuid>", "UUID")
    try:
        value = uuid.UUID(raw.strip())
    except ValueError as exc:
        ctx.console.err(f"UUID ไม่ถูกต้อง: {exc}")
        return 2
    ctx.console.heading(f"UUID · {value}")
    ctx.console.keyvalue(
        [
            ("Version", value.version or "nil/unknown"),
            ("Variant", str(value.variant)),
            ("Canonical", str(value)),
            ("URN", value.urn),
            ("Hex", value.hex),
            ("Int", value.int),
            ("Is nil", "yes" if value.int == 0 else "no"),
            ("Max UUID", "yes" if value.int == (1 << 128) - 1 else "no"),
        ]
    )
    if value.version == 1:
        timestamp = (value.time - 0x01B21DD213814000) / 10_000_000
        ctx.console.line("  " + ctx.console.bold("v1 timestamp") + "  " +
                         time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)))
    if value.version == 7 and value.int:
        milliseconds = value.int >> 80
        ctx.console.line("  " + ctx.console.bold("v7 timestamp") + "  " +
                         time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(milliseconds / 1000)))
    ctx.print_json({"uuid": str(value), "version": value.version, "variant": str(value.variant)})
    return 0


def cmd_asn(ctx, argv: List[str]) -> int:
    raw = ctx.need(argv, 0, "osint.asn <asn|ip>", "ASN หรือ IP")
    cleaned = raw.upper().replace("AS", "").strip()
    ctx.console.heading(f"ASN · {raw}")
    if cleaned.isdigit():
        ctx.console.keyvalue([("ASN", f"AS{cleaned}"), ("Number", cleaned)])
        _links(ctx, "Sources", [
            ("BGPView", f"https://bgpview.io/asn/{cleaned}"),
            ("BGP.he.net", f"https://bgp.he.net/AS{cleaned}"),
            ("PeeringDB", f"https://www.peeringdb.com/asn/{cleaned}"),
            ("RIPE Stat", f"https://stat.ripe.net/AS{cleaned}"),
            ("CAIDA AS Rank", f"https://asrank.caida.org/asns?asn={cleaned}"),
            ("Hurricane Electric", f"https://bgp.he.net/AS{cleaned}#_prefixes"),
        ])
    else:
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            ctx.console.err("ระบุ ASN (ตัวเลข) หรือ IP address")
            return 2
        encoded = urllib.parse.quote(raw)
        ctx.console.sub("ดู ASN ของ IP ได้จาก:")
        _links(ctx, "Sources", [
            ("BGPView", f"https://bgpview.io/ip/{encoded}"),
            ("Team Cymru", "https://team-cymru.com/community-services/ip-asn-mapping/"),
            ("RIPE Stat", f"https://stat.ripe.net/{encoded}"),
            ("IPinfo", f"https://ipinfo.io/{encoded}"),
        ])
    ctx.print_json({"input": raw})
    return 0


def cmd_wayback(ctx, argv: List[str]) -> int:
    url = ctx.need(argv, 0, "osint.wayback <url>", "URL")
    encoded = urllib.parse.quote(url, safe="")
    ctx.console.heading(f"Archive · {url}")
    _links(ctx, "Snapshots", [
        ("Wayback", f"https://web.archive.org/web/*/{url}"),
        ("Wayback CDX", f"https://web.archive.org/cdx/search/cdx?url={encoded}&output=json"),
        ("archive.today", f"https://archive.ph/newest/{url}"),
        ("Google cache", "https://www.google.com/search?q=" + urllib.parse.quote(f'cache:"{url}"')),
        ("Common Crawl", f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url={encoded}&output=json"),
    ])
    ctx.print_json({"url": url})
    return 0


def cmd_chain(ctx, argv: List[str]) -> int:
    address = ctx.need(argv, 0, "osint.chain <address>", "ที่อยู่ crypto")
    address = address.strip()
    matches = []
    for slug, name, explorer, pattern in sources.CRYPTO_CHAINS:
        try:
            if re.match(pattern, address):
                matches.append((slug, name, explorer))
        except re.error:
            continue
    ctx.console.heading(f"Crypto address · {len(address)} chars")
    ctx.console.line("  " + address)
    if matches:
        _links(ctx, "Explorers", [(name, explorer.replace("{a}", urllib.parse.quote(address))) for _, name, explorer in matches])
    else:
        ctx.console.warn("ไม่ตรงกับรูปแบบของチェーンที่ฝังไว้")
        _links(ctx, "General", [
            ("Blockchair", f"https://blockchair.com/search?q={urllib.parse.quote(address)}"),
            ("Etherscan", f"https://etherscan.io/search?f=0&q={urllib.parse.quote(address)}"),
            ("Chainabuse", "https://www.chainabuse.com/"),
        ])
    ctx.print_json({"address": address, "chains": [slug for slug, _, _ in matches]})
    return 0


def cmd_links(ctx, argv: List[str]) -> int:
    username = ctx.need(argv, 0, "osint.links <username>", "username")
    if not USERNAME_RE.match(username):
        ctx.console.err("username ไม่ถูกต้อง")
        return 2
    ctx.console.heading(f"All profile links · {username}")
    for _slug, name, template in platforms.USERNAME_PLATFORMS:
        ctx.console.line("  " + _pad(name, 22) + " " + template.replace("{u}", username))
    ctx.console.blank()
    ctx.console.sub(f"{len(platforms.USERNAME_PLATFORMS)} platforms · ใช้ --json เพื่อประมวลผลต่อ")
    ctx.print_json({"username": username,
                    "links": [{"name": name, "url": tpl.replace("{u}", username)}
                              for _, name, tpl in platforms.USERNAME_PLATFORMS]})
    return 0


def cmd_catalog(ctx, argv: List[str]) -> int:
    families = [
        ("osint.username", len(platforms.USERNAME_PLATFORMS)),
        ("osint.email", len(data.EMAIL_TEXT.split())),
        ("osint.domain", len(data.GTLD_TEXT.split()) + len(data.COUNTRY_ROWS)),
        ("osint.dork", len(data.DORK_ENGINES) * len(data.DORK_TOPICS)),
        ("osint.ip", len(sources.IP_SERVICES)),
        ("osint.geo", len(data.COUNTRY_ROWS)),
        ("osint.phone", len(data.COUNTRY_ROWS)),
        ("osint.crypto", len(sources.CRYPTO_CHAINS)),
        ("osint.ua", len(data.UA_BROWSERS) * len(data.UA_PLATFORMS)),
        ("osint.meta", len(data.META_FORMATS)),
        ("osint.tool", len(tools.OSINT_TOOLS)),
        ("osint.source", len(tools.DATA_SOURCES)),
        ("osint.subdomain", len(data.SUBDOMAIN_SOURCES)),
        ("osint.breach", len(data.BREACH_SOURCES)),
        ("osint.hash", len(data.HASH_ALGORITHMS)),
        ("osint.exif", len(tools.EXIF_TAGS)),
    ]
    total = sum(count for _, count in families)
    ctx.console.heading(f"OSINT families · {total} generated commands")
    ctx.console.table(["Family", "Commands"], families)
    ctx.console.blank()
    ctx.console.ok(f"รวม {total} คำสั่ง OSINT (ยังไม่นับ hand-written)")
    ctx.print_json({"families": {name: count for name, count in families}, "total": total})
    return 0


# ---------------------------------------------------------------------- register
def register(registry: Registry) -> None:
    registry.add(cmd_about, name="osint.about", category="osint", usage="osint.about",
                 description="ภาพรวมชุดข้อมูล OSINT ที่ฝังในเครื่องและหลักการใช้งานอย่างมีจริยธรรม")
    registry.add(cmd_username, name="osint.username", category="osint",
                 usage="osint.username <username> [--check] [--limit N] [--all]",
                 description="สร้างลิงก์โปรไฟล์จากทุกแพลตฟอร์ม และตรวจเฉพาะ host ที่อยู่ใน scope",
                 examples=("osint.username johndoe --limit 20", "osint.username johndoe --check"))
    registry.add(cmd_email, name="osint.email", category="osint", usage="osint.email <address>",
                 description="วิเคราะห์อีเมล: provider, gravatar, MX (ถ้าอยู่ใน scope) และลิงก์ breach check")
    registry.add(cmd_domain, name="osint.domain", category="osint", usage="osint.domain <domain> [--rdap]",
                 description="ข้อมูลโดเมน/TLD และลิงก์ RDAP/WHOIS/certificate transparency")
    registry.add(cmd_ip, name="osint.ip", category="osint", usage="osint.ip <ip>",
                 description="จำแนก IP, PTR, integer/hex และลิงก์ IP intelligence")
    registry.add(cmd_hash, name="osint.hash", category="osint", usage="osint.hash <text>",
                 description="คำนวณ hash ทุกอัลกอริทึมใน hashlib พร้อม base encodings")
    registry.add(cmd_identify_hash, name="osint.identify-hash", category="osint", usage="osint.identify-hash <hash>",
                 description="เดาชนิด hash จากความยาว/รูปแบบ (md5, bcrypt, argon2, JWT ฯลฯ)")
    registry.add(cmd_jwt, name="osint.jwt", category="osint", usage="osint.jwt <token>",
                 description="ถอด header/payload ของ JWT และเตือน alg=none/หมดอายุ")
    registry.add(cmd_ua, name="osint.ua", category="osint", usage='osint.ua "<user-agent>"',
                 description="แยก browser/OS/device จาก user-agent string")
    registry.add(cmd_url, name="osint.url", category="osint", usage="osint.url <url>",
                 description="แยกส่วน URL/query parameters และลิงก์ archive")
    registry.add(cmd_encode, name="osint.encode", category="osint", usage="osint.encode <scheme> <text>",
                 description="encode base64/base32/hex/url/rot13/html/binary")
    registry.add(cmd_decode, name="osint.decode", category="osint", usage="osint.decode <scheme> <text>",
                 description="decode ข้อมูลที่ encode ด้วย scheme ที่รองรับ")
    registry.add(cmd_dork, name="osint.dork", category="osint", usage="osint.dork <query> [--engine slug]",
                 description="สร้าง search URL สำหรับ dork ทุก engine หรือ engine เดียว")
    registry.add(cmd_tld, name="osint.tld", category="osint", usage="osint.tld <tld>",
                 description="ข้อมูล TLD: gTLD หรือ ccTLD พร้อม registry link")
    registry.add(cmd_phone, name="osint.phone", category="osint", usage="osint.phone <number>",
                 description="แปลงหมายเลขโทรศัพท์เป็น E.164 และเดาประเทศจากรหัส")
    registry.add(cmd_exif, name="osint.exif", category="osint", usage="osint.exif <image>",
                 description="อ่าน EXIF (รวม GPS) ของ JPEG และ text chunks ของ PNG")
    registry.add(cmd_file, name="osint.file", category="osint", usage="osint.file <path>",
                 description="ระบุชนิดไฟล์จาก magic bytes, hash, entropy และเวลาแก้ไข")
    registry.add(cmd_mac, name="osint.mac", category="osint", usage="osint.mac <mac-address>",
                 description="normalize MAC, แยก OUI และลิงก์ vendor lookup")
    registry.add(cmd_guid, name="osint.guid", category="osint", usage="osint.guid <uuid>",
                 description="ถอด version/variant/timestamp ของ UUID")
    registry.add(cmd_asn, name="osint.asn", category="osint", usage="osint.asn <asn|ip>",
                 description="ลิงก์ข้อมูล ASN/BGP หรือค้น ASN จาก IP")
    registry.add(cmd_wayback, name="osint.wayback", category="osint", usage="osint.wayback <url>",
                 description="ลิงก์ snapshot จาก Wayback/archive.today/Common Crawl")
    registry.add(cmd_chain, name="osint.chain", category="osint", usage="osint.chain <address>",
                 description="ตรวจรูปแบบที่อยู่ crypto และสร้าง explorer link ตามチェーン")
    registry.add(cmd_links, name="osint.links", category="osint", usage="osint.links <username>",
                 description="พิมพ์ลิงก์โปรไฟล์ทั้งหมด (JSON พร้อมประมวลผลต่อ)")
    registry.add(cmd_catalog, name="osint.catalog", category="osint", usage="osint.catalog",
                 description="สรุปจำนวนคำสั่ง OSINT แยกตาม family")
