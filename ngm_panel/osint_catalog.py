"""Expand the OSINT reference tables into individually registered commands.

Each generated command is a real command with its own usage, description and
handler — the same contract as hand-written commands. Families collapse in
``help`` and expand with ``help osint.<family>``.
"""

from __future__ import annotations

import hashlib
import urllib.parse
from typing import Callable, List, Set, Tuple

from . import osint_data as data
from . import osint_platforms as platforms
from . import osint_sources as sources
from . import osint_tools as tools
from .commands import osint
from .registry import Registry


def _register(registry: Registry, family: str, members: List[Tuple[str, Callable, str]], usage: str) -> None:
    for slug, handler, description in members:
        registry.add(
            handler,
            name=f"{family}-{slug}",
            category="osint",
            usage=f"{family}-{slug} {usage}".strip(),
            description=description,
            danger="safe",
            family=family,
        )


# ------------------------------------------------------------------- tool/source
def _tool_handler(slug: str, name: str, url: str, category: str):
    def handler(ctx, argv: List[str]) -> int:
        ctx.console.heading(f"OSINT tool · {name}")
        ctx.console.keyvalue(
            [("Category", category), ("Homepage", url), ("Slug", slug)]
        )
        ctx.console.sub("ติดตั้ง/ใช้งานตามเอกสารของเครื่องมือนั้น — ngm-panel ไม่ได้รันมันให้")
        if argv:
            query = " ".join(argv)
            target = "https://www.google.com/search?q=" + urllib.parse.quote(f"{name} {query}")
            ctx.console.link("Search", target)
        ctx.print_json({"tool": name, "category": category, "url": url})
        return 0

    return handler


def _source_handler(slug: str, name: str, template: str, kind: str):
    def handler(ctx, argv: List[str]) -> int:
        if "{q}" in template:
            query = ctx.need(argv, 0, f"osint.source-{slug} <query>", "คำค้น")
            url = template.replace("{q}", urllib.parse.quote(query))
        else:
            query = ""
            url = template
        ctx.console.heading(f"Data source · {name}")
        ctx.console.keyvalue([("Kind", kind), ("Query", query or "-")])
        ctx.console.link("Open", url)
        ctx.print_json({"source": name, "kind": kind, "query": query, "url": url})
        return 0

    return handler


def _subdomain_handler(slug: str, name: str, template: str):
    def handler(ctx, argv: List[str]) -> int:
        domain = ctx.need(argv, 0, f"osint.subdomain-{slug} <domain>", "โดเมน")
        domain = domain.strip().lower().lstrip(".")
        url = template.replace("{d}", urllib.parse.quote(domain))
        ctx.console.heading(f"Subdomains · {domain} · {name}")
        ctx.console.link("Open", url)
        if "api." in url or url.endswith(".json") or "output=json" in url:
            ctx.console.sub("endpoint นี้คืน JSON — ใช้ curl ได้เมื่ออยู่ใน scope:")
            ctx.console.line("  curl -s '" + url + "'")
        ctx.print_json({"source": name, "domain": domain, "url": url})
        return 0

    return handler


def _breach_handler(slug: str, name: str, template: str):
    def handler(ctx, argv: List[str]) -> int:
        if "{prefix}" in template:
            password = " ".join(argv).strip()
            if not password:
                ctx.console.err(f"usage: osint.breach-{slug} <password>")
                return 2
            prefix = hashlib.sha1(password.encode("utf-8")).hexdigest()[:5].upper()
            url = template.replace("{prefix}", prefix)
            ctx.console.heading(f"Pwned Passwords · {name}")
            ctx.console.keyvalue(
                [
                    ("SHA-1 prefix", prefix),
                    ("k-anonymity", "ส่งเฉพาะ 5 ตัวอักษรแรก — รหัสผ่านไม่ออกจากเครื่อง"),
                    ("URL", url),
                ]
            )
            ctx.console.sub("เรียก API นี้เฉพาะเมื่อมี api.pwnedpasswords.com ใน scope")
            ctx.print_json({"source": name, "prefix": prefix, "url": url})
            return 0
        query = ctx.need(argv, 0, f"osint.breach-{slug} <email|username>", "อีเมลหรือ username")
        url = template.replace("{q}", urllib.parse.quote(query))
        ctx.console.heading(f"Breach lookup · {name}")
        ctx.console.link("Open", url)
        ctx.console.sub("ตรวจ breach เฉพาะบัญชีของคุณเองหรือเมื่อได้รับอนุญาต")
        ctx.print_json({"source": name, "query": query, "url": url})
        return 0

    return handler


# ------------------------------------------------------------------------ crypto
def _crypto_handler(slug: str, name: str, explorer: str, pattern: str):
    import re

    def handler(ctx, argv: List[str]) -> int:
        address = ctx.need(argv, 0, f"osint.crypto-{slug} <address>", "ที่อยู่")
        address = address.strip()
        try:
            valid = re.match(pattern, address) is not None
        except re.error:
            valid = True
        ctx.console.heading(f"{name} · address")
        ctx.console.keyvalue(
            [
                ("Chain", name),
                ("Address", address),
                ("Format check", "valid" if valid else "ไม่ตรงรูปแบบ"),
                ("Regex", pattern),
            ]
        )
        if valid:
            ctx.console.link("Explorer", explorer.replace("{a}", urllib.parse.quote(address)))
        else:
            ctx.console.warn("ที่อยู่นี้ไม่ตรงรูปแบบของเชนนี้ — ตรวจเครือข่ายให้แน่ใจ")
        ctx.print_json({"chain": slug, "name": name, "address": address, "valid": valid})
        return 0

    return handler


def register(registry: Registry) -> None:
    # ------------------------------------------------------------- username
    members = [
        (slug, osint.make_username_command(name, template), f"ลิงก์โปรไฟล์ {name}")
        for slug, name, template in platforms.USERNAME_PLATFORMS
    ]
    _register(registry, "osint.username", members, "<username>")

    # ---------------------------------------------------------------- email
    members = [
        (
            domain.replace(".", "-"),
            osint.make_email_command(domain),
            f"ตัวช่วยตรวจบัญชีอีเมล @{domain} (ลิงก์ login/reset/breach)",
        )
        for domain in sorted(set(data.EMAIL_TEXT.split()))
    ]
    _register(registry, "osint.email", members, "<local-part>")

    # --------------------------------------------------------------- domain
    seen: Set[str] = set()
    members = []
    for tld in data.GTLD_TEXT.split():
        if tld in seen:
            continue
        seen.add(tld)
        members.append(
            (tld, osint.make_domain_command(tld), f"ตรวจโดเมน .{tld} (gTLD) — RDAP/WHOIS/DNS links")
        )
    for row in data.COUNTRY_ROWS:
        iso2, country, _dial, tld = row[0], row[1], row[2], row[3]
        if tld in seen:
            continue
        seen.add(tld)
        members.append(
            (tld, osint.make_domain_command(tld, country, country),
             f"ตรวจโดเมน .{tld} — ccTLD ของ {country}")
        )
    _register(registry, "osint.domain", members, "<name>")

    # ----------------------------------------------------------------- dork
    members = []
    for engine_slug, engine_name, template in data.DORK_ENGINES:
        for topic_slug, topic_label, query in data.DORK_TOPICS:
            members.append(
                (
                    f"{engine_slug}-{topic_slug}",
                    osint.make_dork_command(engine_slug, query, topic_slug, template, topic_label),
                    f"Dork {topic_label} บน {engine_name}",
                )
            )
    _register(registry, "osint.dork", members, "[extra query]")

    # ------------------------------------------------------------------- ip
    members = [
        (slug, osint.make_ip_command(slug, name, template), f"ค้น {name} สำหรับ IP/โดเมน/ASN")
        for slug, name, template in sources.IP_SERVICES
    ]
    _register(registry, "osint.ip", members, "<ip|domain|asn>")

    # -------------------------------------------------------------- geo/phone
    members = [
        (row[0].lower(), osint.make_geo_command(*row),
         f"โปรไฟล์ประเทศ {row[1]} ({row[0]}) — dial +{row[2]}, .{row[3]}")
        for row in data.COUNTRY_ROWS
    ]
    _register(registry, "osint.geo", members, "")
    members = [
        (row[0].lower(), osint.make_phone_command(*row),
         f"แปลงหมายเลขเป็น E.164 ของ {row[1]} (+{row[2]})")
        for row in data.COUNTRY_ROWS
    ]
    _register(registry, "osint.phone", members, "<number>")

    # --------------------------------------------------------------- crypto
    members = [
        (slug, _crypto_handler(slug, name, explorer, pattern),
         f"ตรวจที่อยู่ {name} และเปิด explorer")
        for slug, name, explorer, pattern in sources.CRYPTO_CHAINS
    ]
    _register(registry, "osint.crypto", members, "<address>")

    # ------------------------------------------------------------------- ua
    members = []
    for browser_slug, browser_label, template in data.UA_BROWSERS:
        for platform_slug, platform_label, token in data.UA_PLATFORMS:
            members.append(
                (
                    f"{browser_slug}-{platform_slug}",
                    osint.make_ua_command(browser_slug, browser_label, template,
                                          platform_slug, platform_label, token),
                    f"User-Agent ของ {browser_label} บน {platform_label}",
                )
            )
    _register(registry, "osint.ua", members, "")

    # ------------------------------------------------------------------ meta
    members = [
        (ext, osint.make_meta_command(ext, label, fields), f"metadata ของไฟล์ .{ext} — {label}")
        for ext, label, fields in data.META_FORMATS
    ]
    _register(registry, "osint.meta", members, "[file]")

    # ------------------------------------------------------------------ tool
    members = [
        (slug, _tool_handler(slug, name, url, category), f"{name} — OSINT tool ({category})")
        for slug, name, url, category in tools.OSINT_TOOLS
    ]
    _register(registry, "osint.tool", members, "[search terms]")

    # ---------------------------------------------------------------- source
    members = [
        (slug, _source_handler(slug, name, template, kind), f"{name} — {kind} data source")
        for slug, name, template, kind in tools.DATA_SOURCES
    ]
    _register(registry, "osint.source", members, "[query]")

    # ------------------------------------------------------------- subdomain
    members = [
        (slug, _subdomain_handler(slug, name, template), f"ค้น subdomain ผ่าน {name}")
        for slug, name, template in data.SUBDOMAIN_SOURCES
    ]
    _register(registry, "osint.subdomain", members, "<domain>")

    # ---------------------------------------------------------------- breach
    members = [
        (slug, _breach_handler(slug, name, template), f"ตรวจข้อมูลรั่วไหลผ่าน {name}")
        for slug, name, template in data.BREACH_SOURCES
    ]
    _register(registry, "osint.breach", members, "<email|username>")

    # ------------------------------------------------------------------ hash
    members = [
        (algorithm, osint.make_hash_command(algorithm), f"คำนวณ {algorithm} ของข้อความ")
        for algorithm in data.HASH_ALGORITHMS
    ]
    _register(registry, "osint.hash", members, "<text>")

    # ------------------------------------------------------------------ exif
    members = [
        (slug, osint.make_exif_tag_command(slug, tag, description), f"EXIF tag {tag} — {description}")
        for slug, tag, description in tools.EXIF_TAGS
    ]
    _register(registry, "osint.exif", members, "[file]")


FAMILY_DESCRIPTIONS = {
    "osint.username": "profile links ต่อแพลตฟอร์ม",
    "osint.email": "ตัวช่วยตรวจอีเมลต่อ provider",
    "osint.domain": "โดเมนต่อ TLD (gTLD + ccTLD)",
    "osint.dork": "search dork ต่อ engine × หัวข้อ",
    "osint.ip": "IP intelligence services",
    "osint.geo": "โปรไฟล์ประเทศ",
    "osint.phone": "รูปแบบหมายเลขโทรศัพท์ต่อประเทศ",
    "osint.crypto": "blockchain explorer ต่อเชน",
    "osint.ua": "user-agent presets",
    "osint.meta": "metadata ต่อชนิดไฟล์",
    "osint.tool": "เครื่องมือ OSINT",
    "osint.source": "แหล่งข้อมูลสาธารณะ",
    "osint.subdomain": "แหล่งค้น subdomain",
    "osint.breach": "แหล่งตรวจข้อมูลรั่วไหล",
    "osint.hash": "อัลกอริทึม hash",
    "osint.exif": "EXIF tag reference",
}
