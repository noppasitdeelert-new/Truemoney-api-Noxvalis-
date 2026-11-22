# ngm-panel

> **CLI Tool สำหรับ Windows และ Termux (Android) ที่รันบนเครื่องผู้ใช้ 100% (Local Standalone Execution)**
> ไม่มีเซิร์ฟเวอร์กลาง ไม่มี backend ออนไลน์ ไม่มีการรับส่งคำสั่งหรือผลลัพธ์ออกนอกเครื่อง
> ทุกคำสั่งทำงานและประมวลผลภายในโปรเซส `ngm-panel` บนเครื่องของคุณเอง

[![tests](https://img.shields.io/badge/tests-72%20passed-brightgreen)](#การทดสอบ)
[![commands](https://img.shields.io/badge/catalog-5101%20commands-blue)](#7-catalog-5000-คำสั่ง-และวิธีขยาย)
[![osint](https://img.shields.io/badge/OSINT-3652%20commands-purple)](#54-osint-3652-คำสั่ง)
[![termux](https://img.shields.io/badge/platform-Windows%20%7C%20Termux-lightgrey)](#24-termux--android-มือถือ)
![python](https://img.shields.io/badge/python-3.9%2B-blue)

---

## สารบัญ

1. [ภาพรวมและหลักการ](#1-ภาพรวมและหลักการ)
2. [ติดตั้งและรันบน Windows](#2-ติดตั้งและรันบน-windows) · [Termux / Android](#24-termux--android-มือถือ)
3. [โหมดหน้าจอเต็ม `ngm-panel run`](#3-โหมดหน้าจอเต็ม-ngm-panel-run)
4. [โครงสร้างโปรเจกต์ — อธิบายทีละไฟล์](#4-โครงสร้างโปรเจกต์--อธิบายทีละไฟล์)
5. [คำสั่งทั้งหมดและตัวอย่าง](#5-คำสั่งทั้งหมดและตัวอย่าง) · [OSINT](#54-osint-3652-คำสั่ง) · [mobile](#55-mobile--termux-51-คำสั่ง)
6. [Authorization Guard / Scope / Rate Limit](#6-authorization-guard--scope--rate-limit)
7. [Catalog 5,000+ คำสั่ง และวิธีขยาย](#7-catalog-5000-คำสั่ง-และวิธีขยาย)
8. [แพ็กเป็น .exe ด้วย PyInstaller](#8-แพ็กเป็น-exe-ด้วย-pyinstaller)
9. [Installer (Inno Setup) + PATH อัตโนมัติ](#9-installer-inno-setup--path-อัตโนมัติ)
10. [เผยแพร่ผ่าน winget](#10-เผยแพร่ผ่าน-winget)
11. [การทดสอบ](#11-การทดสอบ)
12. [ความปลอดภัยและขอบเขตความรับผิดชอบ](#12-ความปลอดภัยและขอบเขตความรับผิดชอบ)

---

## 1. ภาพรวมและหลักการ

| ข้อกำหนด | การ implement |
|---|---|
| รันบนเครื่อง 100% | Python standard library ทั้งหมด ไม่มี dependency, ไม่มี telemetry, ไม่มี API กลาง |
| Windows + มือถือ | console app เดียวกัน รองรับ cmd / PowerShell / Windows Terminal และ Termux (Android) |
| เรียกจาก cmd / PowerShell / Windows Terminal | console app + entry point `ngm-panel` + installer เติม `PATH` |
| `ngm-panel run` หน้าจอเต็ม | Alternate Screen Buffer (`\x1b[?1049h`) + Banner + Prompt + history |
| `help` แบบมีหมวด/ค้นหา/แบ่งหน้า | `help_system.py` + pager ตามความสูงหน้าจอ |
| `exit` คืนหน้าจอ | ปิด alternate screen และคืน prompt ของ Windows |
| ทุกคำสั่งภายนอกต้องมี Authorization Guard | `scope_guard.py` + `allowed_targets.json` + ยืนยันก่อน load test |
| Rate Limit / Timeout / Concurrency | `ratelimit.py` + ขีดจำกัดในไฟล์ scope + clamp ทุกค่า |
| 5,000+ คำสั่ง แบบขยายได้ | `Command` dataclass + auto-discovered modules + generator → **5,101 คำสั่ง** (OSINT **3,652**) |
| รองรับ Termux | ตรวจ `TERMUX_VERSION`/`PREFIX`, banner/tables แบบ phone, `mobile.*` + Termux:API presets |
| OSINT 3,500++ | `osint_data.py` + `osint_platforms.py` + `osint_sources.py` + `osint_tools.py` → `osint_catalog.py` |
| แพ็ก `.exe` + winget | `packaging/ngm-panel.spec`, `build.ps1`, `installer/ngm-panel.iss`, `winget/manifests/…` |

**จุดสำคัญ:** โปรเซส `ngm-panel` เป็นผู้รันคำสั่งทั้งหมดเอง (socket, HTTP, TLS, `subprocess` ของ Windows)
ข้อมูลไม่ถูกส่งไปยังเซิร์ฟเวอร์ของผู้พัฒนา — ยกเว้นคำสั่งที่คุณสั่งให้ตรวจสอบโฮสต์ปลายทางเอง ซึ่งเป็นการเชื่อมต่อตรงจากเครื่องคุณ

---

## 2. ติดตั้งและรันบน Windows

### 2.1 จาก source (แนะนำสำหรับพัฒนา)

```powershell
# 1) โคลน / แตกไฟล์โปรเจกต์ แล้วเข้าโฟลเดอร์
cd ngm-panel

# 2) สร้าง virtual environment
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) ไม่มี dependency ตอนรัน — แค่ทำให้ import ได้
python -m pip install -e .

# 4) ตรวจความพร้อม
ngm-panel --version
ngm-panel doctor
ngm-panel catalog --check
```

ถ้าไม่ต้องการติดตั้งเป็น package ก็รันได้เลย:

```powershell
python -m ngm_panel --version
python -m ngm_panel help
python -m ngm_panel run
```

> หมายเหตุ: ถ้าเครื่องยังไม่เคยอนุญาตสคริปต์ ให้รัน PowerShell แบบ
> `powershell -ExecutionPolicy Bypass -File packaging\build.ps1`

### 2.2 จากไฟล์ `.exe` ที่ build แล้ว

```powershell
.\dist\ngm-panel.exe --version
.\dist\ngm-panel.exe doctor
.\dist\ngm-panel.exe run
```

ถ้าต้องการเรียกจากทุกโฟลเดอร์ ให้เพิ่มโฟลเดอร์ของ exe ลง `PATH` (หรือติดตั้งด้วย installer ในหัวข้อ 9):

```powershell
$dir = "$env:LOCALAPPDATA\Programs\ngm-panel"
[Environment]::SetEnvironmentVariable(
  "Path",
  [Environment]::GetEnvironmentVariable("Path","User") + ";$dir",
  "User")
# เปิด terminal ใหม่ แล้วทดสอบ
ngm-panel doctor
```

### 2.3 ภาษาไทย / ตัวอักษรกล่องใน `cmd`

```cmd
chcp 65001
ngm-panel run
```

โปรแกรมตั้ง stdout เป็น UTF-8 ให้อัตโนมัติ และเปิด VT sequences บน Windows console แล้ว
ถ้าสีเพี้ยนให้ใช้ `--no-color` หรือตั้ง environment variable `NO_COLOR=1`

### 2.4 Termux / Android (มือถือ)

`ngm-panel` รันใน Termux ได้โดยไม่ต้องมี dependency เพิ่ม (เฉพาะ `python`)
และจะสลับเป็น **mobile layout** อัตโนมัติเมื่อหน้าจอแคบกว่า 64 คอลัมน์
(ตารางจะแสดงเป็นแบบ stacked, banner เป็นแบบกะทัดรัด, pager เผื่อคีย์บอร์ด)

```bash
# 1) ติดตั้ง Termux จาก F-Droid (ไม่ใช่ Play Store) แล้วอัปเดต repo
pkg update -y && pkg upgrade -y

# 2) แพ็กเกจที่ต้องใช้
pkg install -y python git termux-api

# 3) ดึงโปรเจกต์ (หรือคัดลอกโฟลเดอร์เข้า ~/ngm-panel)
git clone <REPO_URL> ~/ngm-panel
cd ~/ngm-panel

# 4) ติดตั้งเป็นคำสั่ง ngm-panel
pip install -e .

# หรือใช้สคริปต์ที่เตรียมไว้ (ติดตั้ง + สร้าง launcher ให้)
bash packaging/termux/install-termux.sh

# 5) ตรวจและเริ่มใช้งาน
ngm-panel doctor
ngm-panel mobile.doctor
ngm-panel mobile.status
ngm-panel run
```

คำสั่ง `pkg` ที่ใช้บ่อยบนมือถือ:

```bash
pkg install -y python git termux-api      # ติดตั้งพื้นฐาน
pkg install -y openssh                    # ถ้าต้อง ssh ออกไปเครื่องอื่น
pkg install -y nmap dnsutils curl         # เครื่องมือเสริม (ถ้าต้องการ)
pkg list-installed | grep python          # ตรวจเวอร์ชัน
pkg search <ชื่อแพ็กเกจ>                    # ค้นหาแพ็กเกจ
pkg update && pkg upgrade                 # อัปเดตระบบ
termux-setup-storage                      # ให้เข้าถึง Download/DCIM ผ่าน ~/storage
termux-wake-lock                          # กัน Android ฆ่าโปรเซสตอนรันนาน ๆ
termux-wake-unlock
```

หมายเหตุบนมือถือ:

- `mobile.*` ต้องมี **Termux:API** (แอปจาก F-Droid) + `pkg install termux-api`
  คำสั่งจะบอกวิธีติดตั้งเองถ้ายังไม่มี และไม่ crash
- `ngm-panel run` บน Termux ใช้หน้าจอปกติ (inline) โดยอัตโนมัติ เพราะ alternate screen
  ของ Termux มักค้างไม่รีเฟรชหลังรันคำสั่ง — ถ้าต้องการ alt-screen ให้เติม `--alt-screen`
- อัปเดตเวอร์ชันบนมือถือ: `ngm-panel update` (พิมพ์คำสั่ง pkg/git/pip) หรือ
  `ngm-panel update --run` (รันให้เลย) แล้วพิมพ์ `exit` เปิด `ngm-panel` ใหม่
- history ใช้ `readline` ของ Termux ได้ตามปกติ
- `osint.*` สร้างลิงก์/วิเคราะห์ในเครื่อง — แตะนิ้วค้างที่ลิงก์เพื่อคัดลอกไปเปิดเบราว์เซอร์
- คำสั่ง Windows-only (`sys.cim`, `proc.service`, `sys.adapters`) จะแจ้งว่าใช้ได้บน Windows เท่านั้น
  ส่วน `sys.info`, `sys.disk`, `net.local`, `proc.list`, `file.*`, `osint.*` ใช้ได้บน Android

---

## 3. โหมดหน้าจอเต็ม `ngm-panel run`

```
ngm-panel run                 # เข้า alternate screen + banner + prompt
ngm-panel run --no-alt-screen # ใช้ใน CI / piping (ไม่สลับหน้าจอ)
```

ภายในโหมดนี้พิมพ์คำสั่งได้เหมือน CLI ทุกประการ:

```
ngm-panel › help
ngm-panel › help web
ngm-panel › help net.tcp
ngm-panel › scope list
ngm-panel › net.tcp example.com 80,443
ngm-panel › web.scan https://example.com
ngm-panel › exit
```

คำสั่งภายในโหมด: `help` / `?`, `list [category]`, `scope <list|add|remove|check|path>`,
`catalog`, `banner`, `clear` / `cls`, `version`, `exit` / `quit`

- `help` ไม่มี argument → ภาพรวมทุกหมวด + quick start
- `help web` → คำสั่งหลักของหมวด + รายชื่อ generated families
- `help net.tcp` → รายละเอียดคำสั่ง + ขยายคำสั่งที่ generate ทั้ง 1,109 รายการ (แบ่งหน้า)
- `help search rdp` → ค้นจากชื่อ/คำอธิบาย
- `help web.scan` → usage, ตัวอย่าง, ข้อกำหนด scope
- `exit` → ปิด alternate screen คืนหน้าจอเดิมของ Windows
- `↑` / `↓` ใช้ history ได้ (ผ่าน `readline` ถ้ามีในเครื่อง; บน Windows ใหม่ ๆ ใช้ `pyreadline3` ก็ได้)

---

## 4. โครงสร้างโปรเจกต์ — อธิบายทีละไฟล์

```
ngm-panel/
├─ ngm_panel/
│  ├─ __init__.py          เวอร์ชัน + ชื่อแอป
│  ├─ __main__.py          ทำให้ `python -m ngm_panel` ทำงาน
│  ├─ cli.py               entry point: run / help / list / exec / scope / catalog / doctor / version
│  ├─ shell.py             โหมดหน้าจอเต็ม (alternate screen, banner, prompt, history, built-ins)
│  ├─ registry.py          Command model, Registry (auto-load), Context, RunOptions, validation
│  ├─ runner.py            parse global flags (`--json --yes --dry-run --timeout`), dispatch, error handling
│  ├─ help_system.py       help แบบหมวด/ตระกูลคำสั่ง/ค้นหา/แบ่งหน้า
│  ├─ scope_guard.py       Authorization Guard + limits + add/remove target + confirmation
│  ├─ ratelimit.py         RateLimiter, thread-safe Stats
│  ├─ loadgen.py           engine ของ L7/L4/flood: threads, deadline, request cap, Ctrl+C
│  ├─ net_utils.py         normalize host, TCP connect, HTTP client, TLS inspect, security headers
│  ├─ dnsmini.py           DNS client (A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/SRV/CAA) — stdlib only
│  ├─ system.py            wrapper ของ Windows/POSIX: run, powershell, WMI/CIM, services, Termux detect
│  ├─ console.py           ANSI/VT, สี, ตาราง (desktop/mobile), bar, pager, banner, UTF-8 setup
│  ├─ config.py            path ของ config (`%USERPROFILE%\.ngm-panel`), bundled defaults, JSON I/O
│  ├─ catalog.py           generator: ขยาย family ระบบ/เครือข่าย → คำสั่งจริง
│  ├─ osint_data.py        ตาราง OSINT: dork, TLD, email, ประเทศ, metadata, UA, breach sources
│  ├─ osint_platforms.py   ฐานข้อมูล 254 แพลตฟอร์มสำหรับ username enumeration
│  ├─ osint_sources.py     IP intelligence 113 บริการ + blockchain explorer 76 เชน
│  ├─ osint_tools.py       เครื่องมือ OSINT 160 + แหล่งข้อมูล 137 + EXIF tags 87
│  ├─ osint_catalog.py     generator: ขยายข้อมูล OSINT → คำสั่งจริง 3,600+ รายการ
│  ├─ scope_cli.py         logic ของ `scope …` (ใช้ร่วมกับ CLI และ shell)
│  ├─ data/
│  │  ├─ __init__.py
│  │  └─ allowed_targets.json   ค่าเริ่มต้นของ authorized scope (ฝังเข้า .exe)
│  └─ commands/            ทุกโมดูลมี `register(registry)` → โหลดอัตโนมัติ
│     ├─ __init__.py
│     ├─ common.py         helper: authorize/resolve, human bytes, process table, listening ports
│     ├─ net.py            net.ip / net.dns / net.tcp / net.reverse / net.local / net.listen / net.tls
│     ├─ web.py            web.scan / web.security / web.check-header / web.method / web.path
│     ├─ tester.py         web.test-l7 / web.test-l4 / web.test-flood
│     ├─ sysinfo.py        sys.info / sys.hardware / sys.disk / sys.env / sys.cim / …
│     ├─ proc.py           proc.list / proc.find / proc.kill / proc.services / proc.service / proc.ports
│     ├─ files.py          file.ls / file.find / file.hash / file.size / file.tree / file.which / file.stat
│     ├─ diag.py           diag.ping / diag.traceroute / diag.http-timing / diag.dns-server / diag.mtu
│     ├─ sec.py            sec.scope / sec.audit / sec.tls-grade
│     ├─ mobile.py         mobile.status / mobile.doctor / mobile.pkg / mobile.storage / Termux:API
│     └─ osint.py          osint.username/email/domain/ip/hash/jwt/exif/phone/dork/… (hand-written)
├─ tests/test_core.py      offline test suite (72 tests, ไม่ต้องใช้เน็ต)
├─ packaging/
│  ├─ ngm-panel.spec       PyInstaller spec (onefile, console, ฝัง data/)
│  ├─ build.ps1            build + test + smoke test (+ `-Installer`)
│  ├─ build.bat            เหมือนกันสำหรับ cmd.exe
│  ├─ installer/ngm-panel.iss   Inno Setup 6 + เติม PATH ผู้ใช้อัตโนมัติ
│  ├─ termux/install-termux.sh   ติดตั้งบน Termux + สร้าง launcher
│  ├─ termux/ngm-panel          launcher shell สำหรับ $PREFIX/bin
│  ├─ winget/manifests/n/NGM/NgmPanel/1.0.0/*.yaml   manifest 3 ไฟล์ (เวอร์ชันเก่า)
│  └─ winget/manifests/n/NGM/NgmPanel/1.1.1/*.yaml   manifest 3 ไฟล์ (เวอร์ชันปัจจุบัน)
├─ pyproject.toml          packaging + console entry point
├─ requirements-dev.txt    PyInstaller (runtime ไม่มี dependency)
├─ LICENSE                  MIT
└─ README.md
```

### ทำไมไม่ใช่ `if/elif` 1,000 บรรทัด

- ทุกคำสั่งคือ object `Command(name, category, usage, description, handler, danger, family)`
- `Registry.load()` ไล่ import ทุกโมดูลใน `ngm_panel/commands/` แล้วเรียก `register()`
  → เพิ่มไฟล์ใหม่ = เพิ่มคำสั่ง ไม่ต้องแก้ engine
- `catalog.py` สร้างคำสั่งจาก **family spec** (เช่น port 1–1024) โดย handler จริงทุกตัว
- help ซ่อน family ที่มีสมาชิกเยอะไว้เป็นบรรทัดเดียว แล้วขยายเมื่อสั่ง `help <family>` → 5,101 คำสั่งยังใช้งานได้จริง

---

## 5. คำสั่งทั้งหมดและตัวอย่าง

### 5.1 คำสั่งหลัก (hand-written)

| คำสั่ง | ทำอะไร | ตัวอย่าง |
|---|---|---|
| `net.ip <host>` | A/AAAA + reverse DNS + public/private | `net.ip example.com` |
| `net.dns <name> [type]` | query DNS ตรง (UDP) รองรับ 10 ชนิด | `net.dns example.com MX` |
| `net.tcp <host> <ports>` | TCP connect + latency (สูงสุด 64 พอร์ต/ครั้ง) | `net.tcp 127.0.0.1 80,443,8000-8010` |
| `net.tls <host> [port]` | certificate/protocol/cipher/อายุ | `net.tls example.com 443` |
| `net.reverse <ip>` | PTR record | `net.reverse 8.8.8.8` |
| `net.local` | hostname/IP/interface ของเครื่อง | `net.local` |
| `net.listen` | พอร์ต TCP ที่เปิดในเครื่อง + PID/process | `net.listen` |
| `web.scan <url>` | headers + security headers + TLS + title | `web.scan https://example.com` |
| `web.security <url>` | เช็กลิสต์ security headers พร้อมค่า | `web.security https://example.com` |
| `web.check-header <url> <header>` | ตรวจ header เดี่ยว | `web.check-header https://example.com CSP` |
| `web.method <url> <VERB>` | ยิง method เดียว (HEAD/GET/OPTIONS/POST/PUT/PATCH/DELETE) | `web.method https://example.com OPTIONS` |
| `web.path <base> <path>` | ตรวจเส้นทางเดี่ยว | `web.path https://example.com /robots.txt` |
| `web.test-l7 <url>` | โหมด 1: HTTP load (status/latency/throughput) | `web.test-l7 https://example.com -n 5 -d 10 -r 5` |
| `web.test-l4 <host> <port>` | โหมด 2: TCP connect load | `web.test-l4 127.0.0.1 8000 -n 4 -d 10 -r 5` |
| `web.test-flood <url>` | โหมด 3: controlled HTTP benchmark + Ctrl+C | `web.test-flood https://example.com -n 10 -d 15 -r 10` |
| `sys.info` | OS/เครื่อง/ผู้ใช้/Python | `sys.info` |
| `sys.hardware` | CPU/เมนบอร์ด/RAM | `sys.hardware` |
| `sys.disk` | พื้นที่ดิสก์ + แถบใช้งาน | `sys.disk` |
| `sys.env [prefix]` | env vars (ปิดบัง secret) | `sys.env PATH` |
| `sys.env-get <NAME>` | env var ตัวเดียว | `sys.env-get TEMP` |
| `sys.adapters` | `ipconfig /all` | `sys.adapters` |
| `sys.uptime` / `sys.time` / `sys.users` | uptime / เวลา / ผู้ใช้ | `sys.uptime` |
| `sys.cim <Class>` | query WMI/CIM | `sys.cim Win32_LogicalDisk` |
| `proc.list [--sort cpu\|mem] [--top N]` | โปรเซส + ทรัพยากร | `proc.list --sort mem --top 15` |
| `proc.find <name>` | ค้นโปรเซส | `proc.find chrome` |
| `proc.kill <pid>` | สิ้นสุดโปรเซส (มีคำยืนยัน) | `proc.kill 1234` |
| `proc.services [filter]` | service ทั้งหมด + สถานะ | `proc.services spooler` |
| `proc.service <name>` | service เดี่ยว | `proc.service wuauserv` |
| `proc.startup` | โปรแกรมที่เริ่มตอนบูต | `proc.startup` |
| `proc.ports` | พอร์ตที่เปิด + โปรเซส | `proc.ports` |
| `file.ls [path]` | รายการไฟล์ | `file.ls C:\Users` |
| `file.find [root] [pattern]` | ค้นไฟล์ (`*.log`) | `file.find . *.log --max 50` |
| `file.hash <path> [-a sha256]` | hash (8 algorithms) | `file.hash README.md -a sha256` |
| `file.size [path]` | ขนาดไฟล์/โฟลเดอร์ | `file.size C:\Windows\Temp` |
| `file.tree [path] [-d depth]` | โครงสร้างโฟลเดอร์ | `file.tree . -d 2` |
| `file.which <exe>` | หา exe ใน PATH | `file.which python` |
| `file.stat <path>` | metadata | `file.stat README.md` |
| `diag.ping <host> [-c N]` | ping | `diag.ping 8.8.8.8 -c 4` |
| `diag.traceroute <host>` | tracert | `diag.traceroute example.com` |
| `diag.http-timing <url>` | DNS/TCP/TLS/TTFB breakdown | `diag.http-timing https://example.com` |
| `diag.dns-server <ip> <name>` | ทดสอบ resolver เฉพาะ | `diag.dns-server 1.1.1.1 example.com` |
| `diag.mtu <host>` | ประมาณ Path MTU | `diag.mtu example.com` |
| `diag.port-profile <profile> <host>` | กลุ่มพอร์ต (web/mail/database/remote/windows/dev/dns/file/container) | `diag.port-profile web example.com` |
| `sec.scope` | ดู scope + limits | `sec.scope` |
| `sec.audit <url>` | audit + คะแนน 0–100 | `sec.audit https://example.com` |
| `sec.tls-grade <host> [port]` | เกรด TLS A–F | `sec.tls-grade example.com` |

### 5.2 คำสั่งที่ generate (families)

| Family | จำนวน | ตัวอย่าง |
|---|---|---|
| `net.tcp-<port>` | 1,109 (port 1–1024 + named ports) | `net.tcp-8080 example.com`, `net.tcp-3389 10.0.0.5` |
| `net.dns-<type>` | 10 | `net.dns-mx example.com`, `net.dns-txt example.com` |
| `web.header-<header>` | 33 | `web.header-content-security-policy https://example.com` |
| `web.method-<verb>` | 7 | `web.method-options https://example.com` |
| `web.path-<slug>` | 36 | `web.path-robots https://example.com`, `web.path-security-txt …` |
| `diag.ping-size-<bytes>` | 8 | `diag.ping-size-1400 example.com` |
| `file.find-<ext>` | 60 | `file.find-log C:\logs`, `file.find-ps1 .` |
| `proc.service-<name>` | 47 | `proc.service-wuauserv`, `proc.service-spooler` |
| `sys.cim-<class>` | 40 | `sys.cim-win32-logicaldisk` |

### 5.4 OSINT (3,652 คำสั่ง)

หลักการ: **สร้างลิงก์และวิเคราะห์ในเครื่องก่อน** — ไม่มีข้อมูลถูกส่งออกไปที่ใด
คำสั่งที่ต้องยิงเน็ตจริงต้องมี `--check` / `--rdap` และ host ต้องอยู่ใน authorized scope

| Family | จำนวน | ตัวอย่าง |
|---|---|---|
| `osint.username-<platform>` | 254 | `osint.username-github johndoe` · `osint.username johndoe --limit 20` |
| `osint.email-<provider>` | 188 | `osint.email-gmail-com johndoe` · `osint.email you@example.com` |
| `osint.domain-<tld>` | 558 | `osint.domain-coffee shop` · `osint.domain-th mysite` |
| `osint.dork-<engine>-<topic>` | 1,316 | `osint.dork-google-pdf` · `osint.dork-bing-env` |
| `osint.ip-<service>` | 113 | `osint.ip-shodan 8.8.8.8` · `osint.ip-abuseipdb 1.1.1.1` |
| `osint.geo-<iso2>` | 199 | `osint.geo-th` · `osint.geo-jp` |
| `osint.phone-<iso2>` | 199 | `osint.phone-th 0812345678` |
| `osint.crypto-<chain>` | 76 | `osint.crypto-btc bc1…` · `osint.crypto-eth 0x…` |
| `osint.ua-<browser>-<os>` | 132 | `osint.ua-chrome-android` |
| `osint.meta-<ext>` | 103 | `osint.meta-jpg photo.jpg` |
| `osint.tool-<name>` | 160 | `osint.tool-exiftool` · `osint.tool-sherlock` |
| `osint.source-<name>` | 137 | `osint.source-wikidata Bangkok` |
| `osint.subdomain-<source>` | 40 | `osint.subdomain-crtsh example.com` |
| `osint.breach-<source>` | 51 | `osint.breach-hibp a@example.com` |
| `osint.hash-<algo>` | 15 | `osint.hash-sha256 hello` |
| `osint.exif-<tag>` | 87 | `osint.exif-gpslat photo.jpg` |

คำสั่ง hand-written ที่สำคัญ:

| คำสั่ง | ทำอะไร | ตัวอย่าง |
|---|---|---|
| `osint.about` | ภาพรวมชุดข้อมูล + หลักจริยธรรม | `osint.about` |
| `osint.catalog` | จำนวนคำสั่ง OSINT แยก family | `osint.catalog` |
| `osint.username <name>` | ลิงก์ทุกแพลตฟอร์ม, `--check` เฉพาะ host ใน scope | `osint.username johndoe --check` |
| `osint.links <name>` | ลิงก์ทั้งหมด (JSON พร้อมประมวลผล) | `osint.links johndoe` |
| `osint.email <addr>` | provider/gravatar/MX (ถ้า scope อนุญาต)/breach links | `osint.email me@example.com` |
| `osint.domain <domain>` | TLD, RDAP/WHOIS/crt.sh; `--rdap` ต้องอยู่ใน scope | `osint.domain example.com --rdap` |
| `osint.ip <ip>` | จำแนก IP, PTR, int/hex, Shodan/Censys/AbuseIPDB | `osint.ip 8.8.8.8` |
| `osint.hash <text>` | hash ทุกอัลกอริทึม + base64/base32 | `osint.hash hello` |
| `osint.identify-hash <h>` | เดาชนิด hash (md5/bcrypt/argon2/JWT) | `osint.identify-hash 5f4dcc3b…` |
| `osint.jwt <token>` | ถอด header/payload + เตือน alg=none/หมดอายุ | `osint.jwt eyJ…` |
| `osint.ua "<string>"` | แยก browser/OS/device | `osint.ua "Mozilla/5.0 …"` |
| `osint.url <url>` | แยก query parameters + archive links | `osint.url "https://a.com/x?y=1"` |
| `osint.encode/decode` | base64/base32/hex/url/rot13/html/binary | `osint.encode base64 hello` |
| `osint.dork <query>` | ทุก engine หรือ `--engine google` | `osint.dork 'site:example.com filetype:pdf'` |
| `osint.phone <number>` | E.164 + ประเทศ/ccTLD + ลิงก์ | `osint.phone +66812345678` |
| `osint.exif <image>` | อ่าน EXIF (รวม GPS) ของ JPEG, tEXt ของ PNG | `osint.exif photo.jpg` |
| `osint.file <path>` | magic bytes, hash, entropy, เวลา | `osint.file download.zip` |
| `osint.mac <mac>` | OUI + multicast/local bit | `osint.mac 00:1A:2B:3C:4D:5E` |
| `osint.guid <uuid>` | version/variant/timestamp | `osint.guid 550e8400-…` |
| `osint.asn <asn\|ip>` | BGP/PeeringDB/RIPE links | `osint.asn AS13335` |
| `osint.chain <addr>` | ตรวจรูปแบบ + explorer ตามเชน | `osint.chain bc1…` |
| `osint.tld <tld>` | gTLD หรือ ccTLD + registry | `osint.tld .th` |
| `osint.wayback <url>` | snapshot ทุก archive | `osint.wayback example.com` |

> ใช้กับบัญชี/เป้าหมายของคุณเอง หรือข้อมูลสาธารณะที่ได้รับอนุญาตเท่านั้น
> การตรวจ breach หรือ scraping ต้องเป็นไปตามกฎหมายและข้อกำหนดของบริการนั้น

### 5.5 mobile / Termux (51 คำสั่ง)

| คำสั่ง | ทำอะไร |
|---|---|
| `mobile.status` | platform, Android version, ขนาดจอ, termux-api, storage, config dir |
| `mobile.doctor` | ตรวจ python/pip/git/termux-api/storage/launcher |
| `mobile.pkg [filter]` | แพ็กเกจ Termux ที่ติดตั้ง (dpkg) |
| `mobile.pkg-search <term>` | ค้นแพ็กเกจด้วย `pkg search` |
| `mobile.pkg-install <pkg…>` | ติดตั้งด้วย `pkg install -y` (มีคำยืนยัน/`--yes`) |
| `mobile.storage` | `~/storage` + พื้นที่ว่าง |
| `mobile.setup-storage` | เรียก `termux-setup-storage` |
| `mobile.iface` | `ip addr` + Wi-Fi connection info |
| `mobile.battery` | `termux-battery-status` |
| `mobile.wifi` | `termux-wifi-connectioninfo` |
| `mobile.clipboard [get\|set <text>]` | คลิปบอร์ด |
| `mobile.notify <title> [body]` | notification |
| `mobile.toast` / `mobile.vibrate` / `mobile.torch on\|off` | toast/สั่น/ไฟฉาย |
| `mobile.sensor [sensor]` | อ่านเซนเซอร์ |
| `mobile.location` | ตำแหน่ง (gps/network/passive) |
| `mobile.sms [--limit N]` / `mobile.contacts` | SMS/รายชื่อ (ต้องอนุญาตสิทธิ์) |
| `mobile.telephony` | device info + cell info |
| `mobile.share <file>` | share sheet |
| `mobile.wakelock on\|off\|status` | กัน Android ฆ่าโปรเซส |
| `mobile.tts <text>` | อ่านออกเสียง |
| `mobile.api <helper>` + `mobile.api-<helper>` (29) | เรียก Termux:API ใดก็ได้ใน allowlist |

### 5.3 Global flags (ใช้ได้กับทุกคำสั่ง)

```text
--json            แสดงผลลัพธ์เป็น JSON (คำสั่งที่รองรับ)
--yes / -y        ยืนยัน scope อัตโนมัติ (ใช้กับ load test ในโหมด non-interactive)
--dry-run         แสดงแผนของ load test โดยไม่ยิงคำขอ
--timeout 3.5     timeout ต่อ operation (clamped 0.5–60 วินาที, default จาก scope)
--limit 20        จำกัดจำนวนผลลัพธ์ของ help/search
--no-color        ปิด ANSI colour
```

ตัวอย่าง: `ngm-panel net.tcp 127.0.0.1 22,80 --json`

---

## 6. Authorization Guard / Scope / Rate Limit

### 6.1 หลักการ

1. ทุกคำสั่งที่แตะเครือข่ายเรียก `ScopeGuard.authorize(host, port)` **ก่อน** ทำงาน
2. host ต้องตรงกับรายการใน `allowed_targets.json` (exact / `*.wildcard` / CIDR / glob)
3. ถ้าระบุ `ports` ไว้ ต้องใช้พอร์ตที่อนุญาตเท่านั้น
4. IP ที่ resolve ได้จะถูกตรวจด้วย `check_ip()` — private/loopback/reserved ถูกบล็อกถ้า `allow_private_networks=false`
5. Load test ต้องยืนยันขอบเขต (หรือ `--yes`) และถูก clamp ด้วย `limits`

ไฟล์ของผู้ใช้: `%USERPROFILE%\.ngm-panel\allowed_targets.json` (สร้างจากค่าเริ่มต้นในตัวโปรแกรมครั้งแรก)

```powershell
ngm-panel scope list
ngm-panel scope add mysite.local --ports 80,443 --note "my staging"
ngm-panel scope add 10.0.0.0/24
ngm-panel scope check mysite.local 443
ngm-panel scope remove mysite.local
ngm-panel scope path
```

### 6.2 โครงสร้างไฟล์

```json
{
  "version": 1,
  "limits": {
    "max_rps": 5.0,
    "max_concurrency": 20,
    "timeout_seconds": 5.0,
    "request_cap": 2000,
    "max_duration_seconds": 120
  },
  "allow_private_networks": true,
  "require_confirmation": true,
  "targets": [
    { "host": "localhost", "note": "this machine" },
    { "host": "example.com", "ports": [80, 443], "note": "documentation domain" },
    { "host": "*.lab.internal" },
    { "host": "192.168.1.0/24" }
  ]
}
```

### 6.3 ขีดจำกัดที่บังคับใช้จริง

| ค่า | ผล |
|---|---|
| `max_rps` | ตัวคุมจังหวะคำขอ (interval = 1/rps) — ขอเกินจะถูก clamp |
| `max_concurrency` | จำนวน worker thread สูงสุด |
| `max_duration_seconds` | ระยะเวลาสูงสุดของ load test |
| `request_cap` | จำนวนคำขอรวมสูงสุด (หยุดเองเมื่อถึง) |
| `timeout_seconds` | timeout ของ TCP/HTTP/TLS ต่อ operation |
| `allow_private_networks=false` | ห้ามแตะ 127.0.0.0/8, 10/8, 172.16/12, 192.168/16, link-local, multicast |

`Ctrl+C` ระหว่าง `web.test-l7` / `web.test-l4` / `web.test-flood`:
หยุด worker ทั้งหมด, พิมพ์สถิติบางส่วน และไม่ทิ้ง thread ค้าง

---

## 7. Catalog 5,000+ คำสั่ง และวิธีขยาย

### 7.1 ตรวจจำนวน

```powershell
ngm-panel catalog            # ตารางหมวด + families + สถานะ
ngm-panel catalog --check    # exit code 0 เมื่อ >= 5000 และทุกคำสั่งสมบูรณ์
ngm-panel osint.catalog      # สรุปจำนวน OSINT แยก family
ngm-panel list osint         # ชื่อคำสั่ง OSINT ทั้งหมด
```

ผลปัจจุบัน: **5,101 คำสั่ง** ใน 9 หมวด
(`net` 1,126 · `osint` 3,652 · `web` 84 · `file` 67 · `proc` 54 · `mobile` 51 ·
`sys` 50 · `diag` 14 · `sec` 3)

### 7.2 เพิ่มคำสั่งเดี่ยว (1 นาที)

สร้าง `ngm_panel/commands/mytools.py`:

```python
from ..registry import Registry

def cmd_hello(ctx, argv):
    who = ctx.need(argv, 0, "mytool.hello <name>", "ชื่อ")
    ctx.console.ok(f"hello {who} (local only)")
    return 0

def register(registry: Registry) -> None:
    registry.add(
        cmd_hello,
        name="mytool.hello",
        category="sys",
        usage="mytool.hello <name>",
        description="ทักทายจากในเครื่อง",
    )
```

ไม่ต้องแก้ไฟล์อื่น — `Registry.load()` จะ import ให้อัตโนมัติ (ชื่อซ้ำจะ raise ตอนโหลด)

### 7.3 เพิ่มคำสั่งแบบ family (หลักพัน)

เพิ่มใน `ngm_panel/catalog.py` ภายใน `register()`:

```python
codes = ["200", "301", "404", "500"]
_family(
    registry, "web.expect", "web",
    [(code, web.make_expect_command(code), f"คาดหวัง HTTP {code}") for code in codes],
    "HTTP status expectation presets",
)
```

ทุกสมาชิกจะได้ `name`, `category`, `usage`, `description`, `handler`, `family`
และถูกยุบรวมในหน้าจอ help โดยอัตโนมัติ

---

## 8. แพ็กเป็น `.exe` ด้วย PyInstaller

### 8.1 ต้องมีอะไร

- Windows 10/11 x64
- Python 3.9+ (ทดสอบกับ 3.12)
- `pyinstaller>=6.0` (อยู่ใน `requirements-dev.txt`)

### 8.2 build ด้วยสคริปต์ (แนะนำ)

```powershell
# รัน test + catalog check + build + smoke test
powershell -ExecutionPolicy Bypass -File packaging\build.ps1

# build พร้อม installer (ต้องมี Inno Setup 6)
powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -Installer

# ข้าม test (ไม่แนะนำ)
powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -SkipTests
```

หรือ `packaging\build.bat` สำหรับ cmd.exe

ผลลัพธ์: `dist\ngm-panel.exe` (ไฟล์เดียว, ฝัง `ngm_panel/data/allowed_targets.json` ไว้ข้างใน)

### 8.3 build ด้วยมือทีละขั้น

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip pyinstaller
python -m unittest discover -s tests
python -m ngm_panel catalog --check
python -m PyInstaller packaging\ngm-panel.spec --noconfirm --clean

# smoke test
.\dist\ngm-panel.exe --version
.\dist\ngm-panel.exe doctor
.\dist\ngm-panel.exe catalog --check
.\dist\ngm-panel.exe net.local

# ทดสอบโหมดหน้าจอเต็ม
.\dist\ngm-panel.exe run
```

**หมายเหตุทางเทคนิค**

- `console=True` เพราะเป็น terminal tool
- `hiddenimports=collect_submodules("ngm_panel.commands")` กัน auto-discovery หายหลัง freeze
- `datas` ฝังค่าเริ่มต้น scope ไว้ใน `_MEIPASS/ngm_panel/data`
- ไม่มี dependency ภายนอก → exe เล็กและไม่ต้องมี Python บนเครื่องปลายทาง
- ถ้าต้องการไอคอน: วาง `packaging\ngm-panel.ico` แล้วเพิ่ม `--icon` หรือเปิดใน spec

### 8.4 อัปเดต PATH แบบ manual

```powershell
$dir = (Resolve-Path .\dist).Path
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$dir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
}
```

---

## 9. Installer (Inno Setup) + PATH อัตโนมัติ

ไฟล์: `packaging\installer\ngm-panel.iss`

```powershell
winget install --id JRSoftware.InnoSetup -e     # ติดตั้ง Inno Setup 6
powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -Installer
# ผลลัพธ์: dist\ngm-panel-1.0.0-setup.exe
```

สิ่งที่ installer ทำ:

1. ติดตั้ง `ngm-panel.exe` ลง `{autopf}\ngm-panel` (user scope: `%LOCALAPPDATA%\Programs\ngm-panel`)
2. เพิ่มโฟลเดอร์ลง **PATH ของผู้ใช้** (`HKCU\Environment\Path`) — ไม่ต้อง admin
3. broadcast `WM_SETTINGCHANGE` ให้ terminal ใหม่เห็น PATH ทันที
4. สร้าง Start Menu shortcut (`ngm-panel`, `ngm-panel doctor`) และ uninstaller
5. ตอนถอนการติดตั้ง จะลบ PATH ที่เพิ่มไว้ให้เอง

หลังติดตั้ง เปิด terminal ใหม่แล้ว:

```powershell
ngm-panel doctor
ngm-panel run
```

---

## 10. เผยแพร่ผ่าน winget

Manifest อยู่ที่ `packaging\winget\manifests\n\NGM\NgmPanel\1.1.1\`
(`NGM.NgmPanel.yaml`, `.installer.yaml`, `.locale.en-US.yaml`, schema 1.6.0, `InstallerType: inno`)

### 10.1 คำสั่ง winget ที่ผู้ใช้ปลายทางจะใช้

```powershell
winget search ngm-panel
winget show --id NGM.NgmPanel -e
winget install --id NGM.NgmPanel -e
winget install --id NGM.NgmPanel -e --silent
winget install --id NGM.NgmPanel -e --scope user
winget upgrade --id NGM.NgmPanel -e
winget uninstall --id NGM.NgmPanel -e
```

### 10.2 ทดสอบ manifest บนเครื่องก่อน submit

```powershell
# ตรวจ schema
winget validate --manifest packaging\winget\manifests\n\NGM\NgmPanel\1.1.1

# ติดตั้งจาก manifest ในเครื่อง (ไม่ต้องรอ publish)
winget install --manifest packaging\winget\manifests\n\NGM\NgmPanel\1.1.1

# ถอน
winget uninstall --id NGM.NgmPanel -e
```

### 10.3 ก่อน submit ต้องแก้ค่าจริง 3 จุด

1. `NGM.NgmPanel.installer.yaml` → `InstallerUrl` ให้ชี้ release asset จริง
2. `InstallerSha256` → ค่าจริง:

   ```powershell
   Get-FileHash .\dist\ngm-panel-1.1.1-setup.exe -Algorithm SHA256
   ```

3. `ProductCode` → ต้องตรงกับ `AppId` ใน `ngm-panel.iss`
   (ปัจจุบัน `{8F3C2B7A-5D14-4E6B-9C2F-A1D4E7B39C50}`)
   และเปลี่ยน `Publisher`/URLs ให้เป็นของคุณ

### 10.4 submit เข้า winget-pkgs

```powershell
# วิธีที่แนะนำ: wingetcreate (ติดตั้ง: winget install Microsoft.WingetCreate)
wingetcreate submit --token <GITHUB_TOKEN> packaging\winget\manifests\n\NGM\NgmPanel\1.1.1

# หรือ fork microsoft/winget-pkgs แล้วคัดลอกโฟลเดอร์นี้เข้า:
# manifests/n/NGM/NgmPanel/1.1.1/  →  เปิด PR
```

อัปเดตเวอร์ชันครั้งถัดไป:

```powershell
wingetcreate update NGM.NgmPanel --version 1.1.1 `
  --urls https://github.com/NGM/ngm-panel/releases/download/v1.1.1/ngm-panel-1.1.1-setup.exe `
  --submit --token <GITHUB_TOKEN>
```

### 10.5 อัปเดตเวอร์ชันใหม่ตลอดอายุการใช้งาน

คำสั่งเดียวใช้ได้ทั้ง Windows และ Termux — ตัวโปรแกรมตรวจแพลตฟอร์มเอง:

```bash
ngm-panel update           # พิมพ์คำสั่ง winget / pkg / git / pip ที่ต้องใช้
ngm-panel update --run     # รันคำสั่งเหล่านั้นให้ทันที (ต้องมี winget/pkg ตามแพลตฟอร์ม)
ngm-panel update --json    # ผลลัพธ์แบบ JSON สำหรับสคริปต์
```

บน Windows จะเรียก `winget source update` แล้ว `winget upgrade --id NGM.NgmPanel -e --silent`
ส่วน Termux จะเรียก `pkg update -y && pkg upgrade -y` ตามด้วย `git pull --ff-only` +
`pip install -e .` (ถ้าเป็น git checkout) หรือ `pip install --upgrade ngm-panel`

หลังอัปเดตให้ปิด panel เดิม (`exit`) แล้วเปิดใหม่ หน้าจอจึงจะโหลดโค้ดเวอร์ชันล่าสุด

> หมายเหตุ: `winget install NGM.NgmPanel` จะใช้ได้จริงหลัง manifest ถูก merge เข้า repository กลาง
> ก่อนหน้านั้นใช้ `winget install --manifest …` ตามหัวข้อ 10.2

---

## 11. การทดสอบ

### 11.1 Offline test suite (ไม่ต้องใช้เน็ต)

```powershell
python -m unittest discover -s tests -v
```

ครอบคลุม: registry ≥ 5000 + OSINT ≥ 3500 + ฟิลด์ครบ + ชื่อไม่ซ้ำ, family expansion,
lookup แบบ case/underscore, scope guard (exact / wildcard / CIDR / ports / private IP / add-remove / duplicate),
help ทุกโหมด, flag parser, console helpers, host/URL normalization, security header report, config paths,
Termux detection + narrow (stacked) tables, mobile commands, และ OSINT engine
(hash/identify/JWT/encode/phone/domain/username/dork/IP/geo/crypto/PNG metadata/tool/source/breach/UA/GUID/MAC)

ผลที่รันจริงใน repo นี้: **72 tests — OK**

### 11.2 ตรวจ catalog

```powershell
python -m ngm_panel catalog --check   # exit 0 = ผ่าน
python -m ngm_panel doctor
```

### 11.3 ทดสอบกับเซิร์ฟเวอร์ในเครื่อง (ไม่แตะระบบคนอื่น)

```powershell
# เปิด HTTP server ท้องถิ่น
python -m http.server 8765 --bind 127.0.0.1

# อีกหน้าต่าง
ngm-panel net.tcp 127.0.0.1 8765
ngm-panel web.scan http://127.0.0.1:8765
ngm-panel web.path-robots http://127.0.0.1:8765
ngm-panel web.test-l7 http://127.0.0.1:8765 -n 2 -d 5 -r 5
ngm-panel web.test-l4 127.0.0.1 8765 -n 2 -d 5 -r 5
ngm-panel web.test-flood http://127.0.0.1:8765 -n 4 -d 5 -r 8
# กด Ctrl+C ระหว่างเทสต์ → ต้องได้ partial summary และกลับ prompt
```

### 11.4 ทดสอบว่า guard ทำงาน

```powershell
ngm-panel net.tcp example.net 80          # ต้อง exit code 3 + แนะนำให้ scope add
ngm-panel scope add example.net --ports 80
ngm-panel net.tcp example.net 80          # ผ่าน guard
ngm-panel net.tcp example.net 22          # ต้องถูกปฏิเสธ (port ไม่อยู่ใน scope)
```

### 11.5 Checklist ก่อนปล่อย release

- [ ] `python -m unittest discover -s tests` ผ่าน
- [ ] `python -m ngm_panel catalog --check` ผ่าน
- [ ] `packaging\build.ps1` ผ่าน และ `dist\ngm-panel.exe doctor` ทำงาน
- [ ] `dist\ngm-panel.exe run` เข้า/ออก alternate screen ถูกต้อง
- [ ] ติดตั้ง installer → เปิด terminal ใหม่ → `ngm-panel doctor` ใช้ได้
- [ ] `winget validate --manifest …` ผ่าน และ SHA256 ตรงกับไฟล์จริง

---

## 12. ความปลอดภัยและขอบเขตความรับผิดชอบ

### OSINT

- OSINT ใน ngm-panel เป็น **passive-first**: สร้างลิงก์และวิเคราะห์ข้อมูลในเครื่อง
  การยิงเน็ตต้องมี `--check`/`--rdap` และ host ต้องอยู่ใน `allowed_targets.json`
- ใช้กับบัญชี/โดเมนของคุณเอง หรือเป้าหมายที่ได้รับอนุญาตเป็นลายลักษณ์อักษร
- ไม่มีข้อมูลถูกส่งไปที่ ngm-panel — แต่การเปิดลิงก์ third-party คือการเชื่อมต่อจากเครื่องคุณเอง
  และอยู่ภายใต้ Privacy Policy/ToS ของบริการนั้น
- การตรวจ breach, data broker หรือ scraping อาจมีข้อจำกัดทางกฎหมายในบางประเทศ — ตรวจสอบก่อนใช้

- ใช้กับ **ระบบที่คุณเป็นเจ้าของหรือได้รับอนุญาตเป็นลายลักษณ์อักษรเท่านั้น**
  (`allowed_targets.json` เป็นด่านบังคับ ไม่ใช่แค่คำเตือน)
- โปรแกรมไม่มีการเชื่อมต่อกลับไปยังเซิร์ฟเวอร์ของผู้พัฒนา และไม่เก็บ telemetry
- ข้อมูลที่เก็บในเครื่อง: `%USERPROFILE%\.ngm-panel\`
  (`allowed_targets.json`, `history`, `settings.json` ถ้ามี)
- ค่า environment ที่ชื่อมี `KEY/TOKEN/SECRET/PASSWORD/...` จะถูกปิดบังใน `sys.env`
- `proc.kill` และการยิง load test ต้องยืนยันก่อนทุกครั้ง (ยกเว้น `--yes` ที่ผู้ใช้ตั้งใจ)
- Rate/concurrency/duration/request cap ถูก clamp จากไฟล์ scope เสมอ — ไม่มีโหมด "ไม่จำกัด"
- `web.test-flood` คือ **controlled load benchmark** ที่มีขอบเขต ไม่ใช่เครื่องมือโจมตีแบบไม่มีที่สิ้นสุด

MIT License — ดู [LICENSE](LICENSE)
