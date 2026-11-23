#!/usr/bin/env python3
"""Render or validate the winget manifests for ngm-panel (standard library only).

Render a manifest set for a real, already-built installer::

    python packaging/winget/render_manifest.py \
        --version 1.1.1 \
        --sha256 <sha256 of ngm-panel-1.1.1-setup.exe> \
        --out packaging/winget/manifests/n/NGM/NgmPanel/1.1.1

Validate every manifest under a directory (used by CI and before submit)::

    python packaging/winget/render_manifest.py --check packaging/winget/manifests/n/NGM/NgmPanel

``--check`` verifies identity/version consistency, the Inno Setup product code,
that the download URL points at this repository's release asset and that the
SHA-256 is a real 64-character hex digest (a placeholder is reported as an
error when ``--require-sha`` is passed, e.g. in the release job).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Dict, List

PACKAGE_ID = "NGM.NgmPanel"
PACKAGE_NAME = "ngm-panel"
PUBLISHER = "NGM"
PRODUCT_CODE = "{8F3C2B7A-5D14-4E6B-9C2F-A1D4E7B39C50}"
REPO_URL = "https://github.com/noppasitdeelert-new/Truemoney-api-Noxvalis-"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INSTALLER_NAME = "ngm-panel-{version}-setup.exe"
MANIFEST_VERSION = "1.6.0"

VERSION_TEMPLATE = """\
# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.{mv}.schema.json
PackageIdentifier: {pid}
PackageVersion: {version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: {mv}
"""

INSTALLER_TEMPLATE = """\
# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.{mv}.schema.json
PackageIdentifier: {pid}
PackageVersion: {version}
InstallerLocale: en-US
InstallerType: inno
Scope: user
InstallModes:
  - interactive
  - silent
  - silentWithProgress
UpgradeBehavior: install
Commands:
  - {name}
ReleaseDate: {date}
Installers:
  - Architecture: x64
    InstallerUrl: {url}
    InstallerSha256: {sha256}
    ProductCode: "{product_code}"
    AppsAndFeaturesEntries:
      - DisplayName: {name} {version}
        DisplayVersion: {version}
        Publisher: {publisher}
ManifestType: installer
ManifestVersion: {mv}
"""

LOCALE_TEMPLATE = """\
# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.{mv}.schema.json
PackageIdentifier: {pid}
PackageVersion: {version}
PackageLocale: en-US
Publisher: {publisher}
PublisherUrl: {repo}
PublisherSupportUrl: {repo}/issues
PackageName: {name}
PackageUrl: {repo}
License: MIT
LicenseUrl: {repo}/blob/main/LICENSE
Copyright: Copyright (c) 2026 {publisher}
ShortDescription: Local-only terminal panel for Windows and Termux with 5,100+ network, system and OSINT commands.
Description: >-
  ngm-panel runs 100% locally inside its own process on your machine and also
  runs inside Termux on Android. It provides a full-screen terminal panel with
  5,100+ commands: DNS/IP lookups, TCP port checks, web/TLS inspection,
  controlled L7/L4 load tests, Windows system/process inspection, file
  utilities, Termux/mobile helpers (termux-api, storage, packages, notifications)
  and 3,600+ OSINT commands (username/email/domain/IP/dork/metadata reference
  with offline analysis). Every outbound command is checked against an
  authorized-scope file with rate, concurrency, timeout and request caps.
Moniker: {name}
Tags:
  - cli
  - network
  - diagnostics
  - security
  - osint
  - termux
  - android
  - terminal
  - windows
  - utilities
ReleaseNotesUrl: {repo}/releases/tag/v{version}
ManifestType: defaultLocale
ManifestVersion: {mv}
"""


# --------------------------------------------------------------------- helpers
def manifest_names(version: str) -> Dict[str, str]:
    return {
        "version": f"{PACKAGE_ID}.yaml",
        "installer": f"{PACKAGE_ID}.installer.yaml",
        "locale": f"{PACKAGE_ID}.locale.en-US.yaml",
    }


def installer_url(version: str) -> str:
    return f"{REPO_URL}/releases/download/v{version}/{INSTALLER_NAME.format(version=version)}"


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _field(text: str, key: str) -> str:
    match = re.search(r"^\s*" + re.escape(key) + r":\s*(.+?)\s*$", text, re.MULTILINE)
    if not match:
        return ""
    return match.group(1).strip().strip('"').strip("'")


def project_version() -> str:
    text = _read(os.path.join(REPO_ROOT, "pyproject.toml"))
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else ""


def innosetup_version() -> str:
    iss = _read(os.path.join(REPO_ROOT, "packaging", "installer", "ngm-panel.iss"))
    match = re.search(r'^#define MyAppVersion "([^"]+)"', iss, re.MULTILINE)
    return match.group(1) if match else ""


def innosetup_product_code() -> str:
    iss = _read(os.path.join(REPO_ROOT, "packaging", "installer", "ngm-panel.iss"))
    match = re.search(r"AppId=\{\{?([0-9A-Fa-f-]{36})", iss)
    return "{" + match.group(1) + "}" if match else ""


def versions_on_disk(root: str) -> List[str]:
    found = [
        name
        for name in os.listdir(root)
        if os.path.isdir(os.path.join(root, name)) and re.fullmatch(r"\d+\.\d+\.\d+", name)
    ]
    return sorted(found, key=lambda item: tuple(int(part) for part in item.split(".")))


# ------------------------------------------------------------------ validation
def check_version_dir(directory: str, require_sha: bool, repo_url: str) -> List[str]:
    problems: List[str] = []
    version = os.path.basename(directory.rstrip(os.sep))
    names = manifest_names(version)
    payload = {}

    for kind, filename in names.items():
        path = os.path.join(directory, filename)
        if not os.path.isfile(path):
            problems.append(f"{filename}: missing")
            continue
        payload[kind] = _read(path)

    parts = directory.rstrip(os.sep).split(os.sep)
    identity = "/".join(parts[-3:])
    expected_identity = PACKAGE_ID.replace(".", "/") + "/" + version
    if identity != expected_identity:
        problems.append(f"directory must end with {expected_identity}, got {identity}")
    elif len(parts) >= 4 and parts[-4].lower() != PACKAGE_ID[0].lower():
        problems.append(
            f"directory must be manifests/{PACKAGE_ID[0].lower()}/{PACKAGE_ID.replace('.', '/')}/<version>"
        )

    version_text = payload.get("version", "")
    installer_text = payload.get("installer", "")
    locale_text = payload.get("locale", "")

    for kind, text in payload.items():
        if not text:
            continue
        if _field(text, "PackageIdentifier") != PACKAGE_ID:
            problems.append(f"{names[kind]}: PackageIdentifier must be {PACKAGE_ID}")
        if _field(text, "ManifestVersion") != MANIFEST_VERSION:
            problems.append(f"{names[kind]}: ManifestVersion must be {MANIFEST_VERSION}")

    if version_text:
        if _field(version_text, "PackageVersion") != version:
            problems.append(f"{names['version']}: PackageVersion must match directory {version}")
        if _field(version_text, "ManifestType") != "version":
            problems.append(f"{names['version']}: ManifestType must be version")

    if locale_text:
        if _field(locale_text, "PackageVersion") != version:
            problems.append(f"{names['locale']}: PackageVersion must match directory {version}")
        if _field(locale_text, "ManifestType") != "defaultLocale":
            problems.append(f"{names['locale']}: ManifestType must be defaultLocale")
        for required in ("Publisher", "License", "ShortDescription", "PackageLocale"):
            if not _field(locale_text, required):
                problems.append(f"{names['locale']}: missing {required}")

    if installer_text:
        if _field(installer_text, "PackageVersion") != version:
            problems.append(f"{names['installer']}: PackageVersion must match directory {version}")
        if _field(installer_text, "InstallerType") != "inno":
            problems.append(f"{names['installer']}: InstallerType must be inno")
        url = _field(installer_text, "InstallerUrl")
        if not url.startswith("https://"):
            problems.append(f"{names['installer']}: InstallerUrl must be https")
        elif not url.startswith(repo_url.rstrip("/") + f"/releases/download/v{version}/"):
            problems.append(
                f"{names['installer']}: InstallerUrl must be "
                f"{repo_url.rstrip('/')}/releases/download/v{version}/<asset>"
            )
        sha = _field(installer_text, "InstallerSha256")
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", sha):
            problems.append(f"{names['installer']}: InstallerSha256 must be 64 hex characters")
        elif set(sha) == {"0"}:
            message = f"{names['installer']}: InstallerSha256 is still the placeholder"
            if require_sha:
                problems.append(message)
            else:
                print(f"warning: {message} (run with --require-sha after a release build)")
        product_code = _field(installer_text, "ProductCode")
        expected_code = innosetup_product_code()
        if product_code.strip('"') != expected_code:
            problems.append(
                f"{names['installer']}: ProductCode {product_code} != AppId {expected_code} in ngm-panel.iss"
            )
        if f"- {PACKAGE_NAME}" not in installer_text:
            problems.append(f"{names['installer']}: Commands must expose {PACKAGE_NAME}")

    return problems


def check_tree(root: str, require_sha: bool, repo_url: str) -> int:
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    if re.fullmatch(r"\d+\.\d+\.\d+", os.path.basename(root.rstrip(os.sep))):
        directories = [root]
        parent = os.path.dirname(root.rstrip(os.sep))
    else:
        directories = [os.path.join(root, name) for name in versions_on_disk(root)]
        parent = root

    if not directories:
        print(f"error: no version directories under {root}", file=sys.stderr)
        return 2

    failures = 0
    for directory in directories:
        problems = check_version_dir(directory, require_sha, repo_url)
        label = os.path.basename(directory)
        if problems:
            failures += 1
            print(f"FAIL {label}")
            for problem in problems:
                print(f"  - {problem}")
        else:
            print(f"ok   {label}")

    latest = os.path.basename(directories[-1].rstrip(os.sep))
    current = project_version()
    if latest != current:
        print(f"error: newest manifest is {latest} but pyproject.toml says {current}", file=sys.stderr)
        failures += 1
    iss_version = innosetup_version()
    if iss_version and iss_version != current:
        print(f"error: ngm-panel.iss says {iss_version} but pyproject.toml says {current}", file=sys.stderr)
        failures += 1

    return 1 if failures else 0


# -------------------------------------------------------------------- rendering
def render(version: str, sha256: str, url: str, out: str, date: str) -> int:
    os.makedirs(out, exist_ok=True)
    names = manifest_names(version)
    payload = {
        names["version"]: VERSION_TEMPLATE.format(pid=PACKAGE_ID, version=version, mv=MANIFEST_VERSION),
        names["installer"]: INSTALLER_TEMPLATE.format(
            pid=PACKAGE_ID,
            version=version,
            mv=MANIFEST_VERSION,
            name=PACKAGE_NAME,
            url=url,
            sha256=sha256.upper(),
            product_code=PRODUCT_CODE,
            publisher=PUBLISHER,
            date=date,
        ),
        names["locale"]: LOCALE_TEMPLATE.format(
            pid=PACKAGE_ID,
            version=version,
            mv=MANIFEST_VERSION,
            name=PACKAGE_NAME,
            publisher=PUBLISHER,
            repo=REPO_URL,
        ),
    }
    for filename, text in payload.items():
        path = os.path.join(out, filename)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        print(f"wrote {path}")

    problems = check_version_dir(out, require_sha=False, repo_url=REPO_URL)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render or validate ngm-panel winget manifests.")
    parser.add_argument("--check", metavar="DIR", help="validate a version directory or all versions under DIR")
    parser.add_argument("--version", help="version to render, e.g. 1.1.1")
    parser.add_argument("--sha256", help="SHA-256 of the built installer")
    parser.add_argument("--url", help="installer download URL (default: this repository's release asset)")
    parser.add_argument("--out", help="directory to write the three manifests into")
    parser.add_argument("--repo-url", default=REPO_URL, help="expected GitHub repository URL")
    parser.add_argument("--date", default=None, help="ReleaseDate (default: today, YYYY-MM-DD)")
    parser.add_argument("--require-sha", action="store_true", help="fail when InstallerSha256 is a placeholder")
    args = parser.parse_args(argv)

    if args.check:
        return check_tree(args.check, args.require_sha, args.repo_url.rstrip("/"))

    if not (args.version and args.sha256 and args.out):
        parser.error("render needs --version, --sha256 and --out (or use --check)")

    import datetime

    date = args.date or datetime.date.today().isoformat()
    return render(args.version, args.sha256, args.url or installer_url(args.version), args.out, date)


if __name__ == "__main__":
    raise SystemExit(main())
