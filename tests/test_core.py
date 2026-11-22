"""Offline test suite (no network needed).

Run on Windows or Linux:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import io
import json
import os
import struct
import tempfile
import unittest
import uuid

from ngm_panel import config, help_system, net_utils, system
from ngm_panel.console import Console
from ngm_panel.registry import Context, Registry, RunOptions, normalize
from ngm_panel.runner import parse_flags, parse_options
from ngm_panel.scope_cli import run_scope
from ngm_panel.scope_guard import Limits, ScopeError, ScopeGuard, Target


def build_registry() -> Registry:
    return Registry().load()


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_registry()

    def test_catalog_has_at_least_5000_commands(self) -> None:
        self.assertGreaterEqual(len(self.registry), 5000)

    def test_osint_has_at_least_3500_commands(self) -> None:
        count = self.registry.categories().get("osint", 0)
        self.assertGreaterEqual(count, 3500)

    def test_check_passes(self) -> None:
        result = self.registry.check(5000)
        self.assertTrue(result["ok"], result["problems"])

    def test_every_command_is_complete(self) -> None:
        for command in self.registry:
            self.assertTrue(command.name, command)
            self.assertIn(command.category, {"net", "web", "sys", "proc", "file", "diag", "sec", "osint", "mobile"})
            self.assertTrue(command.usage.startswith(command.name), command.name)
            self.assertTrue(command.description)
            self.assertTrue(callable(command.handler))
            self.assertIn(command.danger, {"safe", "scope", "active"})

    def test_names_are_unique_after_normalisation(self) -> None:
        names = [normalize(command.name) for command in self.registry]
        self.assertEqual(len(names), len(set(names)))

    def test_families_expand(self) -> None:
        families = self.registry.families()
        self.assertIn("net.tcp", families)
        self.assertGreaterEqual(len(families["net.tcp"]), 1024)
        for family in ("net.dns", "web.header", "web.path", "file.find", "proc.service", "sys.cim",
                       "osint.username", "osint.dork", "osint.domain", "osint.ip", "osint.tool",
                       "osint.source", "osint.phone", "osint.geo", "mobile.api"):
            self.assertIn(family, families)
        self.assertIsNotNone(self.registry.get("net.tcp-443"))
        self.assertIsNotNone(self.registry.get("net.tcp-3389"))
        self.assertIsNotNone(self.registry.get("net.dns-mx"))
        self.assertIsNotNone(self.registry.get("osint.username-github"))
        self.assertIsNotNone(self.registry.get("osint.email-gmail-com"))
        self.assertIsNotNone(self.registry.get("osint.dork-google-pdf"))
        self.assertIsNotNone(self.registry.get("osint.geo-th"))
        self.assertIsNotNone(self.registry.get("osint.phone-th"))
        self.assertIsNotNone(self.registry.get("osint.crypto-btc"))
        self.assertIsNotNone(self.registry.get("osint.ua-chrome-win11"))

    def test_lookup_is_case_and_underscore_insensitive(self) -> None:
        self.assertIsNotNone(self.registry.get("NET.IP"))
        self.assertIsNotNone(self.registry.get("web.check_header"))

    def test_search_finds_commands(self) -> None:
        names = [command.name for command in self.registry.search("headers")]
        self.assertTrue(names)

    def test_suggestions(self) -> None:
        self.assertTrue(self.registry.suggest("web.scna"))


class ScopeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.guard = ScopeGuard(
            targets=[
                Target("allowed.example", ports=[80, 443]),
                Target("*.wild.example"),
                Target("10.0.0.0/24"),
                Target("127.0.0.1"),
            ],
            limits=Limits(max_rps=3, max_concurrency=4, request_cap=50, max_duration_seconds=30),
            allow_private=True,
            scope_path=os.path.join(self.tmp.name, "allowed_targets.json"),
        )

    def test_allows_exact_host(self) -> None:
        self.assertEqual(self.guard.authorize("allowed.example", 443), "allowed.example")

    def test_rejects_unknown_host(self) -> None:
        with self.assertRaises(ScopeError):
            self.guard.authorize("evil.example")

    def test_port_restriction(self) -> None:
        with self.assertRaises(ScopeError):
            self.guard.authorize("allowed.example", 8443)
        self.assertEqual(self.guard.authorize("allowed.example", 80), "allowed.example")

    def test_wildcard_and_cidr(self) -> None:
        self.assertEqual(self.guard.authorize("api.wild.example"), "api.wild.example")
        with self.assertRaises(ScopeError):
            self.guard.authorize("wild.example.evil.net")
        self.assertEqual(self.guard.authorize("10.0.0.7"), "10.0.0.7")
        with self.assertRaises(ScopeError):
            self.guard.authorize("10.0.1.7")

    def test_url_is_normalised(self) -> None:
        self.assertEqual(self.guard.authorize("https://allowed.example/path?q=1", 443), "allowed.example")

    def test_ip_literal_in_hostname_entry(self) -> None:
        self.assertEqual(self.guard.authorize("127.0.0.1", 8000), "127.0.0.1")

    def test_private_ip_blocked_when_disallowed(self) -> None:
        guard = ScopeGuard(targets=[Target("10.0.0.0/8")], allow_private=False)
        with self.assertRaises(ScopeError):
            guard.check_ip("10.1.2.3")
        self.assertEqual(guard.check_ip("93.184.216.34"), "93.184.216.34")

    def test_limits_are_clamped(self) -> None:
        self.assertEqual(self.guard.clamp_rps(500), 3)
        self.assertEqual(self.guard.clamp_concurrency(64), 4)
        self.assertEqual(self.guard.clamp_duration(999), 30)
        self.assertEqual(self.guard.clamp_timeout(1), 1)

    def test_scope_add_and_remove(self) -> None:
        guard = ScopeGuard(targets=[], scope_path=os.path.join(self.tmp.name, "scope.json"))
        with self.assertRaises(ScopeError):
            guard.authorize("new.example")
        guard.add_target("new.example", ports="8080,8443")
        self.assertEqual(guard.authorize("new.example", 8080), "new.example")
        self.assertTrue(guard.remove_target("new.example"))
        with self.assertRaises(ScopeError):
            guard.authorize("new.example")

    def test_duplicate_add_rejected(self) -> None:
        guard = ScopeGuard(targets=[], scope_path=os.path.join(self.tmp.name, "dup.json"))
        guard.add_target("dup.example")
        with self.assertRaises(ScopeError):
            guard.add_target("dup.example")


class HelpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_registry()

    def _console(self) -> Console:
        return Console(color=False, stream=io.StringIO())

    def test_overview_lists_categories(self) -> None:
        console = self._console()
        code = help_system.show_help(console, self.registry, [])
        output = console.stream.getvalue()
        self.assertEqual(code, 0)
        for category in ("net", "web", "sys", "proc", "file", "diag", "sec", "osint", "mobile"):
            self.assertIn(category, output)
        self.assertIn(str(len(self.registry)), output)

    def test_category_and_family_views(self) -> None:
        console = self._console()
        self.assertEqual(help_system.show_help(console, self.registry, ["net"]), 0)
        self.assertIn("net.tcp-…", console.stream.getvalue())

        console = self._console()
        self.assertEqual(help_system.show_help(console, self.registry, ["net.dns"]), 0)
        self.assertIn("net.dns-mx", console.stream.getvalue())

    def test_command_detail_and_examples(self) -> None:
        console = self._console()
        self.assertEqual(help_system.show_help(console, self.registry, ["web.scan"]), 0)
        output = console.stream.getvalue()
        self.assertIn("web.scan <url>", output)
        self.assertIn("Scope", output)

    def test_search(self) -> None:
        console = self._console()
        help_system.show_help(console, self.registry, ["search", "rdp"])
        self.assertIn("net.tcp-3389", console.stream.getvalue())

    def test_unknown_topic_falls_back_to_search(self) -> None:
        console = self._console()
        self.assertEqual(help_system.show_help(console, self.registry, ["totally-unknown"]), 1)


class RunnerTests(unittest.TestCase):
    def test_global_flags(self) -> None:
        positionals, options = parse_options(["--timeout", "2.5", "host", "--json", "--yes"])
        self.assertEqual(positionals, ["host"])
        self.assertEqual(options.timeout, 2.5)
        self.assertTrue(options.json)
        self.assertTrue(options.yes)

    def test_local_flags(self) -> None:
        positionals, values = parse_flags(["example.com", "-n", "4", "-d", "5", "--cap=10", "-x"], {"n": "int", "d": "float", "cap": "int"})
        self.assertEqual(positionals, ["example.com", "-x"])
        self.assertEqual(values, {"n": 4, "d": 5.0, "cap": 10})

    def test_invalid_flag_value(self) -> None:
        with self.assertRaises(Exception):
            parse_flags(["-n", "abc"], {"n": "int"})

    def test_console_helpers(self) -> None:
        console = Console(color=False, stream=io.StringIO())
        console.table(["A", "B"], [[1, 2]])
        console.bar(0.5)
        console.paginate(["x", "y"], interactive=False)
        self.assertIn("A", console.stream.getvalue())


class NetUtilTests(unittest.TestCase):
    def test_normalize_host(self) -> None:
        self.assertEqual(net_utils.normalize_host("https://Example.com:8443/x"), "example.com")
        self.assertEqual(net_utils.normalize_host("example.com"), "example.com")
        self.assertEqual(net_utils.normalize_host("[::1]:80"), "::1")

    def test_split_url_defaults(self) -> None:
        self.assertEqual(net_utils.split_url("example.com"), ("https", "example.com", 443, "/"))
        self.assertEqual(net_utils.split_url("http://example.com:8080/a?b=1"),
                         ("http", "example.com", 8080, "/a?b=1"))

    def test_ip_helpers(self) -> None:
        self.assertTrue(net_utils.is_ip("192.168.1.1"))
        self.assertFalse(net_utils.ip_is_public("192.168.1.1"))
        self.assertTrue(net_utils.ip_is_public("93.184.216.34"))
        self.assertTrue(net_utils.ip_in_cidr("192.168.1.5", "192.168.1.0/24"))

    def test_security_header_report(self) -> None:
        report = net_utils.security_header_report({"Strict-Transport-Security": ["max-age=31536000"]})
        by_name = {item["header"]: item for item in report}
        self.assertTrue(by_name["Strict-Transport-Security"]["present"])
        self.assertFalse(by_name["Content-Security-Policy"]["present"])

    def test_invalid_scope_host_in_command(self) -> None:
        console = Console(color=False, stream=io.StringIO())
        guard = ScopeGuard(targets=[], scope_path="/tmp/unused-scope.json")
        code = run_scope(console, guard, ["check", "evil.example"])
        self.assertEqual(code, 3)


class ConfigTests(unittest.TestCase):
    def test_bundled_scope_is_valid(self) -> None:
        data = config.read_bundled_scope()
        self.assertIn("targets", data)
        self.assertIn("limits", data)
        self.assertTrue(any(target["host"] == "127.0.0.1" for target in data["targets"]))

    def test_home_override(self) -> None:
        previous = os.environ.get("NGM_PANEL_HOME")
        try:
            os.environ["NGM_PANEL_HOME"] = "/tmp/ngm-panel-test-home"
            self.assertEqual(str(config.home_dir()), "/tmp/ngm-panel-test-home")
        finally:
            if previous is None:
                os.environ.pop("NGM_PANEL_HOME", None)
            else:
                os.environ["NGM_PANEL_HOME"] = previous


def _guard(temp_dir: str) -> ScopeGuard:
    return ScopeGuard(
        targets=[Target("example.com", ports=[80, 443]), Target("127.0.0.1")],
        allow_private=True,
        scope_path=os.path.join(temp_dir, "scope.json"),
    )


def _run(registry: Registry, guard: ScopeGuard, name: str, argv, **options):
    console = Console(color=False, stream=io.StringIO())
    context = Context(registry, guard, console, RunOptions(**options))
    code = registry.require(name).handler(context, list(argv))
    return int(code or 0), console.stream.getvalue()


def _png_with_text(author: str = "Alice") -> bytes:
    payload = b"Author\x00" + author.encode()
    chunk = struct.pack(">I", len(payload)) + b"tEXt" + payload + b"\x00\x00\x00\x00"
    return b"\x89PNG\r\n\x1a\n" + chunk


class TermuxTests(unittest.TestCase):
    def test_termux_detection_from_env(self) -> None:
        keys = ("TERMUX_VERSION", "PREFIX", "ANDROID_ROOT")
        previous = {key: os.environ.get(key) for key in keys}
        try:
            os.environ["TERMUX_VERSION"] = "0.118.1"
            os.environ["PREFIX"] = "/data/data/com.termux/files/usr"
            self.assertTrue(system.is_termux())
            self.assertTrue(system.is_android())
            self.assertTrue(system.is_mobile())
            self.assertEqual(system.platform_tag(), "termux")
            self.assertIn("termux-api", system.termux_api_missing_hint("battery-status"))
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_platform_tag_without_termux(self) -> None:
        keys = ("TERMUX_VERSION", "PREFIX", "ANDROID_ROOT")
        previous = {key: os.environ.get(key) for key in keys}
        try:
            for key in keys:
                os.environ.pop(key, None)
            self.assertFalse(system.is_termux())
            self.assertIn(system.platform_tag(), {"windows", "linux", "macos"})
        finally:
            for key, value in previous.items():
                if value is not None:
                    os.environ[key] = value

    def test_narrow_layout_stacks_tables(self) -> None:
        from unittest import mock

        console = Console(color=False, stream=io.StringIO())
        with mock.patch("ngm_panel.console.narrow", return_value=True):
            console.table(["Header", "Value"], [["row", "cell"]])
        output = console.stream.getvalue()
        self.assertIn("Header", output)
        self.assertIn("cell", output)


class UpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _toggle(self, key: str, value: str):
        previous = os.environ.get(key)
        os.environ[key] = value

        def restore() -> None:
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous

        self.addCleanup(restore)

    def test_update_prints_winget_and_pkg_commands(self) -> None:
        from ngm_panel import __version__, updater

        console = Console(color=False, stream=io.StringIO())
        code = updater.run_update(console, [])
        output = console.stream.getvalue()
        self.assertEqual(code, 0)
        self.assertIn(__version__, output)
        self.assertIn("winget upgrade --id NGM.NgmPanel -e", output)
        self.assertIn("pkg update -y && pkg upgrade -y", output)
        self.assertIn("bash packaging/termux/install-termux.sh", output)
        self.assertIn("ยังไม่รันอะไร", output)

    def test_update_plan_uses_winget_on_windows(self) -> None:
        from unittest import mock

        from ngm_panel import updater

        with mock.patch("ngm_panel.updater.system.is_windows", return_value=True):
            steps = updater.plan()
            self.assertEqual(steps[0][1][:2], ["winget", "source"])
            self.assertIn("upgrade", steps[1][1])
            self.assertEqual(updater.method(), "winget")

    def test_update_plan_uses_pkg_and_pip_on_termux(self) -> None:
        from ngm_panel import updater

        self._toggle("TERMUX_VERSION", "0.118.1")
        self._toggle("PREFIX", "/data/data/com.termux/files/usr")
        steps = updater.plan()
        commands = [command[0] for _, command in steps]
        self.assertEqual(commands[:2], ["pkg", "pkg"])
        self.assertTrue(any("pip" in command for _, command in steps))

    def test_update_is_a_cli_builtin(self) -> None:
        from ngm_panel import cli

        self.assertIn("update", cli.BUILTINS)


class ShellScreenTests(unittest.TestCase):
    def test_termux_defaults_to_inline_screen(self) -> None:
        from ngm_panel.shell import Shell

        class TtyStream(io.StringIO):
            def isatty(self) -> bool:
                return True

        previous = os.environ.get("TERMUX_VERSION")
        os.environ["TERMUX_VERSION"] = "0.118.1"
        self.addCleanup(
            lambda: os.environ.pop("TERMUX_VERSION", None)
            if previous is None
            else os.environ.__setitem__("TERMUX_VERSION", previous)
        )
        with tempfile.TemporaryDirectory() as temp:
            registry = build_registry()
            guard = _guard(temp)
            shell = Shell(registry, guard, Console(color=False, stream=TtyStream()))
            self.assertFalse(shell.alt_screen)
            forced = Shell(registry, guard, Console(color=False, stream=TtyStream()),
                           force_alt_screen=True)
            self.assertTrue(forced.alt_screen)


class MobileCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_registry()

    def test_status_is_offline_and_platform_aware(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            code, output = _run(self.registry, _guard(temp), "mobile.status", [])
        self.assertEqual(code, 0)
        self.assertIn("Platform", output)
        self.assertIn("Layout", output)

    def test_api_family_exists(self) -> None:
        names = [command.name for command in self.registry.family_members("mobile.api")]
        self.assertIn("mobile.api-battery-status", names)
        self.assertGreaterEqual(len(names), 20)

    def test_unknown_api_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            code, output = _run(self.registry, _guard(temp), "mobile.api", ["nope"])
        self.assertEqual(code, 2)
        self.assertIn("ไม่รู้จัก", output)


class OsintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_registry()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.guard = _guard(self.tmp.name)

    def run_cmd(self, name: str, argv, **options):
        return _run(self.registry, self.guard, name, argv, **options)

    def test_about_reports_coverage(self) -> None:
        code, output = self.run_cmd("osint.about", [])
        self.assertEqual(code, 0)
        self.assertIn("OSINT", output)

    def test_catalog_counts_3500(self) -> None:
        code, output = self.run_cmd("osint.catalog", [])
        self.assertEqual(code, 0)
        self.assertIn("OSINT", output)
        total = len(self.registry.family_members("osint.username")) + \
            len(self.registry.family_members("osint.dork"))
        self.assertGreaterEqual(total, 1000)

    def test_sha256_matches_hashlib(self) -> None:
        import hashlib as _hashlib

        code, output = self.run_cmd("osint.hash-sha256", ["abc"])
        self.assertEqual(code, 0)
        self.assertIn(_hashlib.sha256(b"abc").hexdigest(), output)

    def test_hash_command_emits_all_algorithms(self) -> None:
        code, output = self.run_cmd("osint.hash", ["hello"])
        self.assertEqual(code, 0)
        self.assertIn("sha256", output)
        self.assertIn("base64", output.lower())

    def test_identify_hash(self) -> None:
        code, output = self.run_cmd("osint.identify-hash", ["d41d8cd98f00b204e9800998ecf8427e"])
        self.assertEqual(code, 0)
        self.assertIn("MD5", output)

    def test_jwt_decoding_and_warning(self) -> None:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "tester", "exp": 1}).encode()).decode().rstrip("=")
        code, output = self.run_cmd("osint.jwt", [f"{header}.{payload}."])
        self.assertEqual(code, 0)
        self.assertIn("tester", output)
        self.assertIn("alg=none", output)

    def test_encode_decode_roundtrip(self) -> None:
        code, output = self.run_cmd("osint.encode", ["base64", "hello world"])
        self.assertEqual(code, 0)
        self.assertIn("aGVsbG8gd29ybGQ=", output)
        code, output = self.run_cmd("osint.decode", ["base64", "aGVsbG8gd29ybGQ="])
        self.assertEqual(code, 0)
        self.assertIn("hello world", output)

    def test_phone_normalises_to_e164(self) -> None:
        code, output = self.run_cmd("osint.phone", ["+66 81 234 5678"])
        self.assertEqual(code, 0)
        self.assertIn("+66812345678", output)
        self.assertIn("Thailand", output)

    def test_country_phone_family(self) -> None:
        code, output = self.run_cmd("osint.phone-th", ["0812345678"])
        self.assertEqual(code, 0)
        self.assertIn("+66812345678", output)

    def test_domain_links(self) -> None:
        code, output = self.run_cmd("osint.domain", ["example.com"])
        self.assertEqual(code, 0)
        self.assertIn("rdap.org/domain/example.com", output)
        self.assertIn("crt.sh", output)

    def test_username_offline_lists_platforms_without_network(self) -> None:
        code, output = self.run_cmd("osint.username", ["tester", "--limit", "5"])
        self.assertEqual(code, 0)
        self.assertIn("github.com/tester", output)
        self.assertIn("ยังไม่ยิงเน็ต", output)

    def test_generated_username_command(self) -> None:
        code, output = self.run_cmd("osint.username-gitlab", ["tester"])
        self.assertEqual(code, 0)
        self.assertIn("gitlab.com/tester", output)

    def test_dork_command(self) -> None:
        code, output = self.run_cmd("osint.dork-google-pdf", [])
        self.assertEqual(code, 0)
        self.assertIn("google.com/search", output)
        self.assertIn("filetype", output)

    def test_ip_intelligence_offline(self) -> None:
        code, output = self.run_cmd("osint.ip", ["127.0.0.1"])
        self.assertEqual(code, 0)
        self.assertIn("Loopback", output)
        self.assertIn("shodan.io", output)

    def test_ip_service_family(self) -> None:
        code, output = self.run_cmd("osint.ip-shodan", ["8.8.8.8"])
        self.assertEqual(code, 0)
        self.assertIn("shodan.io", output)

    def test_geo_and_crypto(self) -> None:
        code, output = self.run_cmd("osint.geo-th", [])
        self.assertEqual(code, 0)
        self.assertIn("Thailand", output)
        code, output = self.run_cmd("osint.crypto-eth", ["0x" + "a" * 40])
        self.assertEqual(code, 0)
        self.assertIn("etherscan.io", output)

    def test_file_and_png_metadata(self) -> None:
        path = os.path.join(self.tmp.name, "sample.png")
        with open(path, "wb") as handle:
            handle.write(_png_with_text("Alice"))
        code, output = self.run_cmd("osint.file", [path])
        self.assertEqual(code, 0)
        self.assertIn("PNG image", output)
        self.assertIn("SHA256", output)
        code, output = self.run_cmd("osint.exif", [path])
        self.assertEqual(code, 0)
        self.assertIn("Alice", output)

    def test_tool_source_subdomain_breach(self) -> None:
        code, output = self.run_cmd("osint.tool-exiftool", [])
        self.assertEqual(code, 0)
        self.assertIn("exiftool.org", output)
        code, output = self.run_cmd("osint.source-wikidata", ["Bangkok"])
        self.assertEqual(code, 0)
        self.assertIn("wikidata.org", output)
        code, output = self.run_cmd("osint.subdomain-crtsh", ["example.com"])
        self.assertEqual(code, 0)
        self.assertIn("crt.sh", output)
        code, output = self.run_cmd("osint.breach-hibp", ["a@example.com"])
        self.assertEqual(code, 0)
        self.assertIn("haveibeenpwned.com", output)
        code, output = self.run_cmd("osint.breach-hibp-passwords", ["hunter2"])
        self.assertEqual(code, 0)
        self.assertIn("k-anonymity", output)

    def test_ua_presets_and_parser(self) -> None:
        code, output = self.run_cmd("osint.ua-chrome-win11", [])
        self.assertEqual(code, 0)
        self.assertIn("Chrome/131", output)
        code, output = self.run_cmd("osint.ua", ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"])
        self.assertEqual(code, 0)
        self.assertIn("Windows", output)

    def test_guid_and_mac(self) -> None:
        value = str(uuid.uuid4())
        code, output = self.run_cmd("osint.guid", [value])
        self.assertEqual(code, 0)
        self.assertIn("Version", output)
        code, output = self.run_cmd("osint.mac", ["00:1A:2B:3C:4D:5E"])
        self.assertEqual(code, 0)
        self.assertIn("00:1A:2B", output)

    def test_file_hash_covers_files_larger_than_8mb(self) -> None:
        import hashlib as _hashlib

        path = os.path.join(self.tmp.name, "big.bin")
        blob = b"ngm-panel\n" * (900 * 1024)  # ~9.4 MB: above the old 8 MB head read
        with open(path, "wb") as handle:
            handle.write(blob)
        code, output = self.run_cmd("osint.file", [path])
        self.assertEqual(code, 0)
        self.assertIn(_hashlib.md5(blob).hexdigest(), output)
        self.assertIn(_hashlib.sha1(blob).hexdigest(), output)
        self.assertIn(_hashlib.sha256(blob).hexdigest(), output)

    def test_domain_rdap_tolerates_missing_vcard(self) -> None:
        from unittest import mock

        payload = {
            "handle": "2336799_DOMAIN_COM-VRSN",
            "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
            "entities": [
                {"roles": ["registrar"], "vcardArray": []},
                {"roles": ["registrar"], "vcardArray": None},
                {"roles": ["registrar"], "vcardArray": ["vcard", []]},
                {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]]},
                {"roles": ["registrar"], "vcardArray": ["vcard", ["fn"]]},
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]},
                {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Owner"]]]},
                "not-a-dict",
            ],
        }
        guard = ScopeGuard(
            targets=[Target("rdap.org", ports=[443])],
            scope_path=os.path.join(self.tmp.name, "rdap-scope.json"),
        )
        with mock.patch("ngm_panel.commands.osint._fetch_json", return_value=(payload, None)):
            code, output = _run(self.registry, guard, "osint.domain", ["example.com", "--rdap"])
        self.assertEqual(code, 0, output)
        self.assertIn("RDAP response", output)
        self.assertIn("Example Registrar", output)

    def test_domain_rdap_survives_empty_entities(self) -> None:
        from unittest import mock

        guard = ScopeGuard(
            targets=[Target("rdap.org", ports=[443])],
            scope_path=os.path.join(self.tmp.name, "rdap-scope.json"),
        )
        for payload in ({"entities": None}, {"entities": [{}]}, {"events": None}):
            with mock.patch("ngm_panel.commands.osint._fetch_json", return_value=(payload, None)):
                code, output = _run(self.registry, guard, "osint.domain", ["example.com", "--rdap"])
            self.assertEqual(code, 0, output)
            self.assertIn("Registrar", output)

    def test_email_url_dork_and_tld(self) -> None:
        code, output = self.run_cmd("osint.email", ["analyst@example.org"])
        self.assertEqual(code, 0)
        self.assertIn("Gravatar", output)
        self.assertIn("haveibeenpwned.com", output)
        self.assertIn("MX lookup ข้าม", output)
        code, output = self.run_cmd("osint.url", ["https://example.org/login?next=%2Fhome&debug=1"])
        self.assertEqual(code, 0)
        self.assertIn("Query parameters", output)
        self.assertIn("debug", output)
        code, output = self.run_cmd("osint.dork", ["site:example.org filetype:pdf"])
        self.assertEqual(code, 0)
        self.assertIn("google.com/search", output)
        code, output = self.run_cmd("osint.tld", ["th"])
        self.assertEqual(code, 0)
        self.assertIn("Thailand", output)

    def test_asn_wayback_chain_and_links(self) -> None:
        code, output = self.run_cmd("osint.asn", ["AS15169"])
        self.assertEqual(code, 0)
        self.assertIn("bgpview.io/asn/15169", output)
        code, output = self.run_cmd("osint.wayback", ["example.org"])
        self.assertEqual(code, 0)
        self.assertIn("web.archive.org", output)
        code, output = self.run_cmd("osint.chain", ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"])
        self.assertEqual(code, 0)
        self.assertIn("blockstream.info", output)
        code, output = self.run_cmd("osint.links", ["tester"])
        self.assertEqual(code, 0)
        self.assertIn("github.com/tester", output)

    def test_every_osint_family_has_working_handler(self) -> None:
        families = [family for family in self.registry.families() if family.startswith("osint.")]
        self.assertGreaterEqual(len(families), 15)
        for family in families:
            command = self.registry.family_members(family)[0]
            self.assertTrue(callable(command.handler), family)


if __name__ == "__main__":
    unittest.main()
