"""Command catalog generator.

Hand-written commands live in :mod:`ngm_panel.commands`; this module expands
compact *families* into concrete, individually registered, individually working
commands. Adding a family entry here grows the catalog without touching the
engine or any `if/elif` chain.

Current families
----------------
net.tcp-<port>        1,109 presets (every TCP port 1-1024 + named higher ports)
net.dns-<TYPE>        10 record types
web.header-<header>   header probes
web.method-<verb>     HTTP verbs
web.path-<slug>       curated polite paths
diag.ping-size-<n>    packet-size presets
file.find-<ext>       extension scans
proc.service-<name>   Windows service presets
sys.cim-<class>       WMI/CIM class queries

OSINT families live in :mod:`ngm_panel.osint_catalog` (3,500+ generated
commands) so this module stays focused on local system/network families.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Tuple

from . import net_utils, system
from .commands import diag, files, net, proc, sysinfo, tester, web
from .registry import Registry

PORT_NAMES: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp-client", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmp-trap", 179: "bgp", 194: "irc", 389: "ldap",
    443: "https", 445: "microsoft-ds", 464: "kpasswd", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "lpd", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 646: "ldp", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-tls", 2483: "oracle-alt", 3000: "dev-http", 3128: "squid",
    3268: "global-catalog", 3269: "global-catalog-ssl", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4000: "dev-http", 4200: "angular",
    4369: "epmd", 4443: "https-alt", 4505: "salt", 4506: "salt-return",
    5000: "dev-http", 5060: "sip", 5061: "sips", 5173: "vite", 5222: "xmpp",
    5353: "mdns", 5432: "postgresql", 5555: "adb", 5601: "kibana",
    5672: "amqp", 5683: "coap", 5900: "vnc", 5984: "couchdb", 5985: "winrm-http",
    5986: "winrm-https", 6000: "x11", 6379: "redis", 6443: "k8s-api",
    6667: "irc", 7001: "weblogic", 7199: "cassandra-jmx", 7474: "neo4j",
    8000: "dev-http", 8008: "http-alt", 8009: "ajp", 8080: "http-proxy",
    8081: "http-alt", 8086: "influxdb", 8088: "yarn", 8090: "http-alt",
    8161: "activemq", 8443: "https-alt", 8500: "consul", 8529: "arangodb",
    8888: "jupyter", 8983: "solr", 9000: "php-fpm", 9042: "cassandra",
    9090: "prometheus", 9092: "kafka", 9100: "node-exporter", 9200: "elasticsearch",
    9300: "elasticsearch-transport", 9418: "git", 9443: "https-alt",
    9999: "debug", 10000: "webmin", 10250: "kubelet", 10255: "kubelet-ro",
    11211: "memcached", 15672: "rabbitmq-mgmt", 16379: "redis-alt",
    25565: "minecraft", 27017: "mongodb", 27018: "mongodb-shard",
    50000: "sap", 50070: "hadoop-namenode", 61616: "activemq-openwire",
}

DNS_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA"]

HEADER_PROBES: List[str] = []
for _header in net_utils.COMMON_HEADERS + [name for name, _ in net_utils.SECURITY_HEADERS]:
    if _header not in HEADER_PROBES:
        HEADER_PROBES.append(_header)

HTTP_METHODS = ["HEAD", "GET", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]

WEB_PATHS: List[Tuple[str, str, str]] = [
    ("root", "/", "หน้าแรก"),
    ("robots", "/robots.txt", "robots.txt"),
    ("sitemap", "/sitemap.xml", "sitemap.xml"),
    ("security-txt", "/.well-known/security.txt", "security.txt"),
    ("humans", "/humans.txt", "humans.txt"),
    ("favicon", "/favicon.ico", "favicon"),
    ("manifest", "/manifest.json", "web app manifest"),
    ("ads-txt", "/ads.txt", "ads.txt"),
    ("crossdomain", "/crossdomain.xml", "crossdomain policy"),
    ("health", "/health", "health endpoint"),
    ("healthz", "/healthz", "healthz endpoint"),
    ("status", "/status", "status page"),
    ("metrics", "/metrics", "metrics endpoint"),
    ("version", "/version", "version endpoint"),
    ("api", "/api", "API root"),
    ("api-health", "/api/health", "API health"),
    ("login", "/login", "login page"),
    ("admin", "/admin", "admin entry (expect 401/403)"),
    ("wp-login", "/wp-login.php", "WordPress login"),
    ("wp-json", "/wp-json", "WordPress REST root"),
    ("phpinfo", "/phpinfo.php", "phpinfo (should be blocked)"),
    ("env", "/.env", "leaked .env (should be 404)"),
    ("git-config", "/.git/config", "exposed git config (should be 404)"),
    ("backup-zip", "/backup.zip", "backup archive (should be 404)"),
    ("server-status", "/server-status", "Apache status (should be blocked)"),
    ("actuator", "/actuator", "Spring actuator"),
    ("actuator-health", "/actuator/health", "Spring health"),
    ("swagger", "/swagger-ui/index.html", "Swagger UI"),
    ("openapi", "/openapi.json", "OpenAPI document"),
    ("graphql", "/graphql", "GraphQL endpoint"),
    ("feed", "/feed", "RSS feed"),
    ("rss", "/rss.xml", "RSS XML"),
    ("404", "/this-path-should-not-exist-ngm", "404 behaviour probe"),
    ("csp-report", "/csp-report", "CSP report endpoint"),
    ("apple-touch", "/apple-touch-icon.png", "apple touch icon"),
    ("gpc", "/.well-known/gpc.json", "global privacy control"),
]

EXTENSIONS = [
    "txt", "log", "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf",
    "csv", "md", "html", "htm", "css", "js", "ts", "jsx", "tsx", "py",
    "ps1", "bat", "cmd", "sh", "sql", "db", "sqlite", "bak", "old", "tmp",
    "zip", "rar", "7z", "tar", "gz", "iso", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "png", "jpg", "jpeg", "gif", "svg", "ico", "mp3",
    "mp4", "mkv", "wav", "exe", "dll", "msi", "sys", "pem", "key", "crt",
]

PING_SIZES = [32, 64, 128, 256, 512, 1024, 1200, 1400]

EXCLUDED_SERVICES: set = set()


def _family(
    registry: Registry,
    family: str,
    category: str,
    members: List[Tuple[str, Callable, str]],
    description: str,
) -> None:
    """Register one generated family; every member is a full Command."""
    for suffix, handler, member_description in members:
        registry.add(
            handler,
            name=f"{family}-{suffix}",
            category=category,
            usage=f"{family}-{suffix} <target>",
            description=member_description,
            danger="scope" if category in {"net", "web", "diag", "sec"} else "safe",
            family=family,
        )


def register(registry: Registry) -> None:
    # ------------------------------------------------------------- net.tcp
    tcp_members = []
    for port in sorted(set(range(1, 1025)) | set(PORT_NAMES)):
        service = PORT_NAMES.get(port, "")
        description = f"ตรวจ TCP port {port}" + (f" ({service})" if service else " (ไม่ใช่ well-known port)")
        tcp_members.append((str(port), net.make_port_command(port, service), description))
    _family(registry, "net.tcp", "net", tcp_members,
            "TCP port presets — one command per port (1-1024)")

    # ------------------------------------------------------------- net.dns
    dns_members = []
    for record_type in DNS_TYPES:
        dns_members.append(
            (
                record_type.lower(),
                _dns_type_handler(record_type),
                f"สอบถาม DNS record ชนิด {record_type}",
            )
        )
    _family(registry, "net.dns", "net", dns_members, "DNS record type presets")

    # ---------------------------------------------------------- web.header
    header_members = []
    for header in HEADER_PROBES:
        slug = header.lower().replace("_", "-")
        header_members.append((slug, web.make_header_command(header), f"ตรวจ header {header}"))
    _family(registry, "web.header", "web", header_members, "Header probe presets")

    # ---------------------------------------------------------- web.method
    method_members = [
        (verb.lower(), web.make_method_command(verb), f"ส่ง HTTP {verb} แบบควบคุม")
        for verb in HTTP_METHODS
    ]
    _family(registry, "web.method", "web", method_members, "HTTP method presets")

    # ------------------------------------------------------------ web.path
    path_members = [
        (slug, web.make_path_command(path), f"ตรวจ path {path} — {label}")
        for slug, path, label in WEB_PATHS
    ]
    _family(registry, "web.path", "web", path_members, "Curated path probes")

    # ----------------------------------------------------- diag.ping-size
    ping_members = [
        (str(size), diag.make_ping_size_command(size), f"ping ด้วย payload {size} bytes")
        for size in PING_SIZES
    ]
    _family(registry, "diag.ping-size", "diag", ping_members, "Ping payload-size presets")

    # -------------------------------------------------------- file.find
    ext_members = [
        (ext, files.make_extension_command(ext), f"ค้นหาไฟล์ *.{ext} ใต้โฟลเดอร์ที่ระบุ")
        for ext in EXTENSIONS
    ]
    _family(registry, "file.find", "file", ext_members, "File extension search presets")

    # ----------------------------------------------------- proc.service
    service_members = [
        (name, proc.make_service_command(name), f"สถานะ Windows service '{name}'")
        for name in dict.fromkeys(system.windows_services())
    ]
    _family(registry, "proc.service", "proc", service_members, "Windows service presets")

    # --------------------------------------------------------- sys.cim
    cim_members = [
        (class_name.lower().replace("_", "-"), sysinfo.make_cim_command(class_name),
         f"query CIM class {class_name}")
        for class_name in system.cim_classes()
    ]
    _family(registry, "sys.cim", "sys", cim_members, "WMI/CIM class presets")

    # --------------------------------------------------------------- OSINT
    from . import osint_catalog

    osint_catalog.register(registry)


def _dns_type_handler(record_type: str):
    def handler(ctx, argv: List[str]) -> int:
        host = ctx.need(argv, 0, f"net.dns-{record_type.lower()} <name>", "ชื่อโดเมน")
        return net.cmd_dns(ctx, [host, record_type])

    return handler


def spec_summary(registry: Registry) -> List[Tuple[str, int, str]]:
    rows: List[Tuple[str, int, str]] = []
    descriptions = {
        "net.tcp": "TCP port presets 1-1024",
        "net.dns": "DNS record types",
        "web.header": "response header probes",
        "web.method": "HTTP verbs",
        "web.path": "curated paths",
        "diag.ping-size": "ping payload sizes",
        "file.find": "file extension scans",
        "proc.service": "Windows services",
        "sys.cim": "WMI/CIM classes",
        "mobile.api": "Termux:API helpers",
    }
    from .osint_catalog import FAMILY_DESCRIPTIONS

    descriptions.update(FAMILY_DESCRIPTIONS)
    for family, members in registry.families().items():
        rows.append((family, len(members), descriptions.get(family, "generated family")))
    return rows
