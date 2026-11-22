"""Network primitives: host parsing, IP classification, TCP probing, HTTP, TLS."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

USER_AGENT = "ngm-panel/1.0 (local authorized scope check)"


def normalize_host(raw: str) -> str:
    """Accept 'example.com', 'https://example.com:8443/x', '[::1]:80' and return the host."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else "//" + raw
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        host = None
    if host:
        return host.strip("[]").lower().rstrip(".")
    return raw.split("/")[0].split(":")[0].strip("[]").lower().rstrip(".")


def split_url(raw: str) -> Tuple[str, str, int, str]:
    """Return (scheme, host, port, path) with sensible defaults."""
    candidate = raw if "://" in raw else "https://" + raw
    parts = urlsplit(candidate)
    scheme = (parts.scheme or "https").lower()
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return scheme, host, port, path


def parse_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_ip(value: str) -> bool:
    return parse_ip(value) is not None


def ip_is_public(value: str) -> bool:
    address = parse_ip(value)
    if address is None:
        return False
    return bool(address.is_global)


def ip_in_cidr(value: str, cidr: str) -> bool:
    address = parse_ip(value)
    if address is None:
        return False
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return address.version == network.version and address in network


def resolve(host: str, qtype: str = "A", timeout: float = 5.0) -> List[str]:
    """Resolve a hostname to A/AAAA records (IP literals pass straight through)."""
    from . import dnsmini

    address = parse_ip(host)
    if address is not None:
        if qtype == "A" and address.version != 4:
            return []
        if qtype == "AAAA" and address.version != 6:
            return []
        return [str(address)]
    try:
        return dnsmini.resolve_name(host, qtype)
    except Exception:
        return []


@dataclass
class TcpResult:
    host: str
    port: int
    ok: bool
    latency_ms: float
    error: str = ""


def tcp_connect(host: str, port: int, timeout: float = 5.0) -> TcpResult:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - started) * 1000
            return TcpResult(host, port, True, elapsed)
    except OSError as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return TcpResult(host, port, False, elapsed, f"{type(exc).__name__}: {exc}")


def reverse_dns(ip: str, timeout: float = 5.0) -> List[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return [name[0] for name in socket.gethostbyaddr(ip)[:1]]
    except (OSError, socket.herror):
        return []
    finally:
        socket.setdefaulttimeout(None)


@dataclass
class HttpResult:
    ok: bool
    url: str
    status: int = 0
    reason: str = ""
    headers: Dict[str, List[str]] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float = 0.0
    error: str = ""
    http_version: str = ""

    def header(self, name: str) -> Optional[str]:
        for key, values in self.headers.items():
            if key.lower() == name.lower():
                return "; ".join(values)
        return None

    def header_names(self) -> List[str]:
        return list(self.headers.keys())


def http_request(
    url: str,
    method: str = "GET",
    timeout: float = 5.0,
    max_body: int = 65536,
    extra_headers: Optional[Dict[str, str]] = None,
) -> HttpResult:
    scheme, host, port, path = split_url(url)
    if not host:
        return HttpResult(False, url, error="invalid URL / missing host")
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
    if extra_headers:
        headers.update(extra_headers)
    started = time.perf_counter()
    connection = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request(method.upper(), path, headers=headers)
        response = connection.getresponse()
        body = response.read(max_body) if method.upper() != "HEAD" else b""
        elapsed = (time.perf_counter() - started) * 1000
        collected: Dict[str, List[str]] = {}
        for key, value in response.getheaders():
            collected.setdefault(key, []).append(value)
        return HttpResult(
            ok=True,
            url=url,
            status=response.status,
            reason=response.reason or "",
            headers=collected,
            body=body,
            elapsed_ms=elapsed,
            http_version={10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(response.version, "HTTP/1.1"),
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return HttpResult(False, url, elapsed_ms=elapsed, error=f"{type(exc).__name__}: {exc}")
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _decode_der_certificate(der: bytes) -> Dict[str, object]:
    """Decode a DER certificate using CPython's own test decoder (no dependencies)."""
    import ssl as _ssl

    path = None
    try:
        with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as handle:
            path = handle.name
            handle.write(ssl.DER_cert_to_PEM_cert(der).encode("ascii"))
        return dict(_ssl._ssl._test_decode_cert(path))  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        if path:
            try:
                import os

                os.unlink(path)
            except OSError:
                pass


@dataclass
class TlsInfo:
    ok: bool
    host: str
    port: int
    version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    subject_alt_names: List[str] = field(default_factory=list)
    verified: bool = False
    error: str = ""

    def days_left(self) -> Optional[int]:
        if not self.not_after:
            return None
        from datetime import datetime, timezone

        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
            try:
                expiry = datetime.strptime(self.not_after, fmt).replace(tzinfo=timezone.utc)
                return int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400)
            except ValueError:
                continue
        return None


def _format_name(entries) -> str:
    flat = []
    for group in entries or ():
        for key, value in group:
            flat.append(f"{key}={value}")
    return ", ".join(flat)


def tls_inspect(host: str, port: int = 443, timeout: float = 5.0) -> TlsInfo:
    info = TlsInfo(ok=False, host=host, port=port)
    der = b""
    verified = True
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                info.version = tls.version() or ""
                cipher = tls.cipher()
                info.cipher = f"{cipher[0]} ({cipher[1]} bit, {cipher[2]})" if cipher else ""
                cert = tls.getpeercert()
                der = tls.getpeercert(binary_form=True) or b""
    except ssl.SSLCertVerificationError as exc:
        verified = False
        info.error = f"certificate verification failed: {exc.verify_message or exc}"
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    info.version = tls.version() or ""
                    cipher = tls.cipher()
                    info.cipher = f"{cipher[0]} ({cipher[1]} bit, {cipher[2]})" if cipher else ""
                    der = tls.getpeercert(binary_form=True) or b""
                    cert = {}
        except OSError as inner:
            info.error = f"{info.error}; retry failed: {inner}"
            return info
    except (OSError, ssl.SSLError) as exc:
        info.error = f"{type(exc).__name__}: {exc}"
        return info

    if not cert and der:
        cert = _decode_der_certificate(der)
    info.ok = True
    info.verified = verified
    info.subject = _format_name(cert.get("subject"))
    info.issuer = _format_name(cert.get("issuer"))
    info.not_before = str(cert.get("notBefore", ""))
    info.not_after = str(cert.get("notAfter", ""))
    names: List[str] = []
    for kind, value in cert.get("subjectAltName", ()) or ():
        names.append(f"{kind}:{value}")
    info.subject_alt_names = names
    return info


SECURITY_HEADERS = [
    ("Strict-Transport-Security", "บังคับ HTTPS (HSTS)"),
    ("Content-Security-Policy", "จำกัดแหล่งที่มาของสคริปต์/รีซอร์ส"),
    ("X-Frame-Options", "กัน Clickjacking"),
    ("X-Content-Type-Options", "กัน MIME sniffing"),
    ("Referrer-Policy", "คุมข้อมูล Referer"),
    ("Permissions-Policy", "จำกัด Browser APIs"),
    ("Cross-Origin-Opener-Policy", "แยก browsing context"),
    ("Cross-Origin-Resource-Policy", "คุมการโหลดข้ามโดเมน"),
]

COMMON_HEADERS = [
    "server", "content-type", "content-length", "date", "cache-control", "expires",
    "last-modified", "etag", "x-powered-by", "via", "connection", "vary",
    "accept-ranges", "location", "set-cookie", "x-cache", "cf-ray", "age",
    "content-encoding", "transfer-encoding", "x-xss-protection", "x-request-id",
    "access-control-allow-origin", "alt-svc", "x-dns-prefetch-control",
]


def security_header_report(headers: Dict[str, List[str]]) -> List[Dict[str, object]]:
    lower = {key.lower(): "; ".join(values) for key, values in headers.items()}
    report = []
    for name, purpose in SECURITY_HEADERS:
        value = lower.get(name.lower())
        report.append({"header": name, "present": bool(value), "value": value or "", "purpose": purpose})
    return report
