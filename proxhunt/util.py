"""Small shared helpers: proxy line parsing, IP validation, misc."""
from __future__ import annotations

import ipaddress
import re
import time

IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
IPV6_TOKEN_RE = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Fa-f:])")
SCHEME_RE = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<rest>.+)$")
HOSTPORT_RE = re.compile(r"^(?P<host>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})(?::(?P<extra>.+))?$")

PROTO_ALIASES = {
    "http": "http",
    "https": "http",       # a "https" proxy is an HTTP proxy with CONNECT
    "socks": "socks5",
    "socks5": "socks5",
    "socks4": "socks4",
    "socks4a": "socks4",
}


def now() -> float:
    return time.time()


def valid_port(port: int) -> bool:
    return 0 < int(port) < 65536


def public_ipv4(value: str | None) -> str | None:
    """Return the IPv4 string if it is a usable public address, else None."""
    if not value:
        return None
    value = value.strip().strip("[]")
    m = IPV4_RE.fullmatch(value)
    if not m:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version != 4:
        return None
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return None
    return str(ip)


def extract_public_ip(text: str) -> str | None:
    """Extract the first public-looking IPv4 (preferred) or IPv6 from a judge body."""
    if not text:
        return None
    for m in IPV4_RE.finditer(text):
        ip = public_ipv4(m.group(1))
        if ip:
            return ip
    for m in IPV6_TOKEN_RE.finditer(text):
        token = m.group(1)
        if "::" not in token and token.count(":") != 7:
            continue
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue
        if ip.version == 6 and ip.is_global and not ip.ipv4_mapped:
            return str(ip)
    return None


def parse_proxy_line(line: str, default_proto: str = "http"):
    """Parse one proxy list line into (proto, host, port) or None.

    Accepts: ip:port, scheme://ip:port, ip:port:user:pass (auth tail ignored),
    whitespace-separated variants, inline comments.
    """
    if not line:
        return None
    s = line.strip()
    if not s or s.startswith(("#", ";", "//")):
        return None
    # Strip inline comments / trailing junk
    s = s.split("#", 1)[0].strip()
    s = s.split()[0] if s.split() else s
    # Remove common prefixes
    s = s.replace(",", "")
    proto = default_proto
    m = SCHEME_RE.match(s)
    if m:
        proto = PROTO_ALIASES.get(m.group("scheme").lower(), default_proto)
        s = m.group("rest")
    s = s.rstrip("/")
    m = HOSTPORT_RE.match(s)
    if not m:
        return None
    host = m.group("host")
    port = int(m.group("port"))
    ip = public_ipv4(host)
    if not ip or not valid_port(port):
        return None
    return proto, ip, port


def parse_proxy_any(value: str):
    """Parse either 'ip:port' or 'proto://ip:port'."""
    if not value:
        return None
    return parse_proxy_line(value, "http")


def fmt_proxy(proto: str, addr: str) -> str:
    return f"{proto}://{addr}"


def scheme_for(proto: str) -> str:
    return "socks5" if proto == "socks5" else ("socks4" if proto == "socks4" else "http")


def ms(value_s: float) -> int:
    return max(1, int(round(value_s * 1000)))


def human_ts(ts: float | None) -> str:
    if not ts:
        return "-"
    delta = max(0, int(now() - ts))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def safe_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))
