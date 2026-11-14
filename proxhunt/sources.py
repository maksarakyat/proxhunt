"""Free proxy list sources and async scrapers.

Everything here is public, unauthenticated data. Sources are sampled per run
(see `cap`) so that a handful of enormous dumps cannot crowd out the rest.
"""
from __future__ import annotations

import asyncio
import json
import random
import re
from dataclasses import dataclass

import aiohttp

from .config import DEFAULT_PER_SOURCE_CAP, USER_AGENT
from .util import parse_proxy_line, public_ipv4, safe_int

# name, url, protocol hint, parser kind, per-run sample cap
SOURCES: list["Source"] = []


@dataclass
class Source:
    name: str
    url: str
    proto: str = "http"          # http | socks5 | socks4 | mixed
    kind: str = "text"           # text | psjson | pxjson
    cap: int = DEFAULT_PER_SOURCE_CAP
    enabled: bool = True


def _add(name, url, proto="http", kind="text", cap=DEFAULT_PER_SOURCE_CAP):
    SOURCES.append(Source(name, url, proto, kind, cap))


# --- HTTP proxies -----------------------------------------------------------
_add("proxyscrape-http", "https://api.proxyscrape.com/v4/free-proxy-list/get"
     "?request=display_proxies&protocol=http&proxy_format=ipport&format=json",
     "http", "psjson", 2000)
_add("thespeedx-http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt")
_add("monosans-http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt")
_add("proxifly-all", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json",
     "mixed", "pxjson", 3000)
_add("proxyspace-http", "https://proxyspace.pro/http.txt", cap=1500)
_add("openproxylist-http", "https://api.openproxylist.xyz/http.txt", cap=1500)
_add("jetkai-http", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt")
_add("mmpx12-http", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt")
_add("vakhov-http", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt")
_add("clarketm-http", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt")
_add("shiftytr-http", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt")
_add("hideip-http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt")
_add("prxchk-http", "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt")
_add("roosterkid-https", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt")
_add("ercin-http", "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt", cap=1200)
_add("madeval-http", "https://raw.githubusercontent.com/MADEVAL/free-proxy-list/main/http.txt", cap=800)

# --- SOCKS5 proxies ---------------------------------------------------------
_add("proxyscrape-socks5", "https://api.proxyscrape.com/v4/free-proxy-list/get"
     "?request=display_proxies&protocol=socks5&proxy_format=ipport&format=json",
     "socks5", "psjson", 2000)
_add("thespeedx-socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
     "socks5")
_add("monosans-socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
     "socks5")
_add("hookzof-socks5", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
     "socks5", cap=1500)
_add("proxyspace-socks5", "https://proxyspace.pro/socks5.txt", "socks5", cap=1500)
_add("openproxylist-socks5", "https://api.openproxylist.xyz/socks5.txt", "socks5", cap=1500)
_add("ercin-socks5", "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
     "socks5", cap=1200)
_add("madeval-socks5", "https://raw.githubusercontent.com/MADEVAL/free-proxy-list/main/socks5.txt",
     "socks5", cap=800)
_add("vakhov-socks5", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
     "socks5", cap=500)
_add("sunny9577-mixed", "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
     "mixed", "text", 1200)

# --- SOCKS4 proxies (low priority, supported but rarely useful) -------------
_add("proxyscrape-socks4", "https://api.proxyscrape.com/v4/free-proxy-list/get"
     "?request=display_proxies&protocol=socks4&proxy_format=ipport&format=json",
     "socks4", "psjson", 1000)
_add("thespeedx-socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
     "socks4", cap=1000)


# --- scraping ---------------------------------------------------------------

JSDELIVR_RE = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")
HTML_RE = re.compile(r"^\s*(?:<!doctype|<html|<\?xml)", re.IGNORECASE)


def _mirror(url: str) -> str | None:
    m = JSDELIVR_RE.match(url)
    if not m:
        return None
    owner, repo, branch, path = m.groups()
    return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"


def _parse_json(source: Source, text: str) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    items = []
    if isinstance(data, dict):
        items = data.get("proxies") or data.get("data") or []
    elif isinstance(data, list):
        items = data
    for item in items:
        if not isinstance(item, dict):
            continue
        proto = (item.get("protocol") or item.get("type") or source.proto or "http").lower()
        if proto.startswith("https"):
            proto = "http"
        if proto not in ("http", "socks5", "socks4"):
            continue
        ip = public_ipv4(str(item.get("ip") or ""))
        port = safe_int(item.get("port"))
        if not ip or not (0 < port < 65536):
            continue
        country = ""
        geo = item.get("geolocation") or item.get("ip_data") or {}
        if isinstance(geo, dict):
            country = (geo.get("countryCode") or geo.get("country_code")
                       or geo.get("country") or "")
        out[(proto, f"{ip}:{port}")] = {
            "source": source.name,
            "country": str(country or "")[:32],
            "src_anon": str(item.get("anonymity") or "").lower()[:16],
            "src_https": bool(item.get("https") or item.get("ssl")),
        }
    return out


def _parse_text(source: Source, text: str) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for line in text.splitlines():
        parsed = parse_proxy_line(line, source.proto if source.proto != "mixed" else "http")
        if not parsed:
            continue
        proto, ip, port = parsed
        out.setdefault((proto, f"{ip}:{port}"), {"source": source.name})
    return out


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[int, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    async with session.get(url, headers=headers, allow_redirects=True) as resp:
        body = await resp.read()
        return resp.status, body.decode("utf-8", errors="replace")


async def scrape_source(session: aiohttp.ClientSession, source: Source
                        ) -> tuple[dict[tuple[str, str], dict], int, str | None]:
    """Return (entries, raw_count, error). Entries are capped by source.cap."""
    urls = [source.url]
    mirror = _mirror(source.url)
    if mirror:
        urls.append(mirror)
    last_err = None
    for url in urls:
        try:
            status, text = await _fetch(session, url)
        except Exception as exc:  # noqa: BLE001
            last_err = f"{type(exc).__name__}: {exc}"
            continue
        if status != 200 or not text.strip():
            last_err = f"HTTP {status} / empty"
            continue
        if HTML_RE.match(text[:200]) and source.kind == "text":
            last_err = "HTML instead of a proxy list"
            continue
        try:
            if source.kind in ("psjson", "pxjson"):
                entries = _parse_json(source, text)
            else:
                entries = _parse_text(source, text)
        except Exception as exc:  # noqa: BLE001
            last_err = f"parse {type(exc).__name__}: {exc}"
            continue
        raw_count = len(entries)
        if raw_count > source.cap:
            # deterministic-ish sample: same seed per source+day keeps runs stable
            rng = random.Random(f"{source.name}:{int(__import__('time').time() // 86400)}")
            keys = list(entries.keys())
            keys = rng.sample(keys, source.cap)
            entries = {k: entries[k] for k in keys}
            # Only report capped count for transparency
        return entries, raw_count, None
    return {}, 0, last_err


async def scrape_all(protocols: set[str], only: set[str] | None = None,
                     verbose: bool = False) -> tuple[dict[tuple[str, str], dict], list[dict]]:
    """Scrape every enabled source in parallel.

    Returns (merged candidates, per-source report). merged values contain
    source/country/src_anon/src_https hints.
    """
    selected = [s for s in SOURCES if s.enabled and s.proto != "mixed" and s.proto in protocols
                or s.enabled and s.proto == "mixed" and protocols & {"http", "socks5", "socks4"}]
    if only:
        selected = [s for s in SOURCES if s.name in only]
    if not selected:
        return {}, []

    timeout = aiohttp.ClientTimeout(total=45, connect=20, sock_read=35)
    connector = aiohttp.TCPConnector(limit=40, ttl_dns_cache=300)
    merged: dict[tuple[str, str], dict] = {}
    report: list[dict] = []
    async with aiohttp.ClientSession(timeout=timeout, connector=connector,
                                     trust_env=False) as session:
        results = await asyncio.gather(
            *(scrape_source(session, s) for s in selected))
    for src, (entries, raw, err) in zip(selected, results):
        report.append({"source": src.name, "proto": src.proto, "raw": raw,
                       "kept": len(entries), "error": err})
        if verbose:
            status = f"kept={len(entries)}/{raw}" if not err else f"ERROR {err}"
            print(f"  [source] {src.name:24s} {status}")
        for key, meta in entries.items():
            if key not in merged:
                merged[key] = dict(meta)
            else:
                # keep first source, fill missing hints
                for hint in ("country", "src_anon", "src_https"):
                    if not merged[key].get(hint) and meta.get(hint):
                        merged[key][hint] = meta[hint]
    return merged, report


def list_sources() -> list[Source]:
    return SOURCES
