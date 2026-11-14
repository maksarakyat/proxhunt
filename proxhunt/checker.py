"""Async proxy validator.

Pipeline per candidate:
  1. cheap TCP connect probe (no judge traffic for closed ports)
  2. HTTP and HTTPS judge probes in parallel -> exit IP, latency
  3. anonymity classification through a header-echo judge
  4. sequential "stream" test: N hits, interval, stable exit IP
  5. optional bandwidth test (Cloudflare 128 KiB)
"""
from __future__ import annotations

import asyncio
import json
import random
import re
import statistics
import time
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

import aiohttp
from aiohttp_socks import ProxyConnector

from .config import (ANON_JUDGES, DEFAULT_CONCURRENCY, DEFAULT_STREAM_CHECKS,
                     DEFAULT_STREAM_INTERVAL, DEFAULT_TIMEOUT, DEFAULT_TCP_TIMEOUT,
                     IP_JUDGES_HTTP, IP_JUDGES_HTTPS, SPEED_BYTES, SPEED_JUDGE,
                     USER_AGENT)
from .util import extract_public_ip, ms, public_ipv4

TAG_RE = re.compile(r"<[^>]+>")
HDR_LINE_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,48})\s*=\s*(.*)$")

JUDGE_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Cache-Control": "no-cache, no-store",
    "Pragma": "no-cache",
}

FORWARD_LEAK_KEYS = {
    "x_forwarded_for", "x_real_ip", "forwarded", "forwarded_for",
    "client_ip", "x_client_ip", "true_client_ip", "cf_connecting_ip",
    "x_originating_ip", "x_remote_ip",
}
PROXY_HEADER_KEYS = FORWARD_LEAK_KEYS | {
    "via", "proxy_connection", "proxy_agent", "x_proxy_id", "x_bluecoat_via",
    "x_cache", "x_forwarded_host", "x_forwarded_proto", "x_forwarded_port",
    "x_forwarded_server", "x_via", "x_proxy", "proxy_client_ip",
}


@dataclass
class CheckResult:
    proto: str
    addr: str
    ip: str
    port: int
    http_ok: bool = False
    https_ok: bool = False
    tls_ok: bool = False
    stream_ok: bool = False
    mode: str = ""
    anon: str = "unknown"
    exit_ip_http: str | None = None
    exit_ip_https: str | None = None
    latency_ms: int | None = None
    speed_kbps: float | None = None
    successes: int = 0
    fails: int = 0
    error: str | None = None
    elapsed_ms: int = 0

    def as_row(self) -> dict:
        return asdict(self)


class JudgePool:
    """Round-robin judge selection with a per-host concurrency cap."""

    def __init__(self, http_urls: list[str], https_urls: list[str], per_host: int = 120):
        self.urls = {"http": list(http_urls), "https": list(https_urls)}
        self.per_host = per_host
        self.sems: dict[str, asyncio.Semaphore] = {}
        self.idx = {"http": 0, "https": 0}

    def _sem(self, url: str) -> asyncio.Semaphore:
        host = urlsplit(url).netloc
        if host not in self.sems:
            self.sems[host] = asyncio.Semaphore(self.per_host)
        return self.sems[host]

    def pick(self, scheme: str, exclude: set[str] | None = None) -> str:
        urls = self.urls[scheme]
        for _ in range(len(urls)):
            i = self.idx[scheme] % len(urls)
            self.idx[scheme] += 1
            url = urls[i]
            if not exclude or url not in exclude:
                return url
        return random.choice(urls)

    async def fetch(self, session: aiohttp.ClientSession, scheme: str, proxy: str | None,
                    max_bytes: int = 8192, attempts: int = 2,
                    timeout: aiohttp.ClientTimeout | None = None,
                    verify: bool = False) -> tuple[str | None, int | None]:
        seen: set[str] = set()
        for _ in range(attempts):
            url = self.pick(scheme, seen)
            seen.add(url)
            sem = self._sem(url)
            t0 = time.monotonic()
            try:
                async with sem:
                    status, body = await self._get(session, url, proxy, max_bytes,
                                                   timeout, verify)
            except Exception:  # noqa: BLE001 - proxy/judge failures are expected
                continue
            ip = extract_public_ip(body)
            if status == 200 and ip:
                return ip, ms(time.monotonic() - t0)
        return None, None

    @staticmethod
    async def _get(session: aiohttp.ClientSession, url: str, proxy: str | None,
                   max_bytes: int, timeout: aiohttp.ClientTimeout | None,
                   verify: bool = False) -> tuple[int, str]:
        kwargs = {"proxy": proxy, "ssl": None if verify else False,
                  "allow_redirects": False, "headers": JUDGE_HEADERS}
        if timeout is not None:
            kwargs["timeout"] = timeout
        async with session.get(url, **kwargs) as resp:
            status = resp.status
            buf = bytearray()
            async for chunk in resp.content.iter_chunked(8192):
                buf.extend(chunk)
                if len(buf) >= max_bytes:
                    break
            return status, buf.decode("utf-8", errors="replace")


class Checker:
    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY,
                 tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
                 timeout: float = DEFAULT_TIMEOUT,
                 stream_checks: int = DEFAULT_STREAM_CHECKS,
                 stream_interval: float = DEFAULT_STREAM_INTERVAL,
                 do_anon: bool = True, speed_budget: int = 0,
                 anon_concurrency: int = 40, speed_concurrency: int = 16,
                 verbose: bool = False, check_tls: bool = True):
        self.concurrency = max(1, int(concurrency))
        self.tcp_timeout = tcp_timeout
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=min(6.0, timeout),
                                             sock_read=min(8.0, timeout))
        self.speed_timeout = aiohttp.ClientTimeout(total=25, connect=8, sock_read=20)
        self.stream_checks = max(0, int(stream_checks))
        self.stream_interval = max(0.0, float(stream_interval))
        self.do_anon = do_anon
        self.speed_budget = max(0, int(speed_budget))
        self.verbose = verbose
        self.check_tls = check_tls
        self.judges = JudgePool(IP_JUDGES_HTTP, IP_JUDGES_HTTPS, per_host=120)
        self.anon_sem = asyncio.Semaphore(max(1, anon_concurrency))
        self.speed_sem = asyncio.Semaphore(max(1, speed_concurrency))
        self.http_session: aiohttp.ClientSession | None = None
        self.real_ip: str | None = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=0, ttl_dns_cache=300, enable_cleanup_closed=True)
        self.http_session = aiohttp.ClientSession(
            connector=connector, timeout=self.timeout, trust_env=False,
            headers={"User-Agent": USER_AGENT}, cookie_jar=aiohttp.DummyCookieJar())
        self.real_ip = await self._discover_real_ip()
        if self.verbose:
            print(f"[checker] real egress IP: {self.real_ip or 'UNKNOWN'}")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.http_session:
            await self.http_session.close()

    async def _discover_real_ip(self) -> str | None:
        for url in ["https://checkip.amazonaws.com", "https://api.ipify.org?format=json"]:
            try:
                async with self.http_session.get(
                        url, ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                        headers=JUDGE_HEADERS) as resp:
                    body = (await resp.text(errors="replace"))[:4096]
                ip = extract_public_ip(body)
                if ip:
                    return ip
            except Exception:  # noqa: BLE001
                continue
        return None

    # -- individual stages --------------------------------------------------
    async def _tcp_alive(self, ip: str, port: int) -> bool:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.tcp_timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:  # noqa: BLE001
                pass
            return True
        except Exception:  # noqa: BLE001
            if writer is not None:
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass
            return False

    async def _anon_level(self, session: aiohttp.ClientSession, proxy: str | None,
                          exit_ip: str | None) -> str:
        if exit_ip and self.real_ip and exit_ip == self.real_ip:
            return "transparent"
        for url in ANON_JUDGES:
            try:
                async with self.anon_sem:
                    status, body = await JudgePool._get(
                        session, url, proxy, 65536, self.timeout)
                if status != 200 or not body:
                    continue
                headers = self._parse_header_echo(body)
                if headers is None:
                    continue
                if self.real_ip:
                    for key, value in headers.items():
                        if key in FORWARD_LEAK_KEYS and self.real_ip in value:
                            return "transparent"
                if any(k in PROXY_HEADER_KEYS for k in headers):
                    return "anonymous"
                return "elite"
            except Exception:  # noqa: BLE001
                continue
        return "unknown"

    @staticmethod
    def _parse_header_echo(body: str) -> dict[str, str] | None:
        text = body.strip()
        if text.startswith("{"):
            try:
                data = json.loads(text)
                hdrs = data.get("headers")
                if isinstance(hdrs, dict):
                    return {str(k).lower().replace("http_", "").replace("-", "_"): str(v)
                            for k, v in hdrs.items()}
            except json.JSONDecodeError:
                return None
        plain = TAG_RE.sub("\n", body)
        out: dict[str, str] = {}
        for line in plain.splitlines():
            m = HDR_LINE_RE.match(line.strip())
            if not m:
                continue
            key = m.group(1).lower()
            if key.startswith("http_"):
                key = key[5:]
            out[key.replace("-", "_")] = m.group(2).strip()
        if not out:
            return None
        # azenv leaks the seen remote address as REMOTE_ADDR
        if "remote_addr" in out:
            out["remote_addr"] = out["remote_addr"]
        return out

    async def _stream_test(self, session: aiohttp.ClientSession, res: CheckResult,
                           proxy: str | None) -> None:
        n = self.stream_checks
        if n <= 0:
            return
        scheme = "https" if res.https_ok else "http"
        ips: list[str] = []
        lats: list[int] = []
        ok = 0
        for i in range(n):
            if i:
                await asyncio.sleep(self.stream_interval)
            ip, lat = await self.judges.fetch(
                session, scheme, proxy, max_bytes=4096, attempts=3)
            if ip:
                ok += 1
                ips.append(ip)
                if lat:
                    lats.append(lat)
            elif (n - i - 1) + ok < n:
                break
        res.successes += ok
        res.fails += max(0, n - ok)
        if ok == n and ips and len(set(ips)) == 1:
            res.stream_ok = True
            res.mode = "stream"
        else:
            res.mode = "once"
        if lats:
            existing = [res.latency_ms] if res.latency_ms else []
            res.latency_ms = int(statistics.median(existing + lats))

    async def _speed_test(self, session: aiohttp.ClientSession, res: CheckResult,
                          proxy: str | None) -> None:
        if self.speed_budget <= 0 or not res.https_ok:
            return
        # single event-loop thread: decrement is safe without a lock
        self.speed_budget -= 1
        t0 = time.monotonic()
        try:
            async with self.speed_sem:
                status, _ = await JudgePool._get(
                    session, SPEED_JUDGE, proxy, SPEED_BYTES + 1024, self.speed_timeout)
                # _get returns text, which mangles binary. Re-fetch is wasteful;
                # instead we only need completion time and success. Use byte count
                # of the decoded body as an approximation of transferred volume.
            elapsed = max(0.001, time.monotonic() - t0)
            # The body of the speed endpoint is a run of ASCII zeroes, so len(text)
            # equals the byte count here.
            size = len(_) if isinstance(_, str) else 0
            if status == 200 and size >= SPEED_BYTES * 0.98 and elapsed > 0:
                res.speed_kbps = round(size / 1024.0 / elapsed, 1)
        except Exception:  # noqa: BLE001
            return

    # -- main per-candidate check -------------------------------------------
    async def check(self, proto: str, addr: str) -> CheckResult:
        ip, _, port_s = addr.partition(":")
        res = CheckResult(proto=proto, addr=addr, ip=ip, port=int(port_s))
        t_start = time.monotonic()
        if not await self._tcp_alive(ip, int(port_s)):
            res.error = "tcp"
            res.fails = 1
            res.elapsed_ms = ms(time.monotonic() - t_start)
            return res

        session = self.http_session
        own_session = False
        proxy = None
        try:
            if proto in ("socks5", "socks4"):
                try:
                    connector = ProxyConnector.from_url(f"{proto}://{addr}", rdns=True)
                    session = aiohttp.ClientSession(
                        connector=connector, timeout=self.timeout,
                        trust_env=False, headers={"User-Agent": USER_AGENT},
                        cookie_jar=aiohttp.DummyCookieJar())
                    own_session = True
                except Exception as exc:  # noqa: BLE001
                    res.error = f"connector:{type(exc).__name__}"
                    res.fails = 1
                    res.elapsed_ms = ms(time.monotonic() - t_start)
                    return res
            else:
                proxy = f"http://{addr}"

            if proto == "http":
                (ip_h, lat_h), (ip_s, lat_s) = await asyncio.gather(
                    self.judges.fetch(session, "http", proxy, max_bytes=4096, attempts=2),
                    self.judges.fetch(session, "https", proxy, max_bytes=4096, attempts=2))
            else:
                ip_s, lat_s = await self.judges.fetch(
                    session, "https", None, max_bytes=4096, attempts=2)
                ip_h, lat_h = None, None
                if not ip_s:
                    ip_h, lat_h = await self.judges.fetch(
                        session, "http", None, max_bytes=4096, attempts=2)

            res.exit_ip_http = ip_h
            res.exit_ip_https = ip_s
            res.http_ok = bool(ip_h)
            res.https_ok = bool(ip_s)
            lats = [x for x in (lat_h, lat_s) if x]
            if lats:
                res.latency_ms = int(statistics.median(lats))
            res.successes = int(bool(ip_h)) + int(bool(ip_s))

            if not (res.http_ok or res.https_ok):
                res.error = "no-exit-ip"
                res.fails = 1
                res.elapsed_ms = ms(time.monotonic() - t_start)
                return res

            # A CONNECT tunnel can still be a TLS MITM. Verify the certificate
            # chain end-to-end with the system CA store; tls_ok is the safe flag.
            if self.check_tls and res.https_ok:
                ip_v, _lat_v = await self.judges.fetch(
                    session, "https", proxy, max_bytes=4096, attempts=2, verify=True)
                if ip_v:
                    res.tls_ok = True
                    res.successes += 1

            if ((ip_h and self.real_ip and ip_h == self.real_ip) or
                    (ip_s and self.real_ip and ip_s == self.real_ip)):
                res.anon = "transparent"

            if self.do_anon and res.http_ok and res.anon != "transparent":
                res.anon = await self._anon_level(session, proxy, ip_h)

            if res.anon != "transparent" and self.stream_checks > 0:
                await self._stream_test(session, res, proxy)

            if res.stream_ok and self.speed_budget > 0:
                await self._speed_test(session, res, proxy)

        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}:{exc}"[:120]
            res.fails += 1
        finally:
            if own_session and session is not None:
                try:
                    await session.close()
                except Exception:  # noqa: BLE001
                    pass

        res.elapsed_ms = ms(time.monotonic() - t_start)
        return res

    # -- batch runner -------------------------------------------------------
    async def run(self, items: list[tuple[str, str]], store=None,
                  on_progress=None) -> list[dict]:
        total = len(items)
        queue: asyncio.Queue = asyncio.Queue()
        for item in items:
            queue.put_nowait(item)
        done = 0
        alive = 0
        streams = 0
        errors = 0
        buffer: list[dict] = []
        flush_lock = asyncio.Lock()
        started = time.monotonic()
        last_report = 0.0

        async def flush(force: bool = False):
            nonlocal buffer
            if not buffer or (len(buffer) < 200 and not force):
                return
            async with flush_lock:
                if not buffer:
                    return
                batch, buffer = buffer, []
                if store is not None:
                    store.apply_results(batch)

        async def worker():
            nonlocal done, alive, streams, errors, last_report
            while True:
                try:
                    proto, addr = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    res = await self.check(proto, addr)
                except Exception as exc:  # noqa: BLE001
                    ip, _, port_s = addr.partition(":")
                    res = CheckResult(proto=proto, addr=addr,
                                      ip=public_ipv4(ip) or ip,
                                      port=int(port_s) if port_s.isdigit() else 0,
                                      error=f"{type(exc).__name__}:{exc}"[:120],
                                      fails=1)
                row = res.as_row()
                buffer.append(row)
                done += 1
                if res.http_ok or res.https_ok:
                    alive += 1
                if res.stream_ok:
                    streams += 1
                if res.error:
                    errors += 1
                if done % 200 == 0:
                    await flush()
                now_t = time.monotonic()
                if on_progress and now_t - last_report >= 1.0:
                    last_report = now_t
                    on_progress(done, total, alive, streams, errors,
                                now_t - started)

        workers = min(self.concurrency, max(1, total))
        tasks = [asyncio.create_task(worker()) for _ in range(workers)]
        try:
            await asyncio.gather(*tasks)
        finally:
            await flush(force=True)
        if on_progress:
            on_progress(done, total, alive, streams, errors, time.monotonic() - started)
        return []
