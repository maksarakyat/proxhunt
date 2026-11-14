"""Local rotating proxy: HTTP forward proxy + SOCKS5 listener.

Upstreams are free proxies from the SQLite pool. Policies:
  rotate  - a different upstream for every new request / tunnel (default)
  sticky  - keyed by proxy auth username, X-Proxhunt-Session header, or client IP
            for --sticky-ttl seconds (good for streaming / multi-hit sessions)
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import random
import time
from collections import Counter, deque
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import (COOLDOWN_SECONDS, DEFAULT_RETRIES, DEFAULT_STICKY_TTL,
                     POOL_REFRESH_SECONDS)
from .store import Store
from .util import human_ts

log = logging.getLogger("proxhunt.rotator")

MAX_HEAD = 64 * 1024
MAX_BUFFERED_BODY = 2 * 1024 * 1024
MAX_REPLAY = 64 * 1024


@dataclass
class Upstream:
    proto: str
    addr: str
    score: float
    latency_ms: int
    mode: str
    https_ok: bool
    anon: str
    last_ok: float = 0.0
    tls_ok: bool = False

    @property
    def url(self) -> str:
        return f"{self.proto}://{self.addr}"


class PoolManager:
    def __init__(self, store: Store, protos: str = "http,socks5",
                 require_https: bool = False, require_stream: bool = False,
                 min_score: float = 0.0, alive_minutes: int = 180,
                 limit: int = 500, require_tls: bool = False):
        self.store = store
        self.protos = protos
        self.require_https = require_https
        self.require_stream = require_stream
        self.require_tls = require_tls
        self.min_score = min_score
        self.alive_minutes = alive_minutes
        self.limit = limit
        self.items: list[Upstream] = []
        self.by_addr: dict[str, Upstream] = {}
        self.cooldown: dict[str, float] = {}
        self.usage: Counter[str] = Counter()
        self.recent: deque[str] = deque(maxlen=30)
        self.last_refresh = 0.0
        self.last_count = -1

    def refresh(self) -> int:
        rows = self.store.pool(limit=self.limit, proto=self.protos,
                               require_https=self.require_https,
                               require_stream=self.require_stream,
                               min_score=self.min_score,
                               alive_minutes=self.alive_minutes,
                               tls_only=self.require_tls)
        items = []
        for r in rows:
            items.append(Upstream(
                proto=r["proto"], addr=r["addr"], score=float(r["score"] or 0),
                latency_ms=int(r["latency_ms"] or 9999), mode=r["mode"] or "",
                https_ok=bool(r["https_ok"]), anon=r["anon"] or "unknown",
                last_ok=float(r["last_ok"] or 0), tls_ok=bool(r.get("tls_ok"))))
        self.items = items
        self.by_addr = {u.addr: u for u in items}
        self.last_refresh = time.time()
        if len(items) != self.last_count:
            log.info("pool refreshed: %d live upstreams (https=%d stream=%d)",
                     len(items), sum(1 for u in items if u.https_ok),
                     sum(1 for u in items if u.mode == "stream"))
            self.last_count = len(items)
        return len(items)

    def _usable(self, up: Upstream, need_https: bool) -> bool:
        if need_https and not up.https_ok:
            return False
        until = self.cooldown.get(up.addr, 0)
        return until <= time.time()

    def pick(self, need_https: bool = False, tried: set[str] | None = None) -> Upstream | None:
        tried = tried or set()
        cands = [u for u in self.items
                 if u.addr not in tried and self._usable(u, need_https)]
        if not cands:
            return None
        # spread load: prefer proxies not used in the last few requests
        recent = set(self.recent)
        fresh = [u for u in cands if u.addr not in recent]
        pool = fresh if fresh else cands
        pool.sort(key=lambda u: u.score, reverse=True)
        top = pool[:200]
        t = time.time()
        weights = []
        for u in top:
            age = max(0.0, t - (u.last_ok or t))
            # half-life ~30 min: freshly validated proxies are strongly preferred
            freshness = max(0.15, 2.0 ** (-age / 1800.0))
            weights.append(max(1.0, u.score) * freshness)
        up = random.choices(top, weights=weights, k=1)[0]
        self.usage[up.addr] += 1
        self.recent.append(up.addr)
        return up

    def fail(self, up: Upstream, seconds: float = COOLDOWN_SECONDS):
        self.cooldown[up.addr] = time.time() + seconds
        try:
            self.store.mark_runtime_fail(up.proto, up.addr)
        except Exception:  # noqa: BLE001
            log.exception("failed to persist upstream failure")

    def ok(self, up: Upstream):
        self.cooldown.pop(up.addr, None)

    def snapshot(self) -> dict:
        return {
            "size": len(self.items),
            "https": sum(1 for u in self.items if u.https_ok),
            "stream": sum(1 for u in self.items if u.mode == "stream"),
            "cooling": sum(1 for t in self.cooldown.values() if t > time.time()),
            "last_refresh": human_ts(self.last_refresh),
            "top_used": self.usage.most_common(5),
        }


class RotatorServer:
    def __init__(self, pool: PoolManager, bind: str = "127.0.0.1",
                 port: int = 8899, socks_port: int | None = 8900,
                 policy: str = "rotate", sticky_ttl: int = DEFAULT_STICKY_TTL,
                 retries: int = DEFAULT_RETRIES, hedge: int = 3,
                 upstream_timeout: float = 6.0):
        self.pool = pool
        self.bind = bind
        self.port = port
        self.socks_port = socks_port
        self.policy = policy
        self.sticky_ttl = sticky_ttl
        self.retries = retries
        self.hedge = max(1, int(hedge))
        self.upstream_timeout = max(2.0, float(upstream_timeout))
        self.stats = {"requests": 0, "ok": 0, "fail": 0, "tunnels": 0,
                      "http": 0, "socks": 0, "started": time.time()}
        self.active = 0
        self.sticky: dict[str, tuple[Upstream, float]] = {}
        self.servers: list[asyncio.AbstractServer] = []
        self._refresh_task: asyncio.Task | None = None
        self._sticky_task: asyncio.Task | None = None

    # -- lifecycle ----------------------------------------------------------
    async def start(self):
        self.pool.refresh()
        self.servers.append(await asyncio.start_server(
            self.handle_http, self.bind, self.port, limit=MAX_HEAD))
        log.info("HTTP proxy listening on http://%s:%d", self.bind, self.port)
        if self.socks_port:
            self.servers.append(await asyncio.start_server(
                self.handle_socks, self.bind, self.socks_port, limit=65536))
            log.info("SOCKS5 proxy listening on socks5://%s:%d", self.bind, self.socks_port)
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        self._sticky_task = asyncio.create_task(self._sticky_cleanup())

    async def stop(self):
        for task in (self._refresh_task, self._sticky_task):
            if task:
                task.cancel()
        for srv in self.servers:
            srv.close()
        for srv in self.servers:
            await srv.wait_closed()
        log.info("stopped: %s", self.stats)

    async def _refresh_loop(self):
        while True:
            await asyncio.sleep(POOL_REFRESH_SECONDS)
            try:
                self.pool.refresh()
            except Exception:  # noqa: BLE001
                log.exception("pool refresh failed")

    async def _sticky_cleanup(self):
        while True:
            await asyncio.sleep(30)
            t = time.time()
            for key, (_, exp) in list(self.sticky.items()):
                if exp <= t:
                    self.sticky.pop(key, None)

    def snapshot(self) -> dict:
        return {
            "status": "ok",
            "policy": self.policy,
            "sticky_ttl": self.sticky_ttl,
            "uptime_s": int(time.time() - self.stats["started"]),
            "requests": self.stats["requests"],
            "ok": self.stats["ok"],
            "fail": self.stats["fail"],
            "active": self.active,
            "pool": self.pool.snapshot(),
        }

    # -- HTTP proxy ---------------------------------------------------------
    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.stats["requests"] += 1
        self.stats["http"] += 1
        self.active += 1
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "?"
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=20)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                    asyncio.LimitOverrunError, ConnectionError):
                return
            parsed = self._parse_http_head(head)
            if not parsed:
                await self._simple_response(writer, 400, "bad request")
                return

            method, target, version, headers = parsed
            host, port, path, absolute_uri, is_connect = self._target_info(
                method, target, headers)
            if not host:
                await self._simple_response(writer, 400, "missing host")
                return

            if host.lower() in ("proxhunt.local", "proxhunt"):
                await self._admin_response(writer, path or "/")
                return

            need_https = (is_connect and port == 443) or False
            session_key = self._session_key(headers, client_ip)
            sticky_key = None
            if session_key:
                sticky_key = f"{session_key}|{'https' if need_https else 'http'}"

            # Read a small body up-front so we can retry a failed upstream.
            body = b""
            can_retry = True
            if not is_connect:
                te = headers.get("transfer-encoding", "").lower()
                cl = headers.get("content-length")
                if cl and cl.isdigit():
                    length = int(cl)
                    if length <= MAX_BUFFERED_BODY:
                        try:
                            body = await asyncio.wait_for(
                                reader.readexactly(length), timeout=20)
                        except Exception:  # noqa: BLE001
                            return
                    else:
                        can_retry = False
                elif te == "chunked":
                    can_retry = False

            tried: set[str] = set()
            last_error = "no upstream"

            if is_connect:
                await self._connect_relay(reader, writer, host, port, need_https,
                                          sticky_key, tried)
                return

            for _attempt in range(max(1, self.retries)):
                up = self._choose(sticky_key, need_https, tried)
                if not up:
                    break
                tried.add(up.addr)
                try:
                    up_reader, up_writer, resp_head = await self._http_forward(
                        up, host, port, path, absolute_uri, method, version,
                        headers, body, can_retry)
                    if resp_head:
                        writer.write(resp_head)
                        await writer.drain()
                    self.pool.ok(up)
                    self.stats["ok"] += 1
                    self.stats["tunnels"] += 1
                    if sticky_key:
                        self.sticky[sticky_key] = (up, time.time() + self.sticky_ttl)
                    log.debug("%s %s:%s via %s %s", method, host, port,
                              up.proto, up.addr)
                    await self._pipe(reader, writer, up_reader, up_writer,
                                     wait_downstream=True)
                    return
                except Exception as exc:  # noqa: BLE001
                    last_error = f"{type(exc).__name__}: {exc}"[:100]
                    self.pool.fail(up)
                    if sticky_key:
                        self.sticky.pop(sticky_key, None)
                    log.debug("upstream %s failed: %s", up.addr, last_error)
                    if not can_retry:
                        break

            self.stats["fail"] += 1
            await self._simple_response(writer, 502,
                                        f"proxhunt: no usable upstream ({last_error})")
        finally:
            self.active -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    def _choose(self, sticky_key: str | None, need_https: bool,
                tried: set[str]) -> Upstream | None:
        if sticky_key:
            entry = self.sticky.get(sticky_key)
            if entry and entry[1] > time.time():
                up = entry[0]
                if up.addr not in tried and self.pool._usable(up, need_https):
                    # sliding expiry: a session that keeps working stays sticky
                    self.sticky[sticky_key] = (up, time.time() + self.sticky_ttl)
                    return up
            self.sticky.pop(sticky_key, None)
        return self.pool.pick(need_https, tried)

    async def _connect_relay(self, reader, writer, host: str, port: int,
                             need_https: bool, sticky_key: str | None,
                             tried: set[str]):
        """CONNECT with hedged dialing and client-byte replay across dead upstreams.

        The client's first bytes (normally a TLS ClientHello) are buffered until
        the upstream sends its first byte. If an upstream accepts CONNECT and
        then dies silently, the same bytes are replayed through the next upstream.
        This turns many 000/connection-reset failures into slow successes.
        """
        replay = bytearray()
        established = False
        allow_replay = port in (443, 8443, 9443, 10443)
        attempts = 0
        max_attempts = max(1, self.retries)
        last_error = "no upstream"
        while attempts < max_attempts:
            count = 1 if sticky_key else min(self.hedge, max_attempts - attempts)
            batch = self._pick_batch(need_https, sticky_key, tried, count)
            if not batch:
                break
            attempts += len(batch)
            up, up_reader, up_writer = await self._race_candidates(batch, host, port)
            if not up:
                last_error = "all upstream handshakes failed"
                continue
            if not established:
                try:
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n"
                                 b"Proxy-Agent: proxhunt\r\n\r\n")
                    await writer.drain()
                    established = True
                except Exception:  # noqa: BLE001
                    up_writer.close()
                    return
            try:
                if replay:
                    up_writer.write(bytes(replay))
                    await up_writer.drain()
            except Exception as exc:  # noqa: BLE001
                last_error = f"replay {type(exc).__name__}: {exc}"[:80]
                self.pool.fail(up, seconds=120)
                try:
                    up_writer.close()
                except Exception:  # noqa: BLE001
                    pass
                continue

            spoke, outcome, allow_replay = await self._relay_loop(
                reader, writer, up_reader, up_writer, replay, allow_replay,
                expect_tls=port in (443, 8443, 9443, 10443))
            if spoke:
                self.pool.ok(up)
                self.stats["ok"] += 1
                self.stats["tunnels"] += 1
                if sticky_key:
                    self.sticky[sticky_key] = (up, time.time() + self.sticky_ttl)
                log.debug("CONNECT %s:%s via %s %s%s", host, port, up.proto,
                          up.addr, " (after retry)" if attempts > len(batch) else "")
                return

            last_error = outcome
            self.pool.fail(up, seconds=120)
            if sticky_key:
                self.sticky.pop(sticky_key, None)
            log.debug("CONNECT %s:%s pre-data failure via %s: %s", host, port,
                      up.addr, outcome)
            if outcome == "client_eof" or not allow_replay:
                break

        self.stats["fail"] += 1
        if not established:
            await self._simple_response(
                writer, 502, f"proxhunt: no usable upstream ({last_error})")

    def _pick_batch(self, need_https: bool, sticky_key: str | None,
                    tried: set[str], count: int) -> list[Upstream]:
        batch: list[Upstream] = []
        if sticky_key:
            up = self._choose(sticky_key, need_https, tried)
            if up:
                tried.add(up.addr)
                batch.append(up)
            return batch
        for _ in range(max(1, count)):
            up = self.pool.pick(need_https, tried)
            if not up:
                break
            tried.add(up.addr)
            batch.append(up)
        return batch

    async def _race_candidates(self, batch: list[Upstream], host: str, port: int):
        async def attempt(up: Upstream, delay: float):
            if delay:
                await asyncio.sleep(delay)
            try:
                r, w = await self._tunnel_to(up, host, port)
                return up, r, w, None
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                return up, None, None, exc

        tasks = [asyncio.create_task(attempt(up, i * 0.25))
                 for i, up in enumerate(batch)]
        pending = set(tasks)
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                up, r, w, exc = task.result()
                if r is not None and w is not None:
                    losers = list(pending)
                    for p in losers:
                        p.cancel()
                    results = await asyncio.gather(*losers, return_exceptions=True)
                    for res in results:
                        if isinstance(res, tuple) and len(res) == 4 and res[2] is not None:
                            try:
                                res[2].close()
                            except Exception:  # noqa: BLE001
                                pass
                    return up, r, w
                self.pool.fail(up, seconds=60)
                log.debug("handshake via %s failed: %s", up.addr,
                          f"{type(exc).__name__}: {exc}"[:80])
        return None, None, None

    async def _relay_loop(self, reader, writer, up_reader, up_writer,
                          replay: bytearray, allow_replay: bool, expect_tls: bool):
        client_task = asyncio.create_task(reader.read(65536))
        up_task = asyncio.create_task(up_reader.read(65536))
        spoke = False
        client_seen = False
        outcome = "closed"
        try:
            if replay and replay[0] != 0x16:
                expect_tls = False
            while True:
                done, _pending = await asyncio.wait(
                    {client_task, up_task}, return_when=asyncio.FIRST_COMPLETED)
                if client_task in done:
                    data = client_task.result()
                    if not data:
                        outcome = "client_eof"
                        try:
                            if up_writer.can_write_eof():
                                up_writer.write_eof()
                        except Exception:  # noqa: BLE001
                            pass
                        break
                    if not client_seen:
                        client_seen = True
                        if data[0] != 0x16:
                            expect_tls = False
                    if not spoke and allow_replay:
                        if len(replay) + len(data) <= MAX_REPLAY:
                            replay.extend(data)
                        else:
                            allow_replay = False
                            replay.clear()
                    up_writer.write(data)
                    await up_writer.drain()
                    client_task = asyncio.create_task(reader.read(65536))
                if up_task in done:
                    data = up_task.result()
                    if not data:
                        outcome = "upstream_eof"
                        break
                    if not spoke and expect_tls and data[0] != 0x16:
                        # HTTP error page, MITM certificate, or garbage — this
                        # upstream is not giving us a real TLS session.
                        outcome = f"bad_upstream_data:{data[:8].hex()}"
                        log.debug("discarding upstream data %r", data[:16])
                        break
                    spoke = True
                    replay.clear()
                    writer.write(data)
                    await writer.drain()
                    up_task = asyncio.create_task(up_reader.read(65536))
        except Exception as exc:  # noqa: BLE001
            outcome = f"{type(exc).__name__}: {exc}"[:80]
        finally:
            for task in (client_task, up_task):
                task.cancel()
            await asyncio.gather(client_task, up_task, return_exceptions=True)
            try:
                up_writer.close()
            except Exception:  # noqa: BLE001
                pass
        return spoke, outcome, allow_replay

    async def _http_forward(self, up: Upstream, host: str, port: int, path: str,
                            absolute_uri: str, method: str, version: str,
                            headers: dict[str, str], body: bytes, can_retry: bool):
        if up.proto == "http":
            up_reader, up_writer = await self._open_tcp(up)
            request_target = absolute_uri
        else:
            up_reader, up_writer = await self._tunnel_to(up, host, port)
            request_target = path or "/"
        out_headers = {k: v for k, v in headers.items()
                       if k not in ("proxy-authorization", "proxy-connection")}
        out_headers["connection"] = "close"
        if "host" not in out_headers:
            host_hdr = f"[{host}]" if ":" in host else host
            out_headers["host"] = host_hdr if port in (80, 443) else f"{host_hdr}:{port}"
        lines = [f"{method} {request_target} {version}"]
        lines += [f"{k}: {v}" for k, v in out_headers.items()]
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", errors="replace")
        up_writer.write(raw)
        if body:
            up_writer.write(body)
        await up_writer.drain()

        if not can_retry:
            # Body is still streaming from the client; pipe everything raw.
            return up_reader, up_writer, b""

        try:
            resp_head = await asyncio.wait_for(up_reader.readuntil(b"\r\n\r\n"), timeout=25)
        except Exception:
            try:
                up_writer.close()
            except Exception:  # noqa: BLE001
                pass
            raise
        status = 0
        try:
            status = int(resp_head.split(b" ", 2)[1])
        except Exception:  # noqa: BLE001
            pass
        if status in (407, 429, 502, 503, 504):
            try:
                up_writer.close()
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(f"upstream HTTP {status}")
        return up_reader, up_writer, resp_head

    # -- SOCKS5 local listener ----------------------------------------------
    async def handle_socks(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.stats["requests"] += 1
        self.stats["socks"] += 1
        self.active += 1
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "?"
        up_writer = None
        try:
            ver_nmethods = await asyncio.wait_for(reader.readexactly(2), timeout=15)
            if ver_nmethods[0] != 5:
                return
            methods = await reader.readexactly(ver_nmethods[1])
            method = 0 if 0 in methods else (2 if 2 in methods else 0xFF)
            writer.write(bytes([5, method]))
            await writer.drain()
            if method == 0xFF:
                return
            username = None
            if method == 2:
                sub = await reader.readexactly(2)
                if sub[0] != 1:
                    return
                user = await reader.readexactly(sub[1])
                plen = await reader.readexactly(1)
                await reader.readexactly(plen[0])
                username = user.decode("utf-8", errors="replace")
                writer.write(b"\x01\x00")
                await writer.drain()

            req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
            ver, cmd, _rsv, atyp = req
            if ver != 5 or cmd != 1:
                await self._socks_reply(writer, 7)
                return
            if atyp == 1:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 3:
                n = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(n)).decode("utf-8", errors="replace")
            elif atyp == 4:
                raw = await reader.readexactly(16)
                host = str(ipaddress.IPv6Address(raw))
            else:
                await self._socks_reply(writer, 8)
                return
            port = int.from_bytes(await reader.readexactly(2), "big")

            session_key = username or (f"ip:{client_ip}" if self.policy == "sticky" else None)
            sticky_key = f"{session_key}|{'https' if port == 443 else 'http'}" if session_key else None
            need_https = port == 443

            tried: set[str] = set()
            last_error = "no upstream"
            for _attempt in range(max(1, self.retries)):
                up = self._choose(sticky_key, need_https, tried)
                if not up:
                    break
                tried.add(up.addr)
                try:
                    up_reader, up_writer = await self._tunnel_to(up, host, port)
                    await self._socks_reply(writer, 0)
                    self.pool.ok(up)
                    self.stats["ok"] += 1
                    self.stats["tunnels"] += 1
                    if sticky_key:
                        self.sticky[sticky_key] = (up, time.time() + self.sticky_ttl)
                    await self._pipe(reader, writer, up_reader, up_writer)
                    return
                except Exception as exc:  # noqa: BLE001
                    last_error = f"{type(exc).__name__}: {exc}"[:100]
                    self.pool.fail(up)
                    if sticky_key:
                        self.sticky.pop(sticky_key, None)
            self.stats["fail"] += 1
            log.debug("socks target %s:%s failed: %s", host, port, last_error)
            await self._socks_reply(writer, 1)
        except Exception:  # noqa: BLE001
            try:
                await self._socks_reply(writer, 1)
            except Exception:  # noqa: BLE001
                pass
        finally:
            self.active -= 1
            if up_writer is not None:
                try:
                    up_writer.close()
                except Exception:  # noqa: BLE001
                    pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # -- upstream dialers ----------------------------------------------------
    async def _open_tcp(self, up: Upstream) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        host, _, port_s = up.addr.partition(":")
        return await asyncio.wait_for(
            asyncio.open_connection(host, int(port_s)), timeout=self.upstream_timeout)

    async def _tunnel_to(self, up: Upstream, host: str, port: int):
        timeout = self.upstream_timeout * 2
        if up.proto == "http":
            return await asyncio.wait_for(self._http_connect(up, host, port), timeout=timeout)
        if up.proto == "socks5":
            return await asyncio.wait_for(self._socks5_connect(up, host, port), timeout=timeout)
        return await asyncio.wait_for(self._socks4_connect(up, host, port), timeout=timeout)

    async def _http_connect(self, up: Upstream, host: str, port: int):
        reader, writer = await self._open_tcp(up)
        try:
            authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            req = (f"CONNECT {authority} HTTP/1.1\r\n"
                   f"Host: {authority}\r\n"
                   f"Proxy-Connection: keep-alive\r\n\r\n").encode()
            writer.write(req)
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"),
                                          timeout=self.upstream_timeout)
            try:
                status = int(head.split(b" ", 2)[1])
            except Exception:  # noqa: BLE001
                status = 0
            if status != 200:
                raise RuntimeError(f"CONNECT rejected: {head[:40]!r}")
            return reader, writer
        except BaseException:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            raise

    async def _socks5_connect(self, up: Upstream, host: str, port: int):
        reader, writer = await self._open_tcp(up)
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(2),
                                          timeout=self.upstream_timeout)
            if resp != b"\x05\x00":
                raise RuntimeError("socks5 greeting rejected")
            try:
                ip = ipaddress.ip_address(host)
                if ip.version == 4:
                    atyp, addr = 1, ip.packed
                else:
                    atyp, addr = 4, ip.packed
            except ValueError:
                raw = host.encode("idna")[:255]
                atyp, addr = 3, bytes([len(raw)]) + raw
            writer.write(b"\x05\x01\x00" + bytes([atyp]) + addr + port.to_bytes(2, "big"))
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(4),
                                          timeout=self.upstream_timeout)
            if resp[0] != 5 or resp[1] != 0:
                raise RuntimeError(f"socks5 connect failed: {resp!r}")
            atyp = resp[3]
            if atyp == 1:
                await reader.readexactly(4)
            elif atyp == 3:
                n = (await reader.readexactly(1))[0]
                await reader.readexactly(n)
            elif atyp == 4:
                await reader.readexactly(16)
            await reader.readexactly(2)
            return reader, writer
        except BaseException:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            raise

    async def _socks4_connect(self, up: Upstream, host: str, port: int):
        reader, writer = await self._open_tcp(up)
        try:
            try:
                ip = ipaddress.ip_address(host)
                if ip.version != 4:
                    raise ValueError
                addr_bytes = ip.packed
                suffix = b""
            except ValueError:
                addr_bytes = b"\x00\x00\x00\x01"  # SOCKS4a
                suffix = host.encode("idna") + b"\x00"
            req = (b"\x04\x01" + port.to_bytes(2, "big") + addr_bytes +
                   b"\x00" + suffix)
            writer.write(req)
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(8),
                                          timeout=self.upstream_timeout)
            if resp[1] != 0x5A:
                raise RuntimeError("socks4 connect rejected")
            return reader, writer
        except BaseException:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            raise

    # -- plumbing -----------------------------------------------------------
    async def _pipe(self, client_reader, client_writer, up_reader, up_writer,
                    wait_downstream: bool = False):
        counts = {"up": 0, "down": 0}

        async def pump(src, dst, key):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    counts[key] += len(data)
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.IncompleteReadError, OSError):
                pass
            finally:
                try:
                    if dst.can_write_eof():
                        dst.write_eof()
                except Exception:  # noqa: BLE001
                    pass

        up_task = asyncio.create_task(pump(up_reader, client_writer, "up"))
        down_task = asyncio.create_task(pump(client_reader, up_writer, "down"))
        try:
            if wait_downstream:
                # HTTP: wait until the response is fully relayed, then stop.
                await up_task
            else:
                await asyncio.wait({up_task, down_task},
                                   return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (up_task, down_task):
                task.cancel()
            await asyncio.gather(up_task, down_task, return_exceptions=True)
            for w in (up_writer, client_writer):
                try:
                    w.close()
                except Exception:  # noqa: BLE001
                    pass
        return counts["down"], counts["up"]

    @staticmethod
    def _parse_http_head(head: bytes):
        try:
            text = head.decode("latin1")
            lines = text.split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    continue
                if ":" not in line:
                    return None
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
            return method.upper(), target, version, headers
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _target_info(method: str, target: str, headers: dict[str, str]):
        """Return host, port, origin path, absolute URI, is_connect."""
        if method == "CONNECT":
            if target.startswith("["):
                host, _, rest = target[1:].partition("]")
                port_s = rest.lstrip(":")
            else:
                host, _, port_s = target.partition(":")
            port = int(port_s) if port_s.isdigit() else 443
            return host, port, None, None, True
        if target.startswith("http://") or target.startswith("https://"):
            parts = urlsplit(target)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme == "https" else 80)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            return host, port, path, target, False
        # origin-form
        host_hdr = headers.get("host", "")
        host, _, port_s = host_hdr.partition(":")
        port = int(port_s) if port_s.isdigit() else 80
        return host, port, target, f"http://{host_hdr}{target}", False

    def _session_key(self, headers: dict[str, str], client_ip: str) -> str | None:
        auth = headers.get("proxy-authorization", "")
        if auth.lower().startswith("basic "):
            try:
                raw = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="replace")
                user = raw.split(":", 1)[0]
                if user:
                    return f"u:{user}"
            except Exception:  # noqa: BLE001
                pass
        sess = headers.get("x-proxhunt-session")
        if sess:
            return f"h:{sess}"
        if self.policy == "sticky":
            return f"ip:{client_ip}"
        return None

    async def _admin_response(self, writer, path: str):
        path = path.split("?", 1)[0]
        if path in ("/__health", "/health"):
            body = b"ok\n"
            ctype = "text/plain"
        elif path in ("/__list", "/list"):
            items = [{"proto": u.proto, "addr": u.addr, "score": u.score,
                      "mode": u.mode, "https": u.https_ok, "anon": u.anon}
                     for u in self.pool.items[:50]]
            body = json.dumps({"count": len(self.pool.items), "items": items},
                              indent=2).encode()
            ctype = "application/json"
        else:
            body = json.dumps(self.snapshot(), indent=2).encode()
            ctype = "application/json"
        writer.write((f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                      ).encode() + body)
        await writer.drain()

    @staticmethod
    async def _simple_response(writer, status: int, message: str):
        reasons = {400: "Bad Request", 502: "Bad Gateway", 504: "Gateway Timeout"}
        body = (message + "\n").encode()
        head = (f"HTTP/1.1 {status} {reasons.get(status, 'Error')}\r\n"
                f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n").encode()
        try:
            writer.write(head + body)
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    async def _socks_reply(writer, code: int):
        try:
            writer.write(bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass


async def run_servers(pool: PoolManager, bind: str, port: int, socks_port: int | None,
                      policy: str, sticky_ttl: int, retries: int,
                      log_file: str | None = None, hedge: int = 3,
                      upstream_timeout: float = 6.0) -> None:
    if log_file:
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
    server = RotatorServer(pool, bind=bind, port=port, socks_port=socks_port,
                           policy=policy, sticky_ttl=sticky_ttl, retries=retries,
                           hedge=hedge, upstream_timeout=upstream_timeout)
    await server.start()
    stop_event = asyncio.Event()

    def _stop(*_args):
        stop_event.set()

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(2, _stop)   # SIGINT
        loop.add_signal_handler(15, _stop)  # SIGTERM
    except (NotImplementedError, RuntimeError):
        pass
    print(f"proxhunt rotator up | HTTP {bind}:{port} | SOCKS5 {bind}:{socks_port or '-'} | "
          f"policy={policy} | hedge={hedge} | pool={len(pool.items)}")
    print(f"try: curl -x http://{bind}:{port} https://httpbin.org/ip")
    print(f"stats: curl -x http://{bind}:{port} http://proxhunt.local/__stats")
    await stop_event.wait()
    await server.stop()
