"""Command line interface for proxhunt."""
from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import os
import random
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone

from . import __version__
from .checker import Checker
from .config import (DEFAULT_ALIVE_MINUTES, DEFAULT_CONCURRENCY, DEFAULT_MAX_NEW,
                     DEFAULT_PORT, DEFAULT_REFRESH_ALIVE_MINUTES, DEFAULT_RETRIES,
                     DEFAULT_SOCKS_PORT, DEFAULT_SPEED_CHECK, DEFAULT_STICKY_TTL,
                     DEFAULT_STREAM_CHECKS, DEFAULT_STREAM_INTERVAL,
                     DEFAULT_TCP_TIMEOUT, DEFAULT_TIMEOUT)
from .rotator import PoolManager, run_servers
from .sources import list_sources
from .store import Store
from .updater import run_recheck, run_update
from .util import human_ts

EXPORT_FIELDS = ["proto", "addr", "mode", "anon", "https_ok", "tls_ok", "stream_ok",
                 "latency_ms", "speed_kbps", "score", "country", "exit_ip_https",
                 "last_ok"]


def _iso(ts):
    if not ts:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _row_out(r: dict) -> dict:
    out = {k: r.get(k) for k in EXPORT_FIELDS}
    out["last_ok"] = _iso(r.get("last_ok"))
    out["last_checked"] = _iso(r.get("last_checked"))
    return out


def _proxy_uri(r: dict, remote_dns: bool = False) -> str:
    if r["proto"] == "socks5":
        return f"socks5h://{r['addr']}" if remote_dns else f"socks5://{r['addr']}"
    if r["proto"] == "socks4":
        return f"socks4a://{r['addr']}" if remote_dns else f"socks4://{r['addr']}"
    return f"http://{r['addr']}"


def cmd_update(args):
    store = Store(args.db)
    protocols = {p.strip() for p in args.protocols.split(",") if p.strip()}
    only = {s.strip() for s in args.sources.split(",")} if args.sources else None
    asyncio.run(run_update(
        store, protocols=protocols, max_new=args.max_new,
        concurrency=args.concurrency, tcp_timeout=args.tcp_timeout,
        timeout=args.timeout, stream_checks=0 if args.no_stream else args.stream_checks,
        stream_interval=args.stream_interval, do_anon=not args.no_anon,
        speed_check=args.speed_check,
        refresh_alive_minutes=args.refresh_alive_minutes,
        only_sources=only, prune_days=args.prune_days, verbose=args.verbose))
    store.close()


async def _live_check(store: Store, items: list[tuple[str, str]],
                      concurrency: int = 100, stream_checks: int = 3):
    async with Checker(concurrency=concurrency, stream_checks=stream_checks) as checker:
        await checker.run(items, store=store)


def cmd_list(args):
    store = Store(args.db)
    if args.live:
        cand = store.list_proxies(
            limit=min(max(args.limit * 3, 10), 300), proto=args.proto,
            mode=None if args.mode == "any" else args.mode,
            https_only=args.https_only, anon=args.anon, country=args.country,
            max_latency=None, min_score=0.0, alive_minutes=0,
            include_transparent=args.include_transparent,
            order="score", tls_only=args.tls_only)
        items = [(r["proto"], r["addr"]) for r in cand]
        if items:
            print(f"[live] revalidating {len(items)} candidates "
                  f"(concurrency={args.live_concurrency}) ...", file=sys.stderr)
            asyncio.run(_live_check(store, items, args.live_concurrency,
                                    stream_checks=3 if args.mode != "once" else 0))
    rows = store.list_proxies(
        limit=args.limit, proto=args.proto, mode=None if args.mode == "any" else args.mode,
        https_only=args.https_only, anon=args.anon, country=args.country,
        max_latency=args.max_latency, min_score=args.min_score,
        alive_minutes=args.alive_minutes, include_transparent=args.include_transparent,
        order=args.order, tls_only=args.tls_only)
    store.close()
    if not rows:
        print("no proxies matched. run: ./run.sh update", file=sys.stderr)
        return 1
    if args.format == "txt":
        for r in rows:
            print(r["addr"])
    elif args.format == "uri":
        for r in rows:
            print(f"{r['proto']}://{r['addr']}")
    elif args.format == "json":
        print(json.dumps([_row_out(r) for r in rows], indent=2))
    elif args.format == "jsonl":
        for r in rows:
            print(json.dumps(_row_out(r)))
    elif args.format == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS + ["last_checked"])
        w.writeheader()
        for r in rows:
            w.writerow(_row_out(r))
        print(buf.getvalue().rstrip())
    elif args.format == "curl":
        for r in rows:
            print(f"curl -x {shlex.quote(_proxy_uri(r))} https://httpbin.org/ip")
    elif args.format == "env":
        r = rows[0]
        uri = _proxy_uri(r, remote_dns=True)
        for key in ("http_proxy", "https_proxy", "all_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            print(f"export {key}={shlex.quote(uri)}")
    return 0


def cmd_check(args):
    store = Store(args.db)
    asyncio.run(run_recheck(store, limit=args.limit, stale_minutes=args.stale_minutes,
                            concurrency=args.concurrency, timeout=args.timeout,
                            tcp_timeout=args.tcp_timeout, do_anon=not args.no_anon,
                            only_alive=not args.all))
    if args.prune_days:
        n = store.prune(args.prune_days)
        print(f"pruned {n} stale rows")
    store.close()


def cmd_stats(args):
    store = Store(args.db)
    s = store.stats()
    print("proxhunt pool status")
    print(f"  total rows      : {s['total']}")
    print(f"  alive (<2h)     : {s['alive']}")
    print(f"  stream-capable  : {s['stream']}")
    print(f"  https/CONNECT   : {s['https']}")
    print(f"  TLS verified    : {s['tls']}")
    print(f"  avg latency     : {s['avg_latency'] or 0:.0f} ms")
    print(f"  protocols       : {', '.join(f'{k}={v}' for k, v in s['by_proto'].items()) or '-'}")
    print(f"  anonymity       : {', '.join(f'{k}={v}' for k, v in s['by_anon'].items()) or '-'}")
    if s["countries"]:
        print(f"  top countries   : {', '.join(f'{c}={n}' for c, n in s['countries'])}")
    print(f"  last update     : {human_ts(s['last_update'])}")
    store.close()


def cmd_sources(args):
    for s in list_sources():
        print(f"{s.name:24s} {s.proto:8s} cap={s.cap:<5d} {s.url}")
    return 0


def cmd_serve(args):
    if args.bind not in ("127.0.0.1", "::1", "localhost") and not args.allow_public:
        print("refusing to bind a public interface without --allow-public "
              "(an open proxy is dangerous).", file=sys.stderr)
        return 2
    store = Store(args.db)
    pool = PoolManager(store, protos=args.proto, require_https=args.require_https,
                       require_stream=args.require_stream, min_score=args.min_score,
                       alive_minutes=args.alive_minutes, limit=args.pool_size,
                       require_tls=args.tls_only)
    if pool.refresh() == 0:
        print("warning: pool is empty; run './run.sh update' first", file=sys.stderr)
    asyncio.run(run_servers(pool, bind=args.bind, port=args.port,
                            socks_port=None if args.socks_port == 0 else args.socks_port,
                            policy=args.policy, sticky_ttl=args.sticky_ttl,
                            retries=args.retries, log_file=args.log_file,
                            hedge=args.hedge, upstream_timeout=args.upstream_timeout))
    store.close()
    return 0


def cmd_exec(args):
    store = Store(args.db)
    rows = store.list_proxies(
        limit=max(50, args.retries * 10), proto=args.proto,
        mode="stream" if args.mode == "stream" else None,
        https_only=args.https_only, min_score=args.min_score,
        alive_minutes=args.alive_minutes, order="score", tls_only=args.tls_only)
    store.close()
    if not rows:
        print("no proxies available; run ./run.sh update", file=sys.stderr)
        return 3
    random.shuffle(rows)
    attempts = min(args.retries, len(rows))
    for i in range(attempts):
        r = rows[i]
        uri = _proxy_uri(r, remote_dns=True)
        env = dict(os.environ)
        for key in ("http_proxy", "https_proxy", "all_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env[key] = uri
        if not args.quiet:
            print(f"[exec] attempt {i + 1}/{attempts} via {r['proto']}://{r['addr']} "
                  f"(mode={r['mode'] or '-'}, score={r['score']:.0f})", file=sys.stderr)
        try:
            rc = subprocess.call(args.command, env=env)
        except FileNotFoundError as exc:
            print(f"command not found: {exc}", file=sys.stderr)
            return 127
        except KeyboardInterrupt:
            return 130
        if rc == 0:
            return 0
        if not args.quiet:
            print(f"[exec] command exited {rc}; trying next proxy", file=sys.stderr)
    return 1


def cmd_daemon(args):
    print(f"proxhunt daemon: update every {args.interval}s "
          f"(ctrl-c to stop); min_alive={args.min_alive}")
    cycle = 0
    try:
        while True:
            cycle += 1
            print(f"\n=== cycle {cycle} @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
            store = Store(args.db)
            try:
                result = asyncio.run(run_update(
                    store, protocols={p.strip() for p in args.protocols.split(",")},
                    max_new=args.max_new, concurrency=args.concurrency,
                    timeout=args.timeout, tcp_timeout=args.tcp_timeout,
                    stream_checks=args.stream_checks, stream_interval=args.stream_interval,
                    do_anon=not args.no_anon, speed_check=args.speed_check,
                    refresh_alive_minutes=args.refresh_alive_minutes,
                    prune_days=args.prune_days, verbose=args.verbose))
                alive = result["stats"]["alive"]
                if alive < args.min_alive:
                    print(f"WARNING: only {alive} alive proxies (< min_alive={args.min_alive})",
                          file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                print(f"update cycle failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            finally:
                store.close()
            if args.once:
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped")


def build_parser():
    p = argparse.ArgumentParser(
        prog="proxhunt",
        description="Find, validate and rotate free proxies (HTTP/SOCKS) "
                    "for authorized testing.")
    p.add_argument("--db", default=None, help="SQLite database path")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"proxhunt {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    u = sub.add_parser("update", help="scrape + validate fresh proxies")
    u.add_argument("--protocols", default="http,socks5",
                   help="comma list: http,socks5,socks4 (default http,socks5)")
    u.add_argument("--max-new", type=int, default=DEFAULT_MAX_NEW,
                   help="max new candidates to check this run")
    u.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    u.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT)
    u.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help="per-request timeout seconds")
    u.add_argument("--stream-checks", type=int, default=DEFAULT_STREAM_CHECKS,
                   help="sequential hits used for streaming classification")
    u.add_argument("--stream-interval", type=float, default=DEFAULT_STREAM_INTERVAL)
    u.add_argument("--speed-check", type=int, default=DEFAULT_SPEED_CHECK,
                   help="bandwidth-test up to N stream candidates (0=off)")
    u.add_argument("--refresh-alive-minutes", type=int, default=DEFAULT_REFRESH_ALIVE_MINUTES,
                   help="recheck proxies verified within this window")
    u.add_argument("--no-anon", action="store_true", help="skip anonymity check")
    u.add_argument("--no-stream", action="store_true", help="skip multi-hit test")
    u.add_argument("--sources", default=None, help="only these source names (comma)")
    u.add_argument("--prune-days", type=int, default=7)
    u.set_defaults(func=cmd_update)

    l = sub.add_parser("list", help="print the current live pool")
    l.add_argument("--proto", default="any", help="http,socks5,socks4,any")
    l.add_argument("--mode", choices=["any", "once", "stream"], default="any")
    l.add_argument("--https-only", action="store_true", help="only CONNECT-capable")
    l.add_argument("--tls-only", action="store_true",
                   help="only proxies that pass verified TLS (no MITM)")
    l.add_argument("--anon", default="any", help="elite,anonymous (default any, no transparent)")
    l.add_argument("--include-transparent", action="store_true")
    l.add_argument("--country", default=None, help="ISO country code from source metadata")
    l.add_argument("--max-latency", type=int, default=None)
    l.add_argument("--min-score", type=float, default=0.0)
    l.add_argument("--alive-minutes", type=int, default=DEFAULT_ALIVE_MINUTES)
    l.add_argument("--limit", type=int, default=100)
    l.add_argument("--live", action="store_true",
                   help="revalidate candidates right now, then print survivors")
    l.add_argument("--live-concurrency", type=int, default=100)
    l.add_argument("--order", choices=["score", "random", "latency", "fresh"],
                   default="score")
    l.add_argument("--format", choices=["txt", "uri", "json", "jsonl", "csv", "curl", "env"],
                   default="txt")
    l.set_defaults(func=cmd_list)

    c = sub.add_parser("check", help="revalidate stored proxies")
    c.add_argument("--limit", type=int, default=2000)
    c.add_argument("--stale-minutes", type=int, default=30)
    c.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    c.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT)
    c.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    c.add_argument("--no-anon", action="store_true")
    c.add_argument("--all", action="store_true",
                   help="also recheck rows that are not currently alive")
    c.add_argument("--prune-days", type=int, default=0)
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("stats", help="pool statistics")
    s.set_defaults(func=cmd_stats)

    src = sub.add_parser("sources", help="list configured sources")
    src.set_defaults(func=cmd_sources)

    sv = sub.add_parser("serve", help="run local rotating HTTP + SOCKS5 proxy")
    sv.add_argument("--bind", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=DEFAULT_PORT)
    sv.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT,
                    help="0 disables the SOCKS5 listener")
    sv.add_argument("--policy", choices=["rotate", "sticky"], default="rotate")
    sv.add_argument("--sticky-ttl", type=int, default=DEFAULT_STICKY_TTL)
    sv.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                    help="upstreams tried per request")
    sv.add_argument("--hedge", type=int, default=3,
                    help="race N upstream CONNECTs in parallel (1=off)")
    sv.add_argument("--upstream-timeout", type=float, default=6.0,
                    help="seconds per upstream connect/handshake")
    sv.add_argument("--proto", default="http,socks5")
    sv.add_argument("--require-https", action="store_true",
                    help="only CONNECT-capable upstreams")
    sv.add_argument("--tls-only", action="store_true",
                    help="only upstreams with verified TLS (no MITM)")
    sv.add_argument("--require-stream", action="store_true",
                    help="only stream-tested upstreams")
    sv.add_argument("--min-score", type=float, default=0.0)
    sv.add_argument("--alive-minutes", type=int, default=60)
    sv.add_argument("--pool-size", type=int, default=500)
    sv.add_argument("--allow-public", action="store_true",
                    help="allow binding a non-loopback address (dangerous)")
    sv.add_argument("--log-file", default=None)
    sv.set_defaults(func=cmd_serve)

    e = sub.add_parser("exec", help="run one command through a rotating proxy (with retries)")
    e.add_argument("--mode", choices=["any", "once", "stream"], default="any")
    e.add_argument("--proto", default="any")
    e.add_argument("--https-only", action="store_true")
    e.add_argument("--tls-only", action="store_true")
    e.add_argument("--min-score", type=float, default=0.0)
    e.add_argument("--alive-minutes", type=int, default=DEFAULT_ALIVE_MINUTES)
    e.add_argument("--retries", type=int, default=3)
    e.add_argument("--quiet", action="store_true")
    e.add_argument("command", nargs=argparse.REMAINDER,
                   help="command after --, e.g. -- curl -s https://httpbin.org/ip")
    e.set_defaults(func=cmd_exec)

    d = sub.add_parser("daemon", help="keep the pool fresh on a schedule")
    d.add_argument("--interval", type=int, default=900)
    d.add_argument("--min-alive", type=int, default=50)
    d.add_argument("--protocols", default="http,socks5")
    d.add_argument("--max-new", type=int, default=DEFAULT_MAX_NEW)
    d.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    d.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT)
    d.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    d.add_argument("--stream-checks", type=int, default=DEFAULT_STREAM_CHECKS)
    d.add_argument("--stream-interval", type=float, default=DEFAULT_STREAM_INTERVAL)
    d.add_argument("--speed-check", type=int, default=DEFAULT_SPEED_CHECK)
    d.add_argument("--refresh-alive-minutes", type=int, default=DEFAULT_REFRESH_ALIVE_MINUTES)
    d.add_argument("--no-anon", action="store_true")
    d.add_argument("--prune-days", type=int, default=7)
    d.add_argument("--once", action="store_true")
    d.set_defaults(func=cmd_daemon)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "exec" and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if args.cmd == "exec" and not args.command:
        parser.error("exec needs a command, e.g. proxhunt exec -- curl -s https://httpbin.org/ip")
    if getattr(args, "verbose", False):
        import logging
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        rc = args.func(args)
        return rc or 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
