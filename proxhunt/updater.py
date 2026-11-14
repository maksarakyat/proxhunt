"""Update pipeline: scrape -> merge with known-good -> validate -> store."""
from __future__ import annotations

import random
import time

from .checker import Checker
from .config import (DEFAULT_CONCURRENCY, DEFAULT_MAX_NEW,
                     DEFAULT_REFRESH_ALIVE_MINUTES, DEFAULT_SPEED_CHECK,
                     DEFAULT_STREAM_CHECKS, DEFAULT_STREAM_INTERVAL,
                     DEFAULT_TCP_TIMEOUT, DEFAULT_TIMEOUT)
from .sources import scrape_all
from .store import Store
from .util import human_ts, now


def _progress_printer(label: str = "checking"):
    last = {"line": 0}

    def cb(done, total, alive, streams, errors, elapsed):
        rate = done / elapsed if elapsed > 0 else 0
        eta = (total - done) / rate if rate > 0 else 0
        print(f"\r  {label}: {done}/{total} ({rate:.1f}/s, ETA {eta:.0f}s) "
              f"alive={alive} stream={streams} err={errors}   ",
              end="", flush=True)
        last["line"] = done
    return cb


def _finish_line():
    print()


async def run_update(store: Store, protocols: set[str], max_new: int = DEFAULT_MAX_NEW,
                     concurrency: int = DEFAULT_CONCURRENCY,
                     tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
                     timeout: float = DEFAULT_TIMEOUT,
                     stream_checks: int = DEFAULT_STREAM_CHECKS,
                     stream_interval: float = DEFAULT_STREAM_INTERVAL,
                     do_anon: bool = True, speed_check: int = DEFAULT_SPEED_CHECK,
                     refresh_alive_minutes: int = DEFAULT_REFRESH_ALIVE_MINUTES,
                     only_sources: set[str] | None = None,
                     prune_days: int = 7, verbose: bool = False) -> dict:
    t0 = time.monotonic()
    print(f"[1/4] scraping sources (protocols: {','.join(sorted(protocols))}) ...")
    candidates, report = await scrape_all(protocols, only=only_sources, verbose=verbose)
    failed = [r for r in report if r["error"]]
    print(f"      {len(candidates)} unique candidates from "
          f"{len(report) - len(failed)}/{len(report)} sources")
    if failed:
        for r in failed[:8]:
            print(f"      ! {r['source']}: {r['error']}")
        if len(failed) > 8:
            print(f"      ! ... {len(failed) - 8} more source errors")

    # Filter to requested protocols (mixed JSON sources can carry all three)
    candidates = {k: v for k, v in candidates.items() if k[0] in protocols}

    print("[2/4] building work queue ...")
    recheck_rows = store.get_recent_alive(minutes=refresh_alive_minutes, limit=8000)
    recheck = [(r["proto"], r["addr"]) for r in recheck_rows if r["proto"] in protocols]
    known = set(recheck)
    new_keys = [k for k in candidates if k not in known]
    random.shuffle(new_keys)
    new_items = new_keys[:max(0, int(max_new))]
    items = recheck + new_items
    # de-duplicate while preserving order
    seen = set()
    items = [x for x in items if not (x in seen or seen.add(x))]
    print(f"      recheck={len(recheck)} new={len(new_items)} total={len(items)}")

    if candidates:
        store.upsert_candidates([(p, a, candidates.get((p, a), {})) for p, a in new_items])

    print("[3/4] validating (tcp -> http/https -> anon -> multi-hit -> speed) ...")
    stats = {"done": 0, "alive": 0, "stream": 0, "errors": 0}
    cb = _progress_printer()

    def wrapped(done, total, alive, streams, errors, elapsed):
        stats.update(done=done, alive=alive, stream=streams, errors=errors)
        cb(done, total, alive, streams, errors, elapsed)

    async with Checker(concurrency=concurrency, tcp_timeout=tcp_timeout,
                       timeout=timeout, stream_checks=stream_checks,
                       stream_interval=stream_interval, do_anon=do_anon,
                       speed_budget=speed_check, verbose=verbose) as checker:
        await checker.run(items, store=store, on_progress=wrapped)
    _finish_line()

    print("[4/4] finalizing ...")
    if prune_days and prune_days > 0:
        removed = store.prune(prune_days)
        if removed:
            print(f"      pruned {removed} stale rows")
    store.set_meta("last_update", str(now()))
    s = store.stats()
    elapsed = time.monotonic() - t0
    print(f"done in {elapsed:.0f}s | this run: checked={stats['done']} "
          f"alive={stats['alive']} stream={stats['stream']}")
    print(f"pool now: alive={s['alive']} (stream={s['stream']}, https={s['https']}), "
          f"total rows={s['total']}, avg latency={s['avg_latency'] or 0:.0f}ms")
    print(f"last update: {human_ts(s['last_update'])}")
    return {"stats": s, "run": stats, "elapsed": elapsed, "report": report}


async def run_recheck(store: Store, limit: int = 2000, stale_minutes: int = 30,
                      concurrency: int = DEFAULT_CONCURRENCY,
                      tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
                      timeout: float = DEFAULT_TIMEOUT,
                      do_anon: bool = True, only_alive: bool = True) -> dict:
    items = store.select_for_recheck(limit=limit, stale_minutes=stale_minutes,
                                     only_alive=only_alive)
    print(f"revalidating {len(items)} proxies (stale>{stale_minutes}m, limit={limit}) ...")
    stats = {"done": 0, "alive": 0, "stream": 0, "errors": 0}
    cb = _progress_printer("recheck")

    def wrapped(done, total, alive, streams, errors, elapsed):
        stats.update(done=done, alive=alive, stream=streams, errors=errors)
        cb(done, total, alive, streams, errors, elapsed)

    async with Checker(concurrency=concurrency, tcp_timeout=tcp_timeout,
                       timeout=timeout, do_anon=do_anon) as checker:
        await checker.run(items, store=store, on_progress=wrapped)
    _finish_line()
    s = store.stats()
    print(f"recheck done: alive={stats['alive']}/{stats['done']} | "
          f"pool alive={s['alive']}")
    return {"stats": s, "run": stats}
