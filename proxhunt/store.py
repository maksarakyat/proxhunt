"""SQLite-backed proxy pool with scoring and freshness filters."""
from __future__ import annotations

import os
import sqlite3
from typing import Iterable

from .config import DB_PATH
from .util import clamp, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS proxies (
    proto         TEXT NOT NULL,
    addr          TEXT NOT NULL,
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL,
    source        TEXT,
    country       TEXT,
    src_anon      TEXT,
    src_https     INTEGER DEFAULT 0,
    http_ok       INTEGER DEFAULT 0,
    https_ok      INTEGER DEFAULT 0,
    tls_ok        INTEGER DEFAULT 0,
    stream_ok     INTEGER DEFAULT 0,
    mode          TEXT DEFAULT '',
    anon          TEXT DEFAULT 'unknown',
    exit_ip_http  TEXT,
    exit_ip_https TEXT,
    latency_ms    INTEGER,
    speed_kbps    REAL,
    success_count INTEGER DEFAULT 0,
    fail_count    INTEGER DEFAULT 0,
    fail_streak   INTEGER DEFAULT 0,
    score         REAL DEFAULT 0,
    first_seen    REAL,
    last_checked  REAL,
    last_ok       REAL,
    PRIMARY KEY (proto, addr)
);
CREATE INDEX IF NOT EXISTS idx_proxies_score ON proxies(score DESC);
CREATE INDEX IF NOT EXISTS idx_proxies_last_ok ON proxies(last_ok);
CREATE INDEX IF NOT EXISTS idx_proxies_mode ON proxies(mode, stream_ok);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

ANON_BONUS = {"elite": 12.0, "anonymous": 6.0, "unknown": 0.0, "transparent": -50.0}


def compute_score(http_ok: bool, https_ok: bool, stream_ok: bool, anon: str,
                  latency_ms: int | None, speed_kbps: float | None,
                  successes: int = 0, fails: int = 0, tls_ok: bool = False) -> float:
    if not (http_ok or https_ok):
        return 0.0
    score = 35.0
    score += 18.0 if https_ok else 0.0
    score += 10.0 if tls_ok else 0.0
    score += 22.0 if stream_ok else 0.0
    score += ANON_BONUS.get((anon or "unknown").lower(), 0.0)
    lat = latency_ms or 5000
    score += max(0.0, 15.0 - lat / 150.0)
    if speed_kbps:
        score += min(10.0, speed_kbps / 80.0)
    score += min(10.0, successes * 3.0)
    score -= min(15.0, fails * 5.0)
    return round(clamp(score, 0.0, 100.0), 2)


class Store:
    def __init__(self, path: str | None = None):
        self.path = path or DB_PATH
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(SCHEMA)
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(proxies)")}
        if "tls_ok" not in cols:
            self.conn.execute("ALTER TABLE proxies ADD COLUMN tls_ok INTEGER DEFAULT 0")
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    # -- meta ---------------------------------------------------------------
    def set_meta(self, key: str, value: str):
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))
        self.conn.commit()

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    # -- candidates ---------------------------------------------------------
    def upsert_candidates(self, candidates: Iterable[tuple[str, str, dict]]):
        rows = []
        ts = now()
        for proto, addr, meta in candidates:
            ip, _, port = addr.partition(":")
            rows.append((proto, addr, ip, int(port), meta.get("source", ""),
                         meta.get("country", ""), meta.get("src_anon", ""),
                         1 if meta.get("src_https") else 0, ts))
        self.conn.executemany(
            """INSERT INTO proxies(proto,addr,ip,port,source,country,src_anon,src_https,first_seen)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(proto,addr) DO UPDATE SET
                 source=COALESCE(NULLIF(proxies.source,''), excluded.source),
                 country=COALESCE(NULLIF(proxies.country,''), excluded.country),
                 src_anon=COALESCE(NULLIF(proxies.src_anon,''), excluded.src_anon),
                 src_https=MAX(proxies.src_https, excluded.src_https)""",
            rows)
        self.conn.commit()

    def get_recent_alive(self, minutes: int = 1440, limit: int = 5000) -> list[dict]:
        cutoff = now() - minutes * 60
        rows = self.conn.execute(
            """SELECT proto, addr, score, last_ok FROM proxies
               WHERE last_ok IS NOT NULL AND last_ok >= ? AND fail_streak < 6
               ORDER BY score DESC, last_ok DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        return [dict(r) for r in rows]

    # -- results ------------------------------------------------------------
    def apply_results(self, results: list[dict]):
        if not results:
            return
        ts = now()
        rows = []
        for r in results:
            alive = bool(r.get("http_ok") or r.get("https_ok"))
            score = compute_score(
                bool(r.get("http_ok")), bool(r.get("https_ok")),
                bool(r.get("stream_ok")), r.get("anon") or "unknown",
                r.get("latency_ms"), r.get("speed_kbps"),
                int(r.get("successes", 0)), int(r.get("fails", 0)),
                bool(r.get("tls_ok")))
            rows.append((
                int(bool(r.get("http_ok"))), int(bool(r.get("https_ok"))),
                int(bool(r.get("tls_ok"))),
                int(bool(r.get("stream_ok"))), r.get("mode") or "",
                r.get("anon") or "unknown",
                r.get("exit_ip_http"), r.get("exit_ip_https"),
                r.get("latency_ms"), r.get("speed_kbps"),
                int(r.get("successes", 0)), int(r.get("fails", 0)),
                0 if alive else 1,
                ts, ts if alive else None, ts if alive else None,
                score, r["proto"], r["addr"]))
        self.conn.executemany(
            """UPDATE proxies SET
                 http_ok=?, https_ok=?, tls_ok=?, stream_ok=?, mode=?, anon=?,
                 exit_ip_http=?, exit_ip_https=?, latency_ms=?, speed_kbps=?,
                 success_count=success_count+?, fail_count=fail_count+?,
                 fail_streak=CASE WHEN ?=0 THEN 0 ELSE fail_streak+1 END,
                 last_checked=?,
                 last_ok=CASE WHEN ? IS NOT NULL THEN ? ELSE last_ok END,
                 score=?
               WHERE proto=? AND addr=?""",
            rows)
        self.conn.commit()

    def mark_runtime_fail(self, proto: str, addr: str):
        self.conn.execute(
            """UPDATE proxies SET fail_streak=fail_streak+1, fail_count=fail_count+1,
                      last_checked=?, score=MAX(0, score*0.75)
               WHERE proto=? AND addr=?""", (now(), proto, addr))
        self.conn.commit()

    def prune(self, days: int = 7) -> int:
        cutoff = now() - days * 86400
        cur = self.conn.execute(
            """DELETE FROM proxies WHERE
                 (last_ok IS NULL AND first_seen < ?)
                 OR (last_ok IS NOT NULL AND last_ok < ?)""",
            (cutoff, cutoff))
        self.conn.commit()
        return cur.rowcount

    # -- queries ------------------------------------------------------------
    @staticmethod
    def _filters_sql(proto: str | None, mode: str | None, https_only: bool,
                     anon: str | None, country: str | None, max_latency: int | None,
                     min_score: float, alive_minutes: int,
                     include_transparent: bool = False, tls_only: bool = False
                     ) -> tuple[str, list]:
        where = ["(http_ok=1 OR https_ok=1)", "fail_streak < 3", "score >= ?"]
        args: list = [min_score]
        if alive_minutes and alive_minutes > 0:
            where.append("last_ok IS NOT NULL AND last_ok >= ?")
            args.append(now() - alive_minutes * 60)
        if proto and proto != "any":
            protos = [p.strip() for p in proto.split(",") if p.strip()]
            if protos:
                where.append("proto IN (%s)" % ",".join("?" * len(protos)))
                args.extend(protos)
        if mode == "stream":
            where.append("stream_ok=1")
        if https_only:
            where.append("https_ok=1")
        if tls_only:
            where.append("tls_ok=1")
        if anon and anon != "any":
            anons = [a.strip() for a in anon.split(",") if a.strip()]
            if anons:
                where.append("COALESCE(anon,'unknown') IN (%s)" % ",".join("?" * len(anons)))
                args.extend(anons)
        elif not include_transparent:
            where.append("COALESCE(anon,'unknown') != 'transparent'")
        if country:
            where.append("UPPER(country) = UPPER(?)")
            args.append(country)
        if max_latency:
            where.append("latency_ms IS NOT NULL AND latency_ms <= ?")
            args.append(max_latency)
        return " AND ".join(where), args

    def list_proxies(self, limit: int = 100, proto: str | None = None,
                     mode: str | None = None, https_only: bool = False,
                     anon: str | None = None, country: str | None = None,
                     max_latency: int | None = None, min_score: float = 0.0,
                     alive_minutes: int = 120, include_transparent: bool = False,
                     order: str = "score", tls_only: bool = False) -> list[dict]:
        where, args = self._filters_sql(proto, mode, https_only, anon, country,
                                        max_latency, min_score, alive_minutes,
                                        include_transparent, tls_only)
        order_sql = "score DESC, latency_ms ASC"
        if order == "random":
            order_sql = "RANDOM()"
        elif order == "latency":
            order_sql = "latency_ms ASC"
        elif order == "fresh":
            order_sql = "last_ok DESC"
        sql = f"SELECT * FROM proxies WHERE {where} ORDER BY {order_sql} LIMIT ?"
        args.append(int(limit))
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def pool(self, limit: int = 500, proto: str | None = None,
             require_https: bool = False, require_stream: bool = False,
             min_score: float = 0.0, alive_minutes: int = 180,
             tls_only: bool = False) -> list[dict]:
        where, args = self._filters_sql(
            proto, "stream" if require_stream else None, require_https,
            None, None, None, min_score, alive_minutes,
            include_transparent=False, tls_only=tls_only)
        sql = (f"SELECT * FROM proxies WHERE {where} "
               f"ORDER BY score DESC, latency_ms ASC LIMIT ?")
        args.append(int(limit))
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def get_one(self, proto: str, addr: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM proxies WHERE proto=? AND addr=?", (proto, addr)).fetchone()
        return dict(row) if row else None

    def select_for_recheck(self, limit: int = 5000, stale_minutes: int = 30,
                           only_alive: bool = True) -> list[tuple[str, str]]:
        where = []
        args: list = []
        if only_alive:
            where.append("last_ok IS NOT NULL")
        if stale_minutes and stale_minutes > 0:
            where.append("(last_checked IS NULL OR last_checked <= ?)")
            args.append(now() - stale_minutes * 60)
        sql = "SELECT proto, addr FROM proxies"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY COALESCE(last_checked,0) ASC LIMIT ?"
        args.append(int(limit))
        return [(r["proto"], r["addr"]) for r in self.conn.execute(sql, args)]

    # -- stats --------------------------------------------------------------
    def stats(self) -> dict:
        cutoff = now() - 120 * 60
        c = self.conn.execute
        total = c("SELECT COUNT(*) n FROM proxies").fetchone()["n"]
        alive = c("""SELECT COUNT(*) n FROM proxies WHERE last_ok IS NOT NULL
                     AND last_ok >= ? AND fail_streak < 3
                     AND (http_ok=1 OR https_ok=1)""", (cutoff,)).fetchone()["n"]
        stream = c("""SELECT COUNT(*) n FROM proxies WHERE last_ok >= ? AND stream_ok=1
                      AND fail_streak < 3""", (cutoff,)).fetchone()["n"]
        https = c("""SELECT COUNT(*) n FROM proxies WHERE last_ok >= ? AND https_ok=1
                     AND fail_streak < 3""", (cutoff,)).fetchone()["n"]
        tls = c("""SELECT COUNT(*) n FROM proxies WHERE last_ok >= ? AND tls_ok=1
                   AND fail_streak < 3""", (cutoff,)).fetchone()["n"]
        by_proto = {r["proto"]: r["n"] for r in c(
            "SELECT proto, COUNT(*) n FROM proxies WHERE last_ok >= ? AND fail_streak < 3 "
            "GROUP BY proto", (cutoff,))}
        by_anon = {r["anon"]: r["n"] for r in c(
            "SELECT COALESCE(anon,'unknown') anon, COUNT(*) n FROM proxies "
            "WHERE last_ok >= ? AND fail_streak < 3 GROUP BY anon", (cutoff,))}
        avg_lat = c("""SELECT AVG(latency_ms) v FROM proxies WHERE last_ok >= ?
                       AND fail_streak < 3 AND latency_ms IS NOT NULL""", (cutoff,)).fetchone()["v"]
        by_country = [(r["country"] or "??", r["n"]) for r in c(
            """SELECT country, COUNT(*) n FROM proxies WHERE last_ok >= ?
               AND fail_streak < 3 AND country != '' GROUP BY country
               ORDER BY n DESC LIMIT 10""", (cutoff,))]
        return {"total": total, "alive": alive, "stream": stream, "https": https,
                "tls": tls,
                "by_proto": by_proto, "by_anon": by_anon,
                "avg_latency": avg_lat, "countries": by_country,
                "last_update": float(self.get_meta("last_update") or 0) or None}
