# Changelog

All notable changes to this project are documented here.

## 1.0.0 — 2026-11-15

- Initial release.
- 28 public proxy sources with per-source sampling and cross-protocol dedupe.
- Layered validation: TCP pre-check, HTTP/HTTPS exit-IP probes, verified TLS,
  anonymity analysis, multi-hit stream classification, and optional bandwidth
  measurement.
- SQLite pool with scoring, freshness filters, failure streaks, and pruning.
- Local HTTP and SOCKS5 rotator with per-request rotation, sticky sessions,
  hedged CONNECT dialing, and ClientHello replay.
- CLI commands: `update`, `list`, `check`, `stats`, `serve`, `exec`, `daemon`,
  and `sources`.
