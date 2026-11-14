# PROXHUNT

**Free-proxy intelligence for authorized security work.**

`proxhunt` discovers public HTTP/HTTPS/SOCKS proxies, validates them against real
egress behavior, classifies what each proxy can actually sustain, and exposes the
result as a clean CLI, a local rotating proxy, or a one-shot execution wrapper.

It is built around a simple principle: **a proxy list is not a proxy pool**. An
open port is not a working proxy. A working proxy for one request is not a proxy
for a session. `proxhunt` measures the difference.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](#requirements)
[![License](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey)](#requirements)

---

## Why

Public proxy lists rot constantly. A proxy that answered a health check ten
minutes ago may be gone, throttled, or actively MITM-ing TLS now. Most tooling
treats that as an inconvenience. `proxhunt` treats it as the core problem.

- **Liveness is measured, not assumed.** Every candidate passes a TCP pre-check,
  HTTP and HTTPS exit-IP probes, and a local-address comparison.
- **Capability is classified.** `once` means one hit. `stream` means three
  sequential hits with a stable exit IP. `tls_ok` means the certificate chain
  verified against the system CA store.
- **Freshness is enforced.** The pool carries `last_ok`, `fail_streak`, and a
  freshness-weighted score. `daemon`, `check`, and `list --live` keep it current.
- **Rotation is local.** One local endpoint can rotate per request or hold a
  sticky session for multi-step workloads, streaming, and downloads.
- **No telemetry. No API keys. Local-first.** Everything lives in a local SQLite
  database.

> Free proxies are untrusted egress. They can log traffic, inject content, or
> terminate TLS with their own certificate. Never send credentials, session
> cookies, or sensitive data through one. Use `--tls-only` when the client
> verifies certificates. This project is intended for authorized penetration
> testing, OSINT, and research against systems you are permitted to test.

---

## Features

| Area | Capability |
|---|---|
| Discovery | 28 public sources: ProxyScrape v4, Proxifly, TheSpeedX, MonoSanS, OpenProxyList, ProxySpace, JetKai, mmpx12, Vakhov, HideIP, Ercin, MADEVAL, and more |
| Normalization | Dedupe across protocols, per-source sampling, strict IPv4/port validation |
| Validation | TCP pre-check, HTTP and HTTPS exit-IP probes, verified TLS, anonymity classification, multi-hit stability, optional 128 KiB throughput test |
| Classification | `once`, `stream`, `https_ok`, `tls_ok`, `anon=elite/anonymous/transparent` |
| Storage | SQLite (WAL), scoring, success/failure history, freshness filters, pruning |
| Rotation | Local HTTP forward proxy and SOCKS5 listener; per-request rotation or sticky sessions |
| Resilience | Hedged CONNECT dialing, pre-data failover, ClientHello replay, upstream cooldown |
| Operations | `update`, `check`, `list --live`, `serve`, `exec`, `daemon`, `stats`, `sources` |
| Output | `txt`, `uri`, `json`, `jsonl`, `csv`, `curl`, `env` |

---

## Architecture

```text
 28 public sources
       │
       ▼
 ┌─────────────┐    dedupe + sample    ┌──────────────────┐
 │  Scraper    │ ────────────────────▶ │ Candidate store  │
 └─────────────┘                       └────────┬─────────┘
                                               │
                                               ▼
 ┌──────────────────────────────────────────────────────────┐
 │ Validator                                                │
 │  1. TCP pre-check                                        │
 │  2. HTTP + HTTPS exit-IP probes                          │
 │  3. verified TLS (system CA)                             │
 │  4. anonymity header analysis                            │
 │  5. multi-hit stream test (stable exit IP)               │
 │  6. optional bandwidth probe                             │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ SQLite pool   │
                    │ score/freshness│
                    └───────┬───────┘
                            │
          ┌─────────────────┼──────────────────┐
          ▼                 ▼                  ▼
     `list` / `exec`   local rotator      `daemon` refresh
                        HTTP + SOCKS5
```

---

## Requirements

- Python 3.10 or newer (tested on 3.13)
- Linux, macOS, or WSL2
- `curl` and standard build tools for the virtual environment
- Network access to public proxy-list sources and judge endpoints

---

## Install

```bash
git clone <repository-url> proxhunt
cd proxhunt
./install.sh
./run.sh --version
```

`install.sh` creates a dedicated virtual environment at `~/.venvs/proxhunt`
(override with `PROXHUNT_VENV=/path/to/venv`) and installs the package in editable
mode. `run.sh` is a thin launcher; every command below can be run through it.

Verify the installation:

```bash
./run.sh sources        # list configured sources
./run.sh stats          # show the local pool
```

Data lives in `data/proxhunt.sqlite3`. It can be relocated:

```bash
PROXHUNT_DB=/srv/proxhunt/pool.sqlite3 ./run.sh stats
# or, before the subcommand:
./run.sh --db /srv/proxhunt/pool.sqlite3 stats
```

---

## Quick Start

```bash
# 1. Discover and validate candidates (first run typically 2–4 minutes)
./run.sh update --max-new 15000 --concurrency 700

# 2. Inspect the live pool
./run.sh stats
./run.sh list --mode stream --https-only --tls-only --limit 20

# 3. Start the local rotator
./run.sh serve --port 8899 --socks-port 8900 \
  --tls-only --require-stream --retries 12 --hedge 4

# 4. Use it
curl -x http://127.0.0.1:8899 https://api.ipify.org?format=json
```

Each request through the rotator selects a different upstream, races a few
CONNECT handshakes, and retries transparently when an upstream dies before
sending TLS data.

---

## Proxy Classes

`proxhunt` does not reduce every proxy to `alive/dead`.

| Field | Meaning | Typical use |
|---|---|---|
| `http_ok` | Plain HTTP request through an HTTP proxy succeeded | HTTP-only scraping |
| `https_ok` | `CONNECT` to port 443 succeeded | HTTPS, but the proxy may MITM |
| `tls_ok` | Verified TLS handshake through the tunnel succeeded | Clients that validate certificates |
| `mode=once` | At least one probe succeeded | One-shot `curl`, single API call |
| `mode=stream` | Three sequential requests succeeded with the same exit IP | Sessions, downloads, HLS/DASH, sticky workflows |
| `anon=elite` | No proxy-revealing headers detected | Cleanest public exits |
| `anon=anonymous` | Proxy headers present, original client IP not leaked | General rotation |
| `anon=transparent` | Client IP leaked or exit equals the local public IP | Filtered out by default |

A `stream` classification is a stability signal, not a bandwidth guarantee. Use
`--speed-check` during `update` and prefer proxies with a high `speed_kbps` for
media workloads.

---

## Command Reference

### `update`

Scrape sources, merge with the known-good pool, validate, score, and persist.

```bash
./run.sh update [options]
```

| Option | Default | Description |
|---|---|---|
| `--protocols http,socks5` | `http,socks5` | Protocols to collect (`socks4` optional) |
| `--max-new 15000` | 15000 | New candidates to validate per run |
| `--concurrency 600` | 600 | Parallel validators |
| `--timeout 9` | 9 s | Per-request judge timeout |
| `--stream-checks 3` | 3 | Sequential hits used for stream classification |
| `--stream-interval 1.2` | 1.2 s | Delay between stream hits |
| `--speed-check 200` | 200 | Bandwidth-test up to N stream candidates (0 disables) |
| `--refresh-alive-minutes 1440` | 1440 | Recheck proxies verified within this window |
| `--no-anon` | off | Skip anonymity analysis |
| `--no-stream` | off | Skip multi-hit testing |
| `--sources name1,name2` | all | Restrict to named sources |
| `--prune-days 7` | 7 | Remove rows not seen alive within N days |

Pipeline:

1. Scrape all selected sources concurrently.
2. Normalize, dedupe, and sample per source.
3. Queue recent live proxies first, then new candidates.
4. Validate and classify.
5. Recompute scores, update freshness, prune stale rows.

### `list`

Print the pool. Output is clean on stdout; progress and diagnostics go to stderr.

```bash
./run.sh list [filters] [--format ...]
```

| Filter | Example | Description |
|---|---|---|
| `--proto` | `http`, `socks5`, `http,socks5`, `any` | Protocol |
| `--mode` | `once`, `stream`, `any` | Multi-hit capability |
| `--https-only` | — | Require CONNECT support |
| `--tls-only` | — | Require verified TLS (no MITM) |
| `--anon` | `elite`, `elite,anonymous` | Default `any`; transparent is excluded |
| `--include-transparent` | — | Include transparent proxies |
| `--country` | `US`, `DE` | Source metadata country, when available |
| `--max-latency` | `2000` | Milliseconds |
| `--min-score` | `50` | Minimum score |
| `--alive-minutes` | `120` | Only proxies checked within N minutes (0 disables) |
| `--live` | — | Revalidate candidates now, then print survivors |
| `--live-concurrency` | `100` | Parallelism for `--live` |
| `--limit` | `100` | Number of rows |
| `--order` | `score`, `random`, `latency`, `fresh` | Sort order |
| `--format` | `txt`, `uri`, `json`, `jsonl`, `csv`, `curl`, `env` | Output format |

Examples:

```bash
# Best verified stream proxies
./run.sh list --mode stream --https-only --tls-only --limit 20

# Revalidate the top candidates immediately and print only survivors
./run.sh list --live --mode stream --https-only --tls-only --limit 10

# Ready-to-run curl commands
./run.sh list --limit 5 --format curl

# Shell environment for the first proxy
eval "$(./run.sh list --limit 1 --format env)"
```

`txt` prints `ip:port`; `uri` prints `proto://ip:port`; `json` includes `mode`,
`anon`, `https_ok`, `tls_ok`, `stream_ok`, `latency_ms`, `speed_kbps`, `score`,
`country`, `exit_ip_https`, and timestamps.

### `check`

Revalidate stored proxies without scraping.

```bash
./run.sh check --limit 500 --stale-minutes 30
```

By default only rows that have been alive are checked. Add `--all` to include
dead rows. This is the fast freshness operation to run between full updates.

### `stats`

```bash
./run.sh stats
```

Shows total rows, live proxies, stream-capable, HTTPS/CONNECT, TLS-verified,
latency, protocol/anonymity/country distribution, and last update time.

### `serve`

Local rotating proxy with HTTP and SOCKS5 listeners.

```bash
./run.sh serve \
  --port 8899 --socks-port 8900 \
  --policy rotate \
  --tls-only --require-stream \
  --retries 12 --hedge 4 --upstream-timeout 5
```

| Option | Default | Description |
|---|---|---|
| `--port` | `8899` | HTTP proxy listener |
| `--socks-port` | `8900` | SOCKS5 listener (`0` disables) |
| `--policy` | `rotate` | `rotate` per request or `sticky` per session |
| `--sticky-ttl` | `300` | Sticky session lifetime in seconds (sliding) |
| `--retries` | `4` | Total upstream attempts per request |
| `--hedge` | `3` | CONNECT handshakes raced in parallel |
| `--upstream-timeout` | `6` | Seconds per connect/handshake |
| `--require-https` | off | Only CONNECT-capable upstreams |
| `--tls-only` | off | Only upstreams with verified TLS |
| `--require-stream` | off | Only stream-tested upstreams |
| `--min-score` | `0` | Minimum score |
| `--alive-minutes` | `60` | Freshness window |
| `--allow-public` | off | Permit non-loopback bind (dangerous: open proxy) |

Operational endpoints, reached through the proxy itself:

```bash
curl -x http://127.0.0.1:8899 http://proxhunt.local/__stats
curl -x http://127.0.0.1:8899 http://proxhunt.local/__list
curl -x http://127.0.0.1:8899 http://proxhunt.local/__health
```

#### Rotation

```bash
export http_proxy=http://127.0.0.1:8899
export https_proxy=http://127.0.0.1:8899

for i in 1 2 3 4 5; do
  curl -sS --max-time 40 https://api.ipify.org?format=json
  echo
done
```

Each request gets a different upstream. Failed upstreams enter a cooldown and are
removed from the hot path; the next request retries another candidate.

#### Sticky sessions

1. **Proxy auth username** — portable across clients and works for CONNECT:

   ```bash
   curl -x http://session-a:any@127.0.0.1:8899 https://api.ipify.org
   curl -x http://session-a:any@127.0.0.1:8899 https://api.ipify.org
   ```

2. **Session header** — for plain HTTP requests. Custom headers are not visible to
   the proxy in a CONNECT tunnel, so use this only where the proxy sees the HTTP
   request itself:

   ```bash
   curl -H 'X-Proxhunt-Session: job-42' \
     -x http://127.0.0.1:8899 http://ifconfig.me/ip
   ```

3. **Global sticky policy** — keyed by client IP. Best for streaming clients that
   cannot set proxy auth or headers:

   ```bash
   ./run.sh serve --policy sticky --sticky-ttl 900
   ```

Sticky mode is recommended for multi-step login flows, ranged downloads, HLS/DASH
segments, `yt-dlp`, `ffmpeg`, and resumable transfers.

### `exec`

Run one command through a randomly selected proxy, with retries.

```bash
./run.sh exec --mode stream --tls-only --retries 5 -- \
  curl -sS https://api.ipify.org?format=json
```

`exec` sets `http_proxy`, `https_proxy`, and `all_proxy` for the child process. If
the command exits non-zero, the next proxy is tried. Do not use multiple retries
for non-idempotent commands; use `--retries 1`.

### `daemon`

Keep the pool fresh on a schedule.

```bash
./run.sh daemon --interval 600 --max-new 12000 --concurrency 700
```

Each cycle performs the same scrape → recheck → validate → prune pipeline as
`update`. Run `serve` in a separate process; it reloads the SQLite pool every ten
seconds. `daemon --once` performs a single cycle, useful for verification or
external schedulers.

### `sources`

```bash
./run.sh sources
```

Prints every configured source, protocol hint, per-run cap, and URL.

---

## Validation Pipeline

```text
TCP pre-check
  └─ closed port: stop, no judge traffic

HTTP probe          HTTPS probe
  └─ exit IP A        └─ exit IP B
       │                    │
       └──────┬─────────────┘
              ▼
       public + not-local check
              │
        verified TLS probe
              │
        anonymity analysis
              │
        multi-hit stream test
              │
        optional bandwidth probe
```

Details:

1. **TCP pre-check.** A bare connect with a short timeout filters closed ports
   before any HTTP request is sent.
2. **Exit-IP probes.** HTTP and HTTPS judges return the observed public address.
   Private, loopback, reserved, and local addresses are rejected.
3. **Transparency check.** If the observed exit equals the local public address,
   the proxy is marked `transparent`.
4. **Verified TLS.** A second HTTPS request uses the system CA store. A certificate
   failure sets `tls_ok=0` but preserves `https_ok=1` so the proxy can still be
   used explicitly with certificate verification disabled.
5. **Anonymity.** A header-echo judge checks `X-Forwarded-For`, `X-Real-IP`,
   `Forwarded`, `Via`, and related headers. Header leakage or the local IP in a
   forwarding header marks the proxy transparent.
6. **Multi-hit stream test.** Three sequential requests with a configurable
   interval. All must succeed and return the same exit IP.
7. **Bandwidth (optional).** A 128 KiB transfer from Cloudflare measures practical
   throughput for ranking stream candidates.

Scores are bounded to `0–100`:

```text
35 base
+18  HTTPS/CONNECT
+10  verified TLS
+22  stream
+12 / +6  elite / anonymous
+≤15 latency
+≤10 bandwidth
+≤10 recent probe successes
-≤15 recent failures
-50  transparent
```

The score is advisory. Filters such as `--tls-only`, `--require-stream`, and
`--max-latency` are the hard constraints.

---

## Operational Recipes

### Python requests

```python
import requests

proxies = {
    "http": "http://127.0.0.1:8899",
    "https": "http://127.0.0.1:8899",
}

for i in range(5):
    r = requests.get(
        "https://api.ipify.org?format=json",
        proxies=proxies,
        timeout=40,
    )
    print(i, r.status_code, r.text)
```

### yt-dlp

```bash
# Sticky local SOCKS5 listener (remote DNS)
./run.sh serve --policy sticky --sticky-ttl 900 \
  --port 8899 --socks-port 8900 --tls-only --require-stream

yt-dlp --proxy socks5h://127.0.0.1:8900 \
  -f 'bestvideo+bestaudio/best' \
  -o '%(title)s.%(ext)s' 'URL'
```

### ffmpeg / HLS

```bash
export http_proxy=http://127.0.0.1:8899
export https_proxy=http://127.0.0.1:8899

ffmpeg -i 'https://example.com/stream.m3u8' \
  -c copy -bsf:a aac_adtstoasc out.mp4
```

Use sticky mode for HLS/DASH. Per-request rotation will break segment sessions.

### proxychains

```ini
[ProxyList]
socks5 127.0.0.1 8900
```

```bash
proxychains4 -q curl -sS https://api.ipify.org
```

### systemd

Adjust paths and deployment user for the target host.

```ini
# /etc/systemd/system/proxhunt-update.service
[Unit]
Description=proxhunt pool updater
After=network-online.target

[Service]
User=proxhunt
WorkingDirectory=/opt/proxhunt
ExecStart=/opt/proxhunt/run.sh daemon --interval 600
Restart=always

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/proxhunt-serve.service
[Unit]
Description=proxhunt rotator
After=network-online.target proxhunt-update.service

[Service]
User=proxhunt
WorkingDirectory=/opt/proxhunt
ExecStart=/opt/proxhunt/run.sh serve --port 8899 --socks-port 8900 \
  --tls-only --require-stream --retries 12 --hedge 4
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## Field Benchmarks

Measured on a Linux host with Python 3.13, 700 concurrent validators, and a fresh
database. Public proxies are volatile; treat these numbers as order of magnitude,
not capacity planning.

| Metric | Result |
|---|---|
| Sources scraped | 28 |
| Unique candidates | 16,976 |
| Candidates validated in one run | 12,386 |
| Validation runtime | 147 s |
| Live proxies | 382 |
| Stream-capable | 101 |
| HTTPS/CONNECT capable | 126 |
| TLS verified | 41 |
| Recheck after ~15 min | 201 live / 76 stream / 84 HTTPS / 37 TLS |

Functional checks:

| Test | Result |
|---|---|
| Rotating HTTPS requests through a fresh TLS-only stream pool | 8/8 HTTP 200, 6 distinct exit IPs |
| Sticky session, three sequential requests | Same exit IP |
| SOCKS5 listener, HTTPS target | HTTP 200, IPv4 and IPv6 exits observed |
| 200 KiB transfer via sticky HTTP proxy | 200,000 bytes, HTTP 200 |
| 200 KiB transfer via local SOCKS5 | 200,000 bytes, HTTP 200 |
| Upstream dies after CONNECT | ClientHello replayed through next upstream; request completes |
| `list --live` | 10 candidates revalidated; 3 survivors printed |

Free proxies are slow. The 200 KiB transfers above completed at roughly
19 KiB/s. Use `speed_kbps` ranking and sticky sessions for media workloads.

---

## Troubleshooting

| Symptom | Cause / resolution |
|---|---|
| `no proxies matched` | Run `update`; relax filters (`--alive-minutes 0`, `--min-score 0`); inspect `stats` |
| `502 proxhunt: no usable upstream` | Pool is stale or exhausted. Run `check`/`update`, raise `--retries`, lower `--min-score`, keep `--hedge 3` |
| `curl: (60) SSL certificate ...` | Upstream is MITM-ing TLS. Use `--tls-only`, or explicitly accept the risk for non-sensitive traffic |
| Works briefly, then fails | Normal public-proxy churn. Run `daemon`, prefer `--mode stream`, shorten `--alive-minutes` |
| SOCKS connection refused | SOCKS listener disabled (`--socks-port 0`) or port already in use |
| High latency | Lower `--retries`; use fresher proxies; avoid `--require-stream` when not needed |
| `database is locked` | Run only one writer at a time; WAL and busy timeout are enabled |
| Too many open files | `run.sh` raises `ulimit -n`; raise it further or lower `--concurrency` |
| Windows host cannot reach the listener | WSL2 normally forwards loopback. For lab-only bridging, bind `0.0.0.0` with `--allow-public`; this creates an open proxy |

Runtime statistics and pool state are available at
`http://proxhunt.local/__stats` through the local proxy.

---

## Security and Legal

- Public proxies are untrusted. They can observe destination hostnames and SNI,
  modify unencrypted traffic, or terminate TLS with a forged certificate.
- Keep certificate verification enabled in clients. Use `--tls-only` to exclude
  MITM upstreams. Only disable verification deliberately and never for
  authenticated or sensitive sessions.
- Free proxies are not an anonymity system. They do not provide privacy, and many
  exit addresses are already blocklisted.
- Use this software only against systems you own or are explicitly authorized to
  test. Respect applicable law, contracts, and terms of service.
- No warranty. No service-level guarantee. Public proxy availability is outside
  this project's control.

---

## Project Layout

```text
proxhunt/
├── proxhunt/
│   ├── cli.py          # command-line interface
│   ├── config.py       # defaults, judges, paths
│   ├── sources.py      # source registry and parsers
│   ├── checker.py      # layered async validator
│   ├── store.py        # SQLite pool, scoring, freshness
│   ├── updater.py      # update and recheck pipelines
│   ├── rotator.py      # HTTP/SOCKS5 rotator, hedging, replay
│   └── util.py         # proxy/IP parsing helpers
├── data/               # SQLite database and logs (gitignored)
├── tests/              # unit tests
├── .github/workflows/  # CI
├── install.sh
├── run.sh
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

---

## License

MIT. See [LICENSE](LICENSE).
