"""Defaults and constants for proxhunt."""
from __future__ import annotations

import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("PROXHUNT_DATA_DIR", os.path.join(PROJECT_ROOT, "data"))
DB_PATH = os.environ.get("PROXHUNT_DB", os.path.join(DATA_DIR, "proxhunt.sqlite3"))
LOG_DIR = os.path.join(DATA_DIR, "logs")

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Judge endpoints. checkip.amazonaws.com is tiny and fast; the others are
# fallbacks. We only trust responses that contain a valid public IPv4.
IP_JUDGES_HTTP = [
    "http://checkip.amazonaws.com",
    "http://api.ipify.org?format=json",
    "http://ifconfig.me/ip",
    "http://httpbin.org/ip",
]
IP_JUDGES_HTTPS = [
    "https://checkip.amazonaws.com",
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://httpbin.org/ip",
]

# Header-echo judges for anonymity classification (HTTP only).
ANON_JUDGES = [
    "http://azenv.net/",
    "http://httpbin.org/get",
]

SPEED_JUDGE = "https://speed.cloudflare.com/__down?bytes=131072"
SPEED_BYTES = 131072

DEFAULT_CONCURRENCY = 600
DEFAULT_TCP_TIMEOUT = 3.0
DEFAULT_TIMEOUT = 9.0
DEFAULT_STREAM_CHECKS = 3
DEFAULT_STREAM_INTERVAL = 1.2
DEFAULT_MAX_NEW = 15000
DEFAULT_REFRESH_ALIVE_MINUTES = 1440
DEFAULT_ALIVE_MINUTES = 120
DEFAULT_MIN_SCORE = 0.0
DEFAULT_SPEED_CHECK = 200
DEFAULT_PER_SOURCE_CAP = 2000

# Rotator defaults
DEFAULT_PORT = 8899
DEFAULT_SOCKS_PORT = 8900
DEFAULT_STICKY_TTL = 300
DEFAULT_RETRIES = 4
POOL_REFRESH_SECONDS = 10
COOLDOWN_SECONDS = 45
