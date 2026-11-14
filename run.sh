#!/usr/bin/env bash
# proxhunt launcher: uses the dedicated venv, raises fd limit, adds project to path.
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${PROXHUNT_VENV:-$HOME/.venvs/proxhunt}"
if [ ! -x "$VENV/bin/python" ]; then
  echo "venv not found at $VENV — run ./install.sh first" >&2
  exit 1
fi
ulimit -n 65535 2>/dev/null || true
export PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}"
exec "$VENV/bin/python" -m proxhunt "$@"
