#!/usr/bin/env bash
# One-time setup for proxhunt (Python 3.10+).
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${PROXHUNT_VENV:-$HOME/.venvs/proxhunt}"
PY="${PYTHON:-python3}"
if [ ! -d "$VENV" ]; then
  echo "[*] creating venv at $VENV"
  "$PY" -m venv "$VENV"
fi
"$VENV/bin/pip" install --upgrade pip >/dev/null
"$VENV/bin/pip" install -e "$DIR"
chmod +x "$DIR/run.sh" || true
echo "[+] installed. try: $DIR/run.sh sources"
echo "    then: $DIR/run.sh update --max-new 15000"
