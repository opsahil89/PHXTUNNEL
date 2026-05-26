#!/usr/bin/env bash
set -euo pipefail

PHX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Phoenix Tunnel requires python3. Install python3 and re-run this installer." >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Phoenix Tunnel must be installed as root because it writes WireGuard, firewall, and systemd config." >&2
  echo "Try: sudo ./install.sh"
  exit 1
fi

exec "$PYTHON_BIN" "$PHX_ROOT/setup.py" "$@"
