#!/usr/bin/env bash
set -euo pipefail

PHX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PHX_REPO_TARBALL="${PHX_REPO_TARBALL:-https://github.com/opsahil89/PHXTUNNEL/archive/refs/heads/master.tar.gz}"

if [[ ! -f "$PHX_ROOT/setup.py" ]]; then
  if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    echo "One-line installation requires curl and tar. Install them, or clone the repository and run sudo ./install.sh." >&2
    exit 1
  fi
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  echo "Downloading Phoenix Tunnel installer bundle..."
  curl -fsSL "$PHX_REPO_TARBALL" | tar -xz -C "$TMP_DIR" --strip-components=1
  PHX_ROOT="$TMP_DIR"
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Phoenix Tunnel requires python3. Install python3 and re-run this installer." >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Phoenix Tunnel must be installed as root because it writes WireGuard, firewall, and systemd config." >&2
  echo "Try: sudo ./install.sh"
  exit 1
fi

if [[ -r /dev/tty ]]; then
  exec "$PYTHON_BIN" "$PHX_ROOT/setup.py" "$@" </dev/tty
fi

echo "Phoenix Tunnel needs an interactive terminal for setup." >&2
echo "Clone the repository and run: sudo ./install.sh $*" >&2
exit 1
