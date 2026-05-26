#!/usr/bin/env bash
set -euo pipefail
PHX_ROOT="${PHX_ROOT:-/opt/phoenix-tunnel}"
cd "$PHX_ROOT"
git pull --ff-only
./setup.py apply
