#!/usr/bin/env bash
set -euo pipefail
apt-get update
apt-get install -y python3 wireguard-tools nftables qrencode iproute2
