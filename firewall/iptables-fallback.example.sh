#!/usr/bin/env bash
set -euo pipefail

# Fallback example for older hosts without nftables. The installer prefers nft.
WG_SUBNET="${WG_SUBNET:-10.100.0.0/24}"
VM_SUBNET="${VM_SUBNET:-172.16.50.0/24}"
WAN_IFACE="${WAN_IFACE:-eth0}"

iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$WAN_IFACE" -j MASQUERADE
iptables -t nat -A POSTROUTING -s "$VM_SUBNET" -o wg0 -j MASQUERADE
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT
