# UltraVM Phoenix Tunnel

Phoenix Tunnel, branded as **UltraVM phx tunnel**, is a self-hosted WireGuard
proxy deployment platform for native Linux and Proxmox VE nodes. It provisions
WireGuard, generates client configs, builds persistent NAT/DNAT firewall rules,
and can turn a Proxmox host into a VM gateway/router.

## One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/ultravm/phoenix-tunnel/main/install.sh | sudo bash
```

For local installs:

```bash
sudo ./install.sh
```

## What It Builds

- Interactive colored CLI wizard
- Automatic WireGuard key generation and `wg0.conf`
- IPv4 and optional IPv6 addressing
- nftables DNAT and masquerading rules
- Proxmox bridge gateway service for VM subnets
- Client config export and optional QR generation
- Health checks, status dashboard, rollback backups, and auto-update helper
- Systemd services that survive reboot

## Repository Layout

```text
phoenix-tunnel/
+-- install.sh
+-- setup.py
+-- configs/
+-- templates/
+-- scripts/
+-- proxmox/
+-- firewall/
+-- wireguard/
+-- docker/
+-- README.md
```

## Requirements

Install these on Debian, Ubuntu, or Proxmox VE:

```bash
sudo apt update
sudo apt install -y python3 wireguard-tools nftables qrencode iproute2
```

## Wizard Inputs

The installer asks for:

- Public IP address or DNS name of the WireGuard proxy/server
- Internal WireGuard subnet, for example `10.100.0.0/24`
- Port forwarding mappings with single ports or ranges, TCP, UDP, or both
- Environment type: `linux` or `proxmox`
- Optional DNS servers, IPv6 subnets, MTU, and kill-switch policy

Example mapping:

```text
51820 UDP -> 172.16.50.10:51820
```

## Proxmox Setup Guide

Run the installer on the Proxmox VE host and choose `proxmox`.

Phoenix Tunnel will:

- Detect VM bridges such as `vmbr0`
- Ask which bridge should serve VM traffic
- Generate a VM subnet such as `172.16.50.0/24`
- Add the first usable address, such as `172.16.50.1/24`, to the bridge through
  `phoenix-tunnel-proxmox-gateway.service`
- Enable IP forwarding
- Configure persistent nftables NAT and DNAT
- Masquerade VM traffic through `wg0`

VM network example:

```text
VM IP:     172.16.50.10/24
Gateway:   172.16.50.1
DNS:       1.1.1.1
Bridge:    vmbr0
```

See `proxmox/vm-cloud-init.example.yaml` for a cloud-init example.

## Common Commands

```bash
sudo ./setup.py install
sudo ./setup.py wizard
sudo ./setup.py apply
sudo ./setup.py status
sudo ./setup.py health
sudo ./setup.py export-client client-1 --qr
sudo ./setup.py rollback
```

After installation, the runtime copy lives at:

```text
/opt/phoenix-tunnel
```

Main generated files:

```text
/etc/phoenix-tunnel/config.json
/etc/phoenix-tunnel/phoenix.nft
/etc/wireguard/wg0.conf
/var/lib/phoenix-tunnel/clients/client-1.conf
```

## Example Topologies

### Native Linux Proxy

```text
Internet -> Linux host public IP -> wg0 -> private services
```

Use this when Phoenix Tunnel runs on a normal VPS or bare-metal Linux server.

### Proxmox VM Gateway

```text
Internet
  |
Proxmox host public IP
  |
wg0
  |
vmbr0: 172.16.50.1/24
  |
VMs: 172.16.50.10, 172.16.50.11, ...
```

Use this when multiple VMs need private routed access and selected public port
forwards.

## Security Recommendations

- Restrict SSH to trusted source IPs before exposing services.
- Keep WireGuard private keys readable only by root.
- Use unique peers per device and remove stale peers quickly.
- Prefer nftables over legacy iptables on new deployments.
- Keep Proxmox and kernel packages updated.
- Use `PersistentKeepalive = 25` for roaming clients behind NAT.
- Forward only the ports you need.
- Store `/etc/phoenix-tunnel/config.json` backups securely because it may
  contain client private keys.

## Troubleshooting

Check generated state:

```bash
sudo /opt/phoenix-tunnel/setup.py status
sudo /opt/phoenix-tunnel/setup.py health
sudo wg show
sudo nft list ruleset
```

If clients connect but cannot reach the internet:

- Confirm `net.ipv4.ip_forward=1`.
- Confirm the outbound interface selected by the wizard is correct.
- Confirm your cloud provider allows UDP on the WireGuard listen port.
- For Proxmox VMs, confirm the VM default gateway is the bridge address.

If port forwards fail:

- Confirm the destination VM IP is reachable from the Proxmox host.
- Confirm the mapping protocol matches the application.
- Check that another firewall is not dropping forwarded traffic.

If a generated config causes problems:

```bash
sudo /opt/phoenix-tunnel/setup.py rollback
sudo systemctl restart wg-quick@wg0 phoenix-tunnel-firewall.service
```

## Auto-Update

For Git-based installs:

```bash
sudo PHX_ROOT=/opt/phoenix-tunnel /opt/phoenix-tunnel/scripts/update.sh
```

The update helper pulls the latest code and reapplies the existing config.

## Docker

Docker support is optional and intended for toolbox-style operations. WireGuard
and nftables still require host networking and `NET_ADMIN`.

```bash
cd docker
docker compose up
```

## CI

The GitHub Actions workflow compiles `setup.py`, syntax-checks shell scripts,
and validates example JSON.
