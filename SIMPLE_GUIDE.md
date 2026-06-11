# Phoenix Tunnel Simple Guide

Phoenix Tunnel makes one Linux or Proxmox server act as a WireGuard tunnel
gateway.

In plain English:

1. You run the installer.
2. It asks for your server IP, private VPN network, and ports to forward.
3. It creates WireGuard keys and config files.
4. It turns on Linux routing.
5. It adds firewall rules so traffic reaches the right VM or service.
6. It creates a client config you can import into the WireGuard app.

## Which Mode Should I Pick?

Pick `linux` if Phoenix Tunnel is running on a normal VPS or dedicated server.

Pick `proxmox` if Phoenix Tunnel is running directly on a Proxmox VE host and
you want VMs behind it.

## Simple Proxmox Example

Use these values if you are unsure:

```text
Server public IP or DNS name: your-server-ip-or-hostname
WireGuard private IPv4 network: 10.100.0.0/24
Environment: proxmox
WireGuard listen port: 51820
Internet network interface: usually eth0 or eno1
Bridge: usually vmbr0
Private VM IPv4 network: 172.16.50.0/24
```

Then configure a VM like this:

```text
VM IP:   172.16.50.10/24
Gateway: 172.16.50.1
DNS:     1.1.1.1
```

## Port Forward Example

To forward public UDP port `51820` to a VM:

```text
Public port:          51820
Internal VM/service:  172.16.50.10
Internal port:        51820
Protocol:             udp
```

To forward every TCP and UDP port:

```text
Public port:          1-65535
Internal VM/service:  172.16.50.1
Internal port:        1-65535
Protocol:             both
```

## Useful Commands

```bash
sudo ./install.sh
sudo /opt/phoenix-tunnel/setup.py status
sudo /opt/phoenix-tunnel/setup.py health
sudo /opt/phoenix-tunnel/setup.py export-client client-1 --qr
```

If something goes wrong:

```bash
sudo /opt/phoenix-tunnel/setup.py rollback
```
