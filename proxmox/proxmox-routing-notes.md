# VM Routing Model

Phoenix Tunnel keeps Proxmox VM routing simple:

- The host receives the first usable address in the VM subnet, for example
  `172.16.50.1/24`, on the selected bridge.
- VMs use the host bridge address as their default gateway.
- nftables masquerades VM traffic toward `wg0` when it exits through the
  WireGuard tunnel.
- DNAT mappings forward public ports to VM addresses such as
  `172.16.50.10`.

This avoids rewriting `/etc/network/interfaces` directly. The generated
`phoenix-tunnel-proxmox-gateway.service` restores the bridge gateway address on
boot.
