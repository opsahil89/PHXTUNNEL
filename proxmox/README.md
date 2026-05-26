# Proxmox VE Notes

Phoenix Tunnel can run directly on a Proxmox VE node and use the host as the
WireGuard gateway for VMs.

Recommended flow:

1. Install WireGuard and nftables on the Proxmox host.
2. Run `sudo ./install.sh`.
3. Choose `proxmox` when the wizard asks for the environment.
4. Select the VM bridge, usually `vmbr0`.
5. Assign VM addresses from the generated VM subnet, for example
   `172.16.50.10/24`, with the Proxmox host as the gateway.

The installer enables forwarding, writes nftables NAT/DNAT policy, and enables
systemd services so the rules return after reboot.
