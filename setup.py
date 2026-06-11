#!/usr/bin/env python3
"""Phoenix Tunnel installer and operations CLI.

UltraVM Phoenix Tunnel ("phx tunnel") is a self-hosted WireGuard proxy and
NAT orchestration platform for Linux and Proxmox VE nodes.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from string import Template
from typing import Any

APP_NAME = "Phoenix Tunnel"
BRAND = "UltraVM"
TUNNEL_NAME = "phx tunnel"
CONFIG_DIR = Path("/etc/phoenix-tunnel")
STATE_DIR = Path("/var/lib/phoenix-tunnel")
LOG_DIR = Path("/var/log/phoenix-tunnel")
SYSTEMD_DIR = Path("/etc/systemd/system")
WG_DIR = Path("/etc/wireguard")
REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = CONFIG_DIR / "config.json"


class UI:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def enabled(cls) -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    @classmethod
    def color(cls, value: str, code: str) -> str:
        return f"{code}{value}{cls.RESET}" if cls.enabled() else value

    @classmethod
    def info(cls, value: str) -> None:
        print(cls.color(f"==> {value}", cls.CYAN))

    @classmethod
    def ok(cls, value: str) -> None:
        print(cls.color(f"OK  {value}", cls.GREEN))

    @classmethod
    def warn(cls, value: str) -> None:
        print(cls.color(f"!!  {value}", cls.YELLOW))

    @classmethod
    def error(cls, value: str) -> None:
        print(cls.color(f"ERR {value}", cls.RED), file=sys.stderr)


class RunError(RuntimeError):
    pass


class Runner:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.log_file = LOG_DIR / "installer.log"

    def run(self, args: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
        if self.dry_run:
            UI.info("[dry-run] " + " ".join(args))
            return subprocess.CompletedProcess(args, 0, "", "")
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with self.log_file.open("a", encoding="utf-8") as log:
            log.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} $ {' '.join(args)}\n")
        proc = subprocess.run(args, text=True, capture_output=capture)
        if check and proc.returncode != 0:
            raise RunError(f"Command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr}")
        return proc


@dataclasses.dataclass
class PortMapping:
    external_port: str
    destination_ip: str
    destination_port: str
    protocol: str


@dataclasses.dataclass
class ClientPeer:
    name: str
    address_v4: str
    address_v6: str | None
    public_key: str
    private_key: str | None = None
    preshared_key: str | None = None
    dns: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class PhoenixConfig:
    public_ip: str
    wg_subnet_v4: str
    wg_subnet_v6: str | None
    listen_port: int
    environment: str
    bridge: str | None
    vm_subnet_v4: str | None
    vm_subnet_v6: str | None
    outbound_interface: str
    dns: list[str]
    kill_switch: bool
    mtu: int
    server_private_key: str
    server_public_key: str
    peers: list[ClientPeer]
    port_mappings: list[PortMapping]
    firewall_backend: str = "nftables"
    tunnel_name: str = TUNNEL_NAME
    brand: str = BRAND

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2)

    @classmethod
    def from_file(cls, path: Path = DEFAULT_CONFIG) -> "PhoenixConfig":
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["peers"] = [ClientPeer(**p) for p in raw.get("peers", [])]
        raw["port_mappings"] = [PortMapping(**m) for m in raw.get("port_mappings", [])]
        return cls(**raw)


@dataclasses.dataclass
class SplitProxyConfig:
    role: str
    proxy_endpoint: str
    wg_subnet_v4: str
    listen_port: int
    proxy_tunnel_ip: str
    backend_tunnel_ip: str
    private_key: str
    public_key: str
    peer_public_key: str
    peer_private_key: str | None
    preshared_key: str | None
    mtu: int
    dns: list[str]
    outbound_interface: str
    port_mappings: list[PortMapping]
    environment: str = "linux"
    bridge: str | None = None
    vm_subnet_v4: str | None = None
    kill_switch: bool = True
    tunnel_name: str = TUNNEL_NAME
    brand: str = BRAND

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2)


def prompt(default: str | None, label: str, validator=None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(UI.color(f"{label}{suffix}: ", UI.BOLD)).strip()
        if not value and default is not None:
            value = default
        try:
            if validator:
                validator(value)
            return value
        except Exception as exc:
            UI.warn(str(exc))


def optional_network(default: str, label: str) -> str | None:
    while True:
        value = input(UI.color(f"{label} [{default}, blank disables]: ", UI.BOLD)).strip()
        if not value:
            return None
        if value.lower() in {"default", "d"}:
            value = default
        try:
            validate_network(value)
            return value
        except Exception as exc:
            UI.warn(str(exc))


def yes_no(label: str, default: bool = True) -> bool:
    marker = "Y/n" if default else "y/N"
    while True:
        value = input(UI.color(f"{label} [{marker}]: ", UI.BOLD)).strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        UI.warn("Answer yes or no.")


def validate_ip_or_host(value: str) -> None:
    if not value:
        raise ValueError("Public IP or hostname is required.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if "." not in value:
            raise ValueError("Use an IP address or DNS hostname.")


def validate_network(value: str) -> None:
    ipaddress.ip_network(value, strict=False)


def validate_port(value: str) -> None:
    for part in value.split(","):
        piece = part.strip()
        if "-" in piece:
            start, end = [int(x) for x in piece.split("-", 1)]
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Port ranges must be within 1-65535 and ordered.")
        else:
            port = int(piece)
            if port < 1 or port > 65535:
                raise ValueError("Ports must be within 1-65535.")


def shell_output(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def detect_public_ip() -> str:
    routes = shell_output(["ip", "-4", "route", "get", "1.1.1.1"])
    parts = routes.split()
    if "src" in parts:
        return parts[parts.index("src") + 1]
    return ""


def detect_outbound_interface() -> str:
    routes = shell_output(["ip", "route", "show", "default"])
    parts = routes.split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    return "eth0"


def detect_bridges() -> list[str]:
    sys_class = Path("/sys/class/net")
    bridges: list[str] = []
    if sys_class.exists():
        for item in sys_class.iterdir():
            if (item / "bridge").exists() or item.name.startswith("vmbr"):
                bridges.append(item.name)
    return sorted(set(bridges)) or ["vmbr0"]


def choose_bridge() -> str:
    bridges = detect_bridges()
    print("Detected VM bridges:")
    for idx, bridge in enumerate(bridges, 1):
        print(f"  {idx}. {bridge}")
    while True:
        value = prompt("1", "Bridge to use")
        if value.isdigit() and 1 <= int(value) <= len(bridges):
            return bridges[int(value) - 1]
        if value:
            return value


def wg_keypair(runner: Runner) -> tuple[str, str]:
    if shutil.which("wg"):
        private = runner.run(["wg", "genkey"], capture=True).stdout.strip()
        public = subprocess.run(["wg", "pubkey"], input=private + "\n", text=True, capture_output=True, check=True).stdout.strip()
        return private, public
    private = base64.b64encode(secrets.token_bytes(32)).decode()
    public = base64.b64encode(secrets.token_bytes(32)).decode()
    UI.warn("wg command not found; generated placeholder keys. Install wireguard-tools and run apply on the target host.")
    return private, public


def preshared_key(runner: Runner) -> str:
    if shutil.which("wg"):
        return runner.run(["wg", "genpsk"], capture=True).stdout.strip()
    return base64.b64encode(secrets.token_bytes(32)).decode()


def first_host(network: str, offset: int) -> str:
    net = ipaddress.ip_network(network, strict=False)
    return str(list(net.hosts())[offset])


def parse_port_mappings() -> list[PortMapping]:
    mappings: list[PortMapping] = []
    UI.info("Add public ports that should point to an internal VM or service. Press Enter when done.")
    while True:
        external = input(UI.color("Public port or range (example 443 or 8000-8010): ", UI.BOLD)).strip()
        if not external:
            break
        try:
            validate_port(external)
        except Exception as exc:
            UI.warn(str(exc))
            continue
        dest_ip = prompt(None, "Internal VM/service IP", lambda v: ipaddress.ip_address(v))
        dest_port = prompt(external, "Internal port or range", validate_port)
        protocol = prompt("both", "Protocol (tcp/udp/both)", lambda v: v.lower() in {"tcp", "udp", "both"} or (_ for _ in ()).throw(ValueError("Use tcp, udp, or both."))).lower()
        mappings.append(PortMapping(external, dest_ip, dest_port, protocol))
        if not yes_no("Add another port mapping?", False):
            break
    return mappings


def parse_proxy_port_mappings(default_dest_ip: str) -> list[PortMapping]:
    mappings: list[PortMapping] = []
    UI.info("Add public proxy ports. They will forward through WireGuard to the backend.")
    while True:
        external = input(UI.color("Public proxy port or range (example 443 or 8000-8010): ", UI.BOLD)).strip()
        if not external:
            break
        try:
            validate_port(external)
        except Exception as exc:
            UI.warn(str(exc))
            continue
        dest_ip = prompt(default_dest_ip, "Backend WireGuard IP", lambda v: ipaddress.ip_address(v))
        dest_port = prompt(external, "Backend port or range", validate_port)
        protocol = prompt("both", "Protocol (tcp/udp/both)", lambda v: v.lower() in {"tcp", "udp", "both"} or (_ for _ in ()).throw(ValueError("Use tcp, udp, or both."))).lower()
        mappings.append(PortMapping(external, dest_ip, dest_port, protocol))
        if not yes_no("Add another proxy port?", False):
            break
    return mappings


def create_config(args: argparse.Namespace) -> PhoenixConfig:
    runner = Runner(dry_run=args.dry_run)
    banner()
    public_ip = prompt(detect_public_ip(), "Server public IP or DNS name", validate_ip_or_host)
    wg_subnet_v4 = prompt("10.100.0.0/24", "WireGuard private IPv4 network", validate_network)
    wg_subnet_v6 = optional_network("fd42:100::/64", "WireGuard private IPv6 network")
    environment = prompt("linux", "Environment (linux/proxmox)", lambda v: v.lower() in {"linux", "proxmox"} or (_ for _ in ()).throw(ValueError("Use linux or proxmox."))).lower()
    listen_port = int(prompt("51820", "WireGuard listen port", validate_port))
    outbound = prompt(detect_outbound_interface(), "Internet network interface")
    dns_raw = prompt("1.1.1.1,9.9.9.9", "DNS servers for VPN clients")
    kill_switch = yes_no("Block VM traffic if it cannot use the tunnel?", True)
    mtu = int(prompt("1420", "WireGuard MTU"))
    bridge = None
    vm_subnet_v4 = None
    vm_subnet_v6 = None
    if environment == "proxmox":
        bridge = choose_bridge()
        vm_subnet_v4 = prompt("172.16.50.0/24", "Private VM IPv4 network", validate_network)
        vm_subnet_v6 = optional_network("fd42:50::/64", "Private VM IPv6 network")
    mappings = parse_port_mappings() if yes_no("Configure port forwarding now?", True) else []
    server_private, server_public = wg_keypair(runner)
    peer_private, peer_public = wg_keypair(runner)
    peer = ClientPeer(
        name="client-1",
        address_v4=first_host(wg_subnet_v4, 1),
        address_v6=first_host(wg_subnet_v6, 1) if wg_subnet_v6 else None,
        public_key=peer_public,
        private_key=peer_private,
        preshared_key=preshared_key(runner),
        dns=[x.strip() for x in dns_raw.split(",") if x.strip()],
    )
    return PhoenixConfig(
        public_ip=public_ip,
        wg_subnet_v4=wg_subnet_v4,
        wg_subnet_v6=wg_subnet_v6 or None,
        listen_port=listen_port,
        environment=environment,
        bridge=bridge,
        vm_subnet_v4=vm_subnet_v4,
        vm_subnet_v6=vm_subnet_v6 or None,
        outbound_interface=outbound,
        dns=[x.strip() for x in dns_raw.split(",") if x.strip()],
        kill_switch=kill_switch,
        mtu=mtu,
        server_private_key=server_private,
        server_public_key=server_public,
        peers=[peer],
        port_mappings=mappings,
    )


def banner() -> None:
    print(UI.color(textwrap.dedent(f"""
        {BRAND} {APP_NAME}
        Tunnel name: {TUNNEL_NAME}
        Simple self-hosted WireGuard tunneling for Linux and Proxmox VE.
    """).strip(), UI.BLUE))


def render_template(name: str, values: dict[str, Any]) -> str:
    path = REPO_ROOT / "templates" / name
    return Template(path.read_text(encoding="utf-8")).safe_substitute(values)


def install_runtime_files() -> None:
    target = Path("/opt/phoenix-tunnel")
    target.mkdir(parents=True, exist_ok=True)
    for name in ["setup.py", "install.sh", "README.md", "SIMPLE_GUIDE.md"]:
        shutil.copy2(REPO_ROOT / name, target / name)
    for directory in ["templates", "scripts", "configs", "wireguard", "firewall", "proxmox", "docker"]:
        src = REPO_ROOT / directory
        dst = target / directory
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
    os.chmod(target / "setup.py", 0o755)


def peer_allowed_ips(cfg: PhoenixConfig, peer: ClientPeer) -> str:
    values = [f"{peer.address_v4}/32"]
    if peer.address_v6:
        values.append(f"{peer.address_v6}/128")
    return ", ".join(values)


def server_addresses(cfg: PhoenixConfig) -> str:
    values = [f"{first_host(cfg.wg_subnet_v4, 0)}/{ipaddress.ip_network(cfg.wg_subnet_v4, strict=False).prefixlen}"]
    if cfg.wg_subnet_v6:
        values.append(f"{first_host(cfg.wg_subnet_v6, 0)}/{ipaddress.ip_network(cfg.wg_subnet_v6, strict=False).prefixlen}")
    return ", ".join(values)


def generate_wg0(cfg: PhoenixConfig) -> str:
    peer_blocks = []
    for peer in cfg.peers:
        block = [
            "[Peer]",
            f"# {peer.name}",
            f"PublicKey = {peer.public_key}",
            f"AllowedIPs = {peer_allowed_ips(cfg, peer)}",
        ]
        if peer.preshared_key:
            block.append(f"PresharedKey = {peer.preshared_key}")
        peer_blocks.append("\n".join(block))
    return render_template("wg0.conf.tmpl", {
        "addresses": server_addresses(cfg),
        "listen_port": cfg.listen_port,
        "private_key": cfg.server_private_key,
        "mtu": cfg.mtu,
        "peers": "\n\n".join(peer_blocks),
    })


def client_config(cfg: PhoenixConfig, peer: ClientPeer) -> str:
    addresses = [f"{peer.address_v4}/32"]
    if peer.address_v6:
        addresses.append(f"{peer.address_v6}/128")
    dns = ", ".join(peer.dns or cfg.dns)
    allowed = ["0.0.0.0/0"]
    if cfg.wg_subnet_v6:
        allowed.append("::/0")
    return render_template("client.conf.tmpl", {
        "name": peer.name,
        "addresses": ", ".join(addresses),
        "dns_line": f"DNS = {dns}" if dns else "",
        "private_key": peer.private_key or "<client-private-key>",
        "server_public_key": cfg.server_public_key,
        "preshared_line": f"PresharedKey = {peer.preshared_key}" if peer.preshared_key else "",
        "endpoint": f"{cfg.public_ip}:{cfg.listen_port}",
        "allowed_ips": ", ".join(allowed),
        "mtu": cfg.mtu,
    })


def split_proxy_wg0(cfg: SplitProxyConfig) -> str:
    peer_lines = [
        "[Peer]",
        "# backend server",
        f"PublicKey = {cfg.peer_public_key}",
        f"AllowedIPs = {cfg.backend_tunnel_ip}/32",
    ]
    if cfg.preshared_key:
        peer_lines.append(f"PresharedKey = {cfg.preshared_key}")
    return "\n".join([
        "# UltraVM Phoenix Tunnel split proxy",
        "[Interface]",
        f"Address = {cfg.proxy_tunnel_ip}/{ipaddress.ip_network(cfg.wg_subnet_v4, strict=False).prefixlen}",
        f"ListenPort = {cfg.listen_port}",
        f"PrivateKey = {cfg.private_key}",
        f"MTU = {cfg.mtu}",
        "SaveConfig = false",
        "",
        "\n".join(peer_lines),
        "",
    ])


def split_backend_wg0(cfg: SplitProxyConfig) -> str:
    dns_line = f"DNS = {', '.join(cfg.dns)}" if cfg.dns else ""
    psk_line = f"PresharedKey = {cfg.preshared_key}" if cfg.preshared_key else ""
    return "\n".join([
        "# UltraVM Phoenix Tunnel backend connector",
        "[Interface]",
        f"Address = {cfg.backend_tunnel_ip}/{ipaddress.ip_network(cfg.wg_subnet_v4, strict=False).prefixlen}",
        f"PrivateKey = {cfg.private_key}",
        f"MTU = {cfg.mtu}",
        dns_line,
        "",
        "[Peer]",
        "# public proxy",
        f"PublicKey = {cfg.peer_public_key}",
        psk_line,
        f"Endpoint = {cfg.proxy_endpoint}:{cfg.listen_port}",
        "AllowedIPs = 0.0.0.0/0",
        "PersistentKeepalive = 25",
        "",
    ])


def split_proxy_nft(cfg: SplitProxyConfig) -> str:
    dnat = []
    for mapping in cfg.port_mappings:
        protocols = ["tcp", "udp"] if mapping.protocol == "both" else [mapping.protocol]
        dest = ipaddress.ip_address(mapping.destination_ip)
        family = "ip6" if dest.version == 6 else "ip"
        destination = f"[{mapping.destination_ip}]:{mapping.destination_port}" if dest.version == 6 else f"{mapping.destination_ip}:{mapping.destination_port}"
        for proto in protocols:
            dnat.append(f"    {proto} dport {mapping.external_port} dnat {family} to {destination}")
    return "\n".join([
        "#!/usr/sbin/nft -f",
        "# UltraVM Phoenix Tunnel split proxy firewall.",
        "table inet phoenix_tunnel {",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
        f"    udp dport {cfg.listen_port} accept comment \"phx tunnel WireGuard\"",
        "  }",
        "",
        "  chain forward {",
        "    type filter hook forward priority 0; policy accept;",
        "    iifname \"wg0\" accept",
        "    oifname \"wg0\" accept",
        "  }",
        "",
        "  chain prerouting {",
        "    type nat hook prerouting priority dstnat; policy accept;",
        "\n".join(dnat) if dnat else "    # no proxy DNAT mappings configured",
        "  }",
        "",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
        f"    ip saddr {cfg.wg_subnet_v4} oifname \"{cfg.outbound_interface}\" masquerade",
        "  }",
        "}",
        "",
    ])


def split_backend_nft(cfg: SplitProxyConfig) -> str:
    vm_rules: list[str] = []
    postrouting: list[str] = []
    if cfg.environment == "proxmox" and cfg.vm_subnet_v4:
        postrouting.append(f"    ip saddr {cfg.vm_subnet_v4} oifname \"wg0\" masquerade")
        if cfg.kill_switch:
            vm_rules.append(f"    ip saddr {cfg.vm_subnet_v4} oifname != \"wg0\" drop comment \"phx tunnel backend kill-switch\"")
    return "\n".join([
        "#!/usr/sbin/nft -f",
        "# UltraVM Phoenix Tunnel backend firewall.",
        "table inet phoenix_tunnel {",
        "  chain forward {",
        "    type filter hook forward priority 0; policy accept;",
        "    iifname \"wg0\" accept",
        "    oifname \"wg0\" accept",
        "\n".join(vm_rules) if vm_rules else "    # no VM kill-switch rules configured",
        "  }",
        "",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
        "\n".join(postrouting) if postrouting else "    # no backend masquerade rules configured",
        "  }",
        "}",
        "",
    ])


def nft_rules(cfg: PhoenixConfig) -> str:
    dnat = []
    for mapping in cfg.port_mappings:
        protocols = ["tcp", "udp"] if mapping.protocol == "both" else [mapping.protocol]
        dest = ipaddress.ip_address(mapping.destination_ip)
        family = "ip6" if dest.version == 6 else "ip"
        destination = f"[{mapping.destination_ip}]:{mapping.destination_port}" if dest.version == 6 else f"{mapping.destination_ip}:{mapping.destination_port}"
        for proto in protocols:
            dnat.append(f"    {proto} dport {mapping.external_port} dnat {family} to {destination}")
    vm_masq = ""
    if cfg.environment == "proxmox" and cfg.vm_subnet_v4:
        vm_masq = f"    ip saddr {cfg.vm_subnet_v4} oifname \"wg0\" masquerade"
    kill_switch_rules = "    # kill-switch disabled"
    if cfg.kill_switch and cfg.environment == "proxmox" and cfg.vm_subnet_v4:
        kill_switch_rules = f"    ip saddr {cfg.vm_subnet_v4} oifname != \"wg0\" drop comment \"phx tunnel kill-switch\""
    return render_template("phoenix.nft.tmpl", {
        "outbound_interface": cfg.outbound_interface,
        "wg_subnet_v4": cfg.wg_subnet_v4,
        "vm_subnet_v4": cfg.vm_subnet_v4 or "0.0.0.0/32",
        "listen_port": cfg.listen_port,
        "dnat_rules": "\n".join(dnat) if dnat else "    # no DNAT mappings configured",
        "vm_masquerade": vm_masq,
        "kill_switch_rules": kill_switch_rules,
    })


def write_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = STATE_DIR / "rollback" / f"{path.as_posix().strip('/').replace('/', '__')}.{int(time.time())}.bak"
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)


def generate_files(cfg: PhoenixConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    write_file(DEFAULT_CONFIG, cfg.to_json(), 0o600)
    write_file(CONFIG_DIR / "phoenix.nft", nft_rules(cfg), 0o600)
    write_file(CONFIG_DIR / "sysctl.conf", render_template("99-phoenix-tunnel.conf.tmpl", {}), 0o644)
    write_file(WG_DIR / "wg0.conf", generate_wg0(cfg), 0o600)
    for peer in cfg.peers:
        write_file(STATE_DIR / "clients" / f"{peer.name}.conf", client_config(cfg, peer), 0o600)
    write_file(SYSTEMD_DIR / "phoenix-tunnel-firewall.service", render_template("phoenix-tunnel-firewall.service.tmpl", {}), 0o644)
    write_file(SYSTEMD_DIR / "phoenix-tunnel-health.service", render_template("phoenix-tunnel-health.service.tmpl", {}), 0o644)
    write_file(SYSTEMD_DIR / "phoenix-tunnel-health.timer", render_template("phoenix-tunnel-health.timer.tmpl", {}), 0o644)
    if cfg.environment == "proxmox" and cfg.bridge and cfg.vm_subnet_v4:
        gateway = first_host(cfg.vm_subnet_v4, 0)
        prefix = ipaddress.ip_network(cfg.vm_subnet_v4, strict=False).prefixlen
        write_file(SYSTEMD_DIR / "phoenix-tunnel-proxmox-gateway.service", render_template("phoenix-tunnel-proxmox-gateway.service.tmpl", {
            "bridge": cfg.bridge,
            "gateway_cidr": f"{gateway}/{prefix}",
        }), 0o644)


def apply_system(cfg: PhoenixConfig, runner: Runner) -> None:
    if runner.dry_run:
        UI.info("Dry run selected. Rendering configuration preview only.")
        print(generate_wg0(cfg))
        print(nft_rules(cfg))
        return
    install_runtime_files()
    generate_files(cfg)
    runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    runner.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)
    write_file(Path("/etc/sysctl.d/99-phoenix-tunnel.conf"), render_template("99-phoenix-tunnel.conf.tmpl", {}), 0o644)
    if shutil.which("nft"):
        runner.run(["nft", "-f", str(CONFIG_DIR / "phoenix.nft")])
    else:
        UI.warn("nft command not found. Generated nft rules at /etc/phoenix-tunnel/phoenix.nft.")
    runner.run(["systemctl", "daemon-reload"], check=False)
    runner.run(["systemctl", "enable", "--now", "wg-quick@wg0"], check=False)
    runner.run(["systemctl", "enable", "--now", "phoenix-tunnel-firewall.service"], check=False)
    if cfg.environment == "proxmox":
        runner.run(["systemctl", "enable", "--now", "phoenix-tunnel-proxmox-gateway.service"], check=False)
    runner.run(["systemctl", "enable", "--now", "phoenix-tunnel-health.timer"], check=False)


def create_split_proxy_config(args: argparse.Namespace) -> SplitProxyConfig:
    runner = Runner(dry_run=args.dry_run)
    banner()
    UI.info("Proxy setup: run this on the server that has the public IP.")
    proxy_endpoint = prompt(detect_public_ip(), "Proxy public IP or DNS name", validate_ip_or_host)
    wg_subnet_v4 = prompt("10.200.0.0/24", "Private tunnel network between proxy and backend", validate_network)
    listen_port = int(prompt("51820", "Proxy WireGuard listen port", validate_port))
    outbound = prompt(detect_outbound_interface(), "Proxy internet network interface")
    mtu = int(prompt("1420", "WireGuard MTU"))
    proxy_private, proxy_public = wg_keypair(runner)
    backend_public = input(UI.color("Backend WireGuard public key (press Enter to generate backend config too): ", UI.BOLD)).strip()
    backend_private = None
    if not backend_public:
        backend_private, backend_public = wg_keypair(runner)
        UI.ok("Generated backend keypair. Copy the exported backend config to the backend server.")
    psk = preshared_key(runner)
    proxy_ip = first_host(wg_subnet_v4, 0)
    backend_ip = first_host(wg_subnet_v4, 1)
    mappings = parse_proxy_port_mappings(backend_ip) if yes_no("Forward public ports to the backend?", True) else []
    return SplitProxyConfig(
        role="proxy",
        proxy_endpoint=proxy_endpoint,
        wg_subnet_v4=wg_subnet_v4,
        listen_port=listen_port,
        proxy_tunnel_ip=proxy_ip,
        backend_tunnel_ip=backend_ip,
        private_key=proxy_private,
        public_key=proxy_public,
        peer_public_key=backend_public,
        peer_private_key=backend_private,
        preshared_key=psk,
        mtu=mtu,
        dns=[],
        outbound_interface=outbound,
        port_mappings=mappings,
    )


def create_split_backend_config(args: argparse.Namespace) -> SplitProxyConfig:
    runner = Runner(dry_run=args.dry_run)
    banner()
    UI.info("Backend setup: run this on the private backend server or Proxmox node.")
    proxy_endpoint = prompt(None, "Proxy public IP or DNS name", validate_ip_or_host)
    proxy_public = prompt(None, "Proxy WireGuard public key")
    wg_subnet_v4 = prompt("10.200.0.0/24", "Private tunnel network used by the proxy", validate_network)
    listen_port = int(prompt("51820", "Proxy WireGuard listen port", validate_port))
    proxy_ip = prompt(first_host(wg_subnet_v4, 0), "Proxy tunnel IP", lambda v: ipaddress.ip_address(v))
    backend_ip = prompt(first_host(wg_subnet_v4, 1), "This backend tunnel IP", lambda v: ipaddress.ip_address(v))
    backend_private, backend_public = wg_keypair(runner)
    psk = input(UI.color("Preshared key from proxy setup (blank to skip): ", UI.BOLD)).strip() or None
    dns_raw = prompt("1.1.1.1,9.9.9.9", "DNS servers for backend/VM traffic")
    mtu = int(prompt("1420", "WireGuard MTU"))
    environment = prompt("linux", "Backend type (linux/proxmox)", lambda v: v.lower() in {"linux", "proxmox"} or (_ for _ in ()).throw(ValueError("Use linux or proxmox."))).lower()
    bridge = None
    vm_subnet_v4 = None
    kill_switch = True
    if environment == "proxmox":
        bridge = choose_bridge()
        vm_subnet_v4 = prompt("172.16.50.0/24", "Private VM IPv4 network", validate_network)
        kill_switch = yes_no("Block VM traffic if it cannot use the proxy tunnel?", True)
    UI.ok(f"Backend public key: {backend_public}")
    UI.info("Add this backend public key to the proxy setup when asked.")
    return SplitProxyConfig(
        role="backend",
        proxy_endpoint=proxy_endpoint,
        wg_subnet_v4=wg_subnet_v4,
        listen_port=listen_port,
        proxy_tunnel_ip=proxy_ip,
        backend_tunnel_ip=backend_ip,
        private_key=backend_private,
        public_key=backend_public,
        peer_public_key=proxy_public,
        peer_private_key=None,
        preshared_key=psk,
        mtu=mtu,
        dns=[x.strip() for x in dns_raw.split(",") if x.strip()],
        outbound_interface=detect_outbound_interface(),
        port_mappings=[],
        environment=environment,
        bridge=bridge,
        vm_subnet_v4=vm_subnet_v4,
        kill_switch=kill_switch,
    )


def write_split_proxy_files(cfg: SplitProxyConfig) -> None:
    write_file(CONFIG_DIR / "proxy.json", cfg.to_json(), 0o600)
    write_file(WG_DIR / "wg0.conf", split_proxy_wg0(cfg), 0o600)
    write_file(CONFIG_DIR / "phoenix.nft", split_proxy_nft(cfg), 0o600)
    write_file(SYSTEMD_DIR / "phoenix-tunnel-firewall.service", render_template("phoenix-tunnel-firewall.service.tmpl", {}), 0o644)
    if cfg.peer_private_key:
        backend_cfg = dataclasses.replace(
            cfg,
            role="backend",
            private_key=cfg.peer_private_key,
            public_key=cfg.peer_public_key,
            peer_public_key=cfg.public_key,
            peer_private_key=None,
            port_mappings=[],
        )
        write_file(STATE_DIR / "backend" / "backend-wg0.conf", split_backend_wg0(backend_cfg), 0o600)


def write_split_backend_files(cfg: SplitProxyConfig) -> None:
    write_file(CONFIG_DIR / "backend.json", cfg.to_json(), 0o600)
    write_file(WG_DIR / "wg0.conf", split_backend_wg0(cfg), 0o600)
    write_file(CONFIG_DIR / "phoenix.nft", split_backend_nft(cfg), 0o600)
    write_file(SYSTEMD_DIR / "phoenix-tunnel-firewall.service", render_template("phoenix-tunnel-firewall.service.tmpl", {}), 0o644)
    if cfg.environment == "proxmox" and cfg.bridge and cfg.vm_subnet_v4:
        gateway = first_host(cfg.vm_subnet_v4, 0)
        prefix = ipaddress.ip_network(cfg.vm_subnet_v4, strict=False).prefixlen
        write_file(SYSTEMD_DIR / "phoenix-tunnel-proxmox-gateway.service", render_template("phoenix-tunnel-proxmox-gateway.service.tmpl", {
            "bridge": cfg.bridge,
            "gateway_cidr": f"{gateway}/{prefix}",
        }), 0o644)


def apply_split_proxy(cfg: SplitProxyConfig, runner: Runner) -> None:
    if runner.dry_run:
        print(split_proxy_wg0(cfg))
        print(split_proxy_nft(cfg))
        return
    install_runtime_files()
    write_split_proxy_files(cfg)
    runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    write_file(Path("/etc/sysctl.d/99-phoenix-tunnel.conf"), render_template("99-phoenix-tunnel.conf.tmpl", {}), 0o644)
    if shutil.which("nft"):
        runner.run(["nft", "-f", str(CONFIG_DIR / "phoenix.nft")])
    runner.run(["systemctl", "daemon-reload"], check=False)
    runner.run(["systemctl", "enable", "--now", "wg-quick@wg0"], check=False)
    runner.run(["systemctl", "enable", "--now", "phoenix-tunnel-firewall.service"], check=False)
    if cfg.peer_private_key:
        UI.ok("Backend WireGuard config exported to /var/lib/phoenix-tunnel/backend/backend-wg0.conf")


def apply_split_backend(cfg: SplitProxyConfig, runner: Runner) -> None:
    if runner.dry_run:
        print(split_backend_wg0(cfg))
        print(split_backend_nft(cfg))
        return
    install_runtime_files()
    write_split_backend_files(cfg)
    runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    write_file(Path("/etc/sysctl.d/99-phoenix-tunnel.conf"), render_template("99-phoenix-tunnel.conf.tmpl", {}), 0o644)
    if shutil.which("nft"):
        runner.run(["nft", "-f", str(CONFIG_DIR / "phoenix.nft")])
    runner.run(["systemctl", "daemon-reload"], check=False)
    runner.run(["systemctl", "enable", "--now", "wg-quick@wg0"], check=False)
    runner.run(["systemctl", "enable", "--now", "phoenix-tunnel-firewall.service"], check=False)
    if cfg.environment == "proxmox":
        runner.run(["systemctl", "enable", "--now", "phoenix-tunnel-proxmox-gateway.service"], check=False)


def health(cfg: PhoenixConfig) -> int:
    checks = {
        "config": DEFAULT_CONFIG.exists(),
        "wireguard_config": (WG_DIR / "wg0.conf").exists(),
        "ip_forward": Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1" if Path("/proc/sys/net/ipv4/ip_forward").exists() else False,
        "wg_command": shutil.which("wg") is not None,
        "nft_command": shutil.which("nft") is not None,
    }
    status = 0
    for name, ok in checks.items():
        print(f"{name:20} {'OK' if ok else 'FAIL'}")
        if not ok:
            status = 1
    wg = shell_output(["wg", "show"]) if shutil.which("wg") else ""
    if wg:
        print("\nWireGuard:")
        print(wg)
    return status


def status_dashboard(cfg: PhoenixConfig) -> None:
    banner()
    print(f"Public endpoint: {cfg.public_ip}:{cfg.listen_port}")
    print(f"Environment:     {cfg.environment}")
    print(f"WireGuard CIDR:  {cfg.wg_subnet_v4}" + (f", {cfg.wg_subnet_v6}" if cfg.wg_subnet_v6 else ""))
    if cfg.environment == "proxmox":
        print(f"VM bridge:       {cfg.bridge}")
        print(f"VM subnet:       {cfg.vm_subnet_v4}" + (f", {cfg.vm_subnet_v6}" if cfg.vm_subnet_v6 else ""))
    print(f"Outbound iface:  {cfg.outbound_interface}")
    print(f"Kill switch:     {'enabled' if cfg.kill_switch else 'disabled'}")
    print("\nPort mappings:")
    if not cfg.port_mappings:
        print("  none")
    for mapping in cfg.port_mappings:
        print(f"  {mapping.external_port}/{mapping.protocol} -> {mapping.destination_ip}:{mapping.destination_port}")
    print("\nClients:")
    for peer in cfg.peers:
        print(f"  {peer.name}: {peer.address_v4}" + (f", {peer.address_v6}" if peer.address_v6 else ""))


def export_qr(peer_path: Path) -> None:
    if shutil.which("qrencode"):
        png = peer_path.with_suffix(".png")
        subprocess.run(["qrencode", "-o", str(png), "-r", str(peer_path)], check=True)
        UI.ok(f"QR code written to {png}")
    else:
        UI.warn("qrencode is not installed. Install qrencode to generate PNG QR codes.")


def rollback() -> None:
    rollback_dir = STATE_DIR / "rollback"
    if not rollback_dir.exists():
        UI.warn("No rollback backups found.")
        return
    backups = sorted(rollback_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    for backup in backups:
        target = Path("/") / backup.name.rsplit(".", 1)[0].replace("__", "/")
        UI.info(f"Restoring {target} from {backup}")
        shutil.copy2(backup, target)
    UI.ok("Rollback files restored. Reload services manually if needed.")


def install_dependencies_hint() -> None:
    UI.info("Install recommended packages if missing:")
    print("  Debian/Ubuntu/Proxmox: apt install wireguard-tools nftables qrencode python3")
    print("  RHEL/Fedora:           dnf install wireguard-tools nftables qrencode python3")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=f"{BRAND} {APP_NAME} ({TUNNEL_NAME})")
    parser.add_argument("--dry-run", action="store_true", help="Render and validate without applying commands")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("install", help="Run interactive wizard and apply configuration")
    sub.add_parser("wizard", help="Run interactive wizard and write generated files")
    sub.add_parser("setup-proxy", help="Set up the public-IP proxy server for a split deployment")
    sub.add_parser("setup-backend", help="Set up the private backend or Proxmox node for a split deployment")
    sub.add_parser("apply", help="Apply existing /etc/phoenix-tunnel/config.json")
    sub.add_parser("status", help="Show dashboard")
    sub.add_parser("health", help="Run health checks")
    sub.add_parser("rollback", help="Restore backed-up config files")
    sub.add_parser("deps", help="Show dependency installation hints")
    export = sub.add_parser("export-client", help="Export client config and optional QR")
    export.add_argument("name", nargs="?", default="client-1")
    export.add_argument("--qr", action="store_true")
    args = parser.parse_args(argv)
    command = args.command or "install"
    runner = Runner(dry_run=args.dry_run)
    if command in {"install", "wizard"}:
        cfg = create_config(args)
        if command == "install":
            apply_system(cfg, runner)
        else:
            generate_files(cfg)
        UI.ok(f"{APP_NAME} generated successfully.")
        return 0
    if command == "setup-proxy":
        cfg = create_split_proxy_config(args)
        apply_split_proxy(cfg, runner)
        UI.ok("Public proxy setup complete.")
        print(f"Proxy WireGuard public key: {cfg.public_key}")
        if cfg.peer_private_key:
            print("Copy /var/lib/phoenix-tunnel/backend/backend-wg0.conf to the backend server as /etc/wireguard/wg0.conf.")
        return 0
    if command == "setup-backend":
        cfg = create_split_backend_config(args)
        apply_split_backend(cfg, runner)
        UI.ok("Backend setup complete.")
        print(f"Backend WireGuard public key: {cfg.public_key}")
        print("Add this backend public key to the proxy setup if the proxy was not generated with backend keys.")
        return 0
    if command == "apply":
        apply_system(PhoenixConfig.from_file(), runner)
        UI.ok("Configuration applied.")
        return 0
    if command == "status":
        status_dashboard(PhoenixConfig.from_file())
        return 0
    if command == "health":
        return health(PhoenixConfig.from_file())
    if command == "rollback":
        rollback()
        return 0
    if command == "deps":
        install_dependencies_hint()
        return 0
    if command == "export-client":
        cfg = PhoenixConfig.from_file()
        peer = next((p for p in cfg.peers if p.name == args.name), None)
        if not peer:
            UI.error(f"Unknown client: {args.name}")
            return 1
        path = STATE_DIR / "clients" / f"{peer.name}.conf"
        print(path.read_text(encoding="utf-8"))
        if args.qr:
            export_qr(path)
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        UI.error("Interrupted.")
        raise SystemExit(130)
    except Exception as exc:
        UI.error(str(exc))
        raise SystemExit(1)
