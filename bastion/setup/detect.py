"""Network/topology detection for the setup wizard (§10 step 1).

Founding-document principle (§10): the wizard MUST arrive at every value through
*detection or explicit user entry* — nothing is hard-coded into installer logic.
This module only DETECTS and PROPOSES; the wizard asks the user to confirm or correct,
and the confirmed value is what writes machine.conf.

Design: the parsing functions are pure (text in -> structured out) so they are unit-testable
without touching the host; the live `detect(System)` orchestrator runs the read-only commands
(`ip`, `sshd -T`, `systemctl`) and threads their output through the parsers. Every live call is
read-only and fails soft — detection never mutates the system and never raises on a missing tool.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..system import System

# Interface-name prefixes we treat as non-physical (never proposed as LAN/WAN).
_VIRTUAL_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "vnet", "tun", "tap",
                     "kube", "cni", "flannel", "tailscale", "bond", "dummy")
_WG_PREFIXES = ("wg",)
_ZT_PREFIXES = ("zt",)
_WIFI_PREFIXES = ("wl",)
_ETH_PREFIXES = ("en", "eth", "em", "eno", "ens", "enp")

# Services the wizard cares about: id -> (binary, unit). Presence = binary OR unit-file;
# active = unit reported active by systemd.
_SERVICES: dict[str, tuple[str, str]] = {
    "nftables": ("nft", "nftables.service"),
    "ufw": ("ufw", "ufw.service"),
    "firewalld": ("firewall-cmd", "firewalld.service"),
    "dnsmasq": ("dnsmasq", "dnsmasq.service"),
    "unbound": ("unbound", "unbound.service"),
    "crowdsec": ("cscli", "crowdsec.service"),
    "zerotier": ("zerotier-cli", "zerotier-one.service"),
    "wireguard": ("wg", "wg-quick.target"),
    "isc-dhcp": ("dhcpd", "dhcpd.service"),
}

# distro ID (from /etc/os-release) -> package-manager name.
_DISTRO_PKG = {
    "arch": "pacman", "endeavouros": "pacman", "manjaro": "pacman", "cachyos": "pacman",
    "debian": "apt", "ubuntu": "apt", "raspbian": "apt", "linuxmint": "apt", "pop": "apt",
    "fedora": "dnf", "rhel": "dnf", "centos": "dnf", "rocky": "dnf", "almalinux": "dnf",
}


@dataclass
class Iface:
    name: str
    kind: str            # ethernet | wifi | wireguard | zerotier | loopback | virtual | other
    up: bool
    addrs: list[str] = field(default_factory=list)   # IPv4 CIDRs, e.g. "10.0.1.1/24"

    @property
    def physical(self) -> bool:
        return self.kind in ("ethernet", "wifi")


@dataclass
class ServiceState:
    present: bool
    active: bool


@dataclass
class Detection:
    distro: str
    pkg_manager: str
    interfaces: list[Iface]
    default_iface: str | None
    gateway: str | None
    ssh_port: int
    services: dict[str, ServiceState]
    proposed_mode: str               # edge | endpoint
    lan_iface: str | None
    wan_iface: str | None
    lan_ip: str | None
    lan_cidr: str | None

    def physical_ifaces(self) -> list[Iface]:
        return [i for i in self.interfaces if i.physical]


# --- pure parsers ----------------------------------------------------------

def classify_iface(name: str, flags: set[str]) -> str:
    if name == "lo" or "LOOPBACK" in flags:
        return "loopback"
    if name.startswith(_WG_PREFIXES):
        return "wireguard"
    if name.startswith(_ZT_PREFIXES):
        return "zerotier"
    if name.startswith(_VIRTUAL_PREFIXES):
        return "virtual"
    if name.startswith(_WIFI_PREFIXES):
        return "wifi"
    if name.startswith(_ETH_PREFIXES):
        return "ethernet"
    return "other"


def parse_interfaces(link_text: str, addr_text: str) -> list[Iface]:
    """Parse `ip -o link show` (+ `ip -o -4 addr show`) output into Iface records."""
    addrs: dict[str, list[str]] = {}
    for line in addr_text.splitlines():
        # "2: enp3s0    inet 192.168.1.10/24 brd ... scope global ..."
        m = re.match(r"\s*\d+:\s+(\S+)\s+inet\s+(\S+)", line)
        if m:
            addrs.setdefault(m.group(1), []).append(m.group(2))

    ifaces: list[Iface] = []
    for line in link_text.splitlines():
        # "2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ... state UP ..."
        m = re.match(r"\s*\d+:\s+([^:@]+)[:@]?\S*:\s+<([^>]*)>", line)
        if not m:
            continue
        name = m.group(1).strip()
        flags = set(m.group(2).split(","))
        # Admin-up if the UP flag is set; carrier (LOWER_UP) is a separate signal we don't require.
        up = "UP" in flags
        ifaces.append(Iface(name=name, kind=classify_iface(name, flags), up=up,
                            addrs=addrs.get(name, [])))
    return ifaces


def parse_default_route(route_text: str) -> tuple[str | None, str | None]:
    """Parse `ip route show default` -> (iface, gateway). First default route wins."""
    for line in route_text.splitlines():
        # "default via 192.168.1.1 dev enp3s0 proto dhcp ..."
        m = re.search(r"^default\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)", line.strip())
        if m:
            return m.group(2), m.group(1)   # (iface, gateway-or-None)
    return None, None


def parse_ssh_port(sshd_t_text: str, sshd_config_text: str = "") -> int:
    """SSH port from `sshd -T` output, falling back to sshd_config, then 22 (§10)."""
    for line in sshd_t_text.splitlines():
        m = re.match(r"\s*port\s+(\d+)", line, re.IGNORECASE)
        if m:
            return int(m.group(1))
    for line in sshd_config_text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"Port\s+(\d+)", s, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return 22


def parse_os_release(text: str) -> str:
    """Extract the distro ID from /etc/os-release contents; '' if absent."""
    for line in text.splitlines():
        if line.startswith("ID="):
            return line.split("=", 1)[1].strip().strip('"').lower()
    return ""


def propose_mode(interfaces: list[Iface], default_iface: str | None) -> str:
    """Edge if ≥2 physical interfaces are present (router-between-networks shape),
    else endpoint. A proposal only — the wizard makes the user confirm (§10 step 2)."""
    phys = [i for i in interfaces if i.physical]
    return "edge" if len(phys) >= 2 else "endpoint"


def propose_lan_wan(interfaces: list[Iface], default_iface: str | None,
                    mode: str) -> tuple[str | None, str | None]:
    """Propose (lan_iface, wan_iface) from detected interfaces.

    Edge: WAN = the default-route interface (faces upstream); LAN = the first other
    physical interface. Endpoint: LAN = the default-route interface (the machine is a
    client on the LAN); no WAN.
    """
    phys = [i for i in interfaces if i.physical]
    names = [i.name for i in phys]
    if mode == "endpoint":
        lan = default_iface if default_iface in names else (names[0] if names else None)
        return lan, None
    # edge: WAN = the default-route interface; LAN = the best remaining candidate,
    # preferring one that is up and already carries an address (a configured NIC beats a
    # down/unconfigured one). The user still confirms or overrides (§10 step 4).
    wan = default_iface if default_iface in names else None
    candidates = sorted((i for i in phys if i.name != wan),
                        key=lambda i: (bool(i.addrs), i.up), reverse=True)
    lan = candidates[0].name if candidates else None
    if wan is None and len(names) >= 2:   # no default route yet (fresh box) — split the first two
        wan, lan = names[0], names[1]
    return lan, wan


def lan_addr_of(interfaces: list[Iface], lan_iface: str | None) -> tuple[str | None, str | None]:
    """Return (lan_ip, lan_cidr) for the chosen LAN interface, or (None, None)."""
    if not lan_iface:
        return None, None
    for i in interfaces:
        if i.name == lan_iface and i.addrs:
            cidr = i.addrs[0]
            ip, _, prefix = cidr.partition("/")
            network = _network_cidr(ip, prefix) if prefix else None
            return ip, network
    return None, None


def _network_cidr(ip: str, prefix: str) -> str | None:
    """Best-effort network address for ip/prefix without importing ipaddress edge cases."""
    try:
        import ipaddress
        return str(ipaddress.ip_interface(f"{ip}/{prefix}").network)
    except ValueError:
        return None


# --- live orchestrator -----------------------------------------------------

def detect(sys: System) -> Detection:
    """Run the read-only detection commands and assemble a Detection. Never mutates."""
    link_text = sys.run("ip", "-o", "link", "show").stdout
    addr_text = sys.run("ip", "-o", "-4", "addr", "show").stdout
    interfaces = parse_interfaces(link_text, addr_text)

    route_text = sys.run("ip", "route", "show", "default").stdout
    default_iface, gateway = parse_default_route(route_text)

    sshd_t = sys.run("sshd", "-T").stdout
    sshd_config = sys.read("/etc/ssh/sshd_config") if sys.exists("/etc/ssh/sshd_config") else ""
    ssh_port = parse_ssh_port(sshd_t, sshd_config)

    os_release = sys.read("/etc/os-release") if sys.exists("/etc/os-release") else ""
    distro = parse_os_release(os_release)
    pkg_manager = _DISTRO_PKG.get(distro) or _detect_pkg_binary(sys)

    services = {}
    for sid, (binary, unit) in _SERVICES.items():
        present = sys.command_exists(binary) or sys.exists(f"/usr/lib/systemd/system/{unit}") \
            or sys.exists(f"/etc/systemd/system/{unit}")
        services[sid] = ServiceState(present=present, active=sys.unit_active(unit))

    mode = propose_mode(interfaces, default_iface)
    lan_iface, wan_iface = propose_lan_wan(interfaces, default_iface, mode)
    lan_ip, lan_cidr = lan_addr_of(interfaces, lan_iface)

    return Detection(
        distro=distro or "auto", pkg_manager=pkg_manager, interfaces=interfaces,
        default_iface=default_iface, gateway=gateway, ssh_port=ssh_port, services=services,
        proposed_mode=mode, lan_iface=lan_iface, wan_iface=wan_iface,
        lan_ip=lan_ip, lan_cidr=lan_cidr,
    )


def _detect_pkg_binary(sys: System) -> str:
    for binary, name in (("pacman", "pacman"), ("apt-get", "apt"), ("dnf", "dnf")):
        if sys.command_exists(binary):
            return name
    return "auto"
