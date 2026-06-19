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

# Coarser P3 categorisation (orthogonal to `kind`, which stays as-is so propose_mode/tests don't
# move): how an interface relates to the firewall topology. physical = a real NIC; bridge = a
# software bridge a hypervisor/container engine owns (libvirt virbr*, docker*, br-*, CNI); overlay =
# a VPN/mesh tunnel (wg/zt/tun/tailscale); virtual = everything else (lo/veth/vnet/dummy/bond).
_BRIDGE_PREFIXES = ("virbr", "docker", "br-", "br0", "cni", "flannel", "kube", "cali")
_OVERLAY_PREFIXES = ("wg", "zt", "tun", "tap", "tailscale", "wt")

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
    # Self-managing dynamic firewalls (own their own nft tables / forward+NAT rules). Their presence
    # is what makes bastion propose COOPERATIVE scope (don't flush their tables). See propose_scope.
    "libvirt": ("virsh", "libvirtd.service"),
    "docker": ("docker", "docker.service"),
    "podman": ("podman", "podman.service"),
}

# nft tables bastion itself owns — anything else in `nft list tables` is a co-resident manager's.
_BASTION_NFT_TABLES = {("inet", "edge"), ("inet", "bastion"), ("ip", "edge_nat"),
                       ("inet", "bastion_recovery")}

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
    up: bool             # administratively up (UP flag) — NOT proof of a live link
    addrs: list[str] = field(default_factory=list)   # IPv4 CIDRs, e.g. "10.0.1.1/24"
    carrier: bool = False  # link is actually up (LOWER_UP) — an unplugged NIC is up but not carrier
    category: str = "virtual"   # physical | bridge | overlay | virtual (P3 topology role)

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
    # P3 detection/synthesis (defaults keep older Detection construction + tests valid).
    co_resident_firewalls: list[str] = field(default_factory=list)   # present managers (ufw/libvirt/…)
    nft_foreign_tables: list[tuple[str, str]] = field(default_factory=list)  # (family, name) not ours
    listeners: list[tuple[str, int]] = field(default_factory=list)   # (proto, port) non-loopback
    proposed_scope: str = "exclusive"                # exclusive | cooperative
    proposed_zones: dict[str, str] = field(default_factory=dict)     # name -> "source -> action"

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


def categorize_iface(name: str) -> str:
    """Coarse topology role (P3), orthogonal to :func:`classify_iface`'s ``kind``. Used to spot the
    bridges a hypervisor/container engine owns (cooperative-scope signal) and to keep overlays as
    'trust the iface' zones. physical = real NIC; bridge = libvirt/docker/CNI bridge; overlay =
    VPN/mesh tunnel; virtual = lo/veth/vnet/dummy/bond and anything else."""
    if name == "lo":
        return "virtual"
    if name.startswith(_OVERLAY_PREFIXES):
        return "overlay"
    if name.startswith(_BRIDGE_PREFIXES):
        return "bridge"
    if name.startswith(_WIFI_PREFIXES) or name.startswith(_ETH_PREFIXES):
        return "physical"
    return "virtual"


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
        # Admin-up if the UP flag is set; carrier (LOWER_UP, and not NO-CARRIER) means a live link.
        # An unplugged NIC reports UP but no carrier — mode detection must not count it as a network.
        up = "UP" in flags
        carrier = "LOWER_UP" in flags and "NO-CARRIER" not in flags
        ifaces.append(Iface(name=name, kind=classify_iface(name, flags), up=up,
                            addrs=addrs.get(name, []), carrier=carrier,
                            category=categorize_iface(name)))
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
    """Edge if the box looks like a router, else endpoint. A proposal only — the wizard
    makes the user confirm (§10 step 2).

    Heuristic (refined after a 2-NIC laptop with an unplugged wired port mis-proposed edge):
    a client whose default route rides a Wi-Fi interface is an endpoint — routers take a
    wired uplink. Otherwise require ≥2 physical interfaces with a live link (carrier); a NIC
    that is administratively UP but has no carrier (e.g. an unplugged laptop ethernet port)
    is not a second network and does not make a router.
    """
    default = next((i for i in interfaces if i.name == default_iface), None)
    if default is not None and default.kind == "wifi":
        return "endpoint"
    linked_phys = [i for i in interfaces if i.physical and i.carrier]
    return "edge" if len(linked_phys) >= 2 else "endpoint"


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
        if default_iface in names:
            return default_iface, None
        # No usable default-route iface: prefer one with a live link and an address (a real
        # NIC) over an unplugged/unconfigured port, so lan_cidr derives from a real address
        # rather than falling back to the example skeleton's placeholder subnet.
        addressed = [i.name for i in phys if i.carrier and i.addrs]
        linked = [i.name for i in phys if i.carrier]
        lan = next(iter(addressed or linked or names), None)
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


# --- P3 detection parsers (co-resident managers, listeners, existing intent) ------------------

def parse_nft_tables(text: str) -> list[tuple[str, str]]:
    """Parse `nft list tables` -> list of (family, name), e.g. ('ip', 'libvirt_network')."""
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*table\s+(\S+)\s+(\S+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def foreign_nft_tables(tables: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The tables bastion does NOT own — a co-resident firewall/manager's (libvirt/docker/ufw)."""
    return [(f, n) for (f, n) in tables if (f, n) not in _BASTION_NFT_TABLES]


def parse_listeners(ss_text: str) -> list[tuple[str, int]]:
    """Parse `ss -tulnH` -> sorted unique (proto, port) for NON-loopback listeners (a server the box
    runs that a zone might need to open). Loopback-only binds (127.0.0.1/::1) are filtered — they're
    never reachable off-box, so they need no firewall rule."""
    out: set[tuple[str, int]] = set()
    for line in ss_text.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto = f[0]
        addr, _, port = f[4].rpartition(":")
        if not port.isdigit():
            continue
        addr = addr.strip("[]")
        if addr in ("127.0.0.1", "::1") or addr.startswith("127."):
            continue
        out.add((proto, int(port)))
    return sorted(out)


def parse_ufw_show_added(text: str) -> list[tuple[str, str, str | None]]:
    """Parse `ufw show added` into (source, port, proto) rule tuples — the box's EXISTING intent,
    even when ufw is disabled (its saved rules still encode the source->ports policy). ``port`` is
    ``'all'`` for a source-only rule; ``proto`` is None unless the rule pins tcp/udp. source is
    ``'any'`` | an IP/CIDR | ``'iface:NAME'``. Only ALLOW rules synthesize (deny = default-drop)."""
    rules: list[tuple[str, str, str | None]] = []
    for line in text.splitlines():
        toks = line.strip().split()
        if len(toks) < 2 or toks[0].lower() != "ufw":
            continue
        toks = toks[1:]
        if toks and toks[0].lower() in ("allow", "deny", "reject", "limit"):
            verb, toks = toks[0].lower(), toks[1:]
        else:
            continue
        if verb != "allow":
            continue
        # 'in on IFACE' / 'out on IFACE' -> an interface zone (trust the whole iface).
        if len(toks) >= 3 and toks[0] in ("in", "out") and toks[1] == "on":
            rules.append((f"iface:{toks[2]}", "all", None))
            continue
        toks = [t for t in toks if t not in ("in", "out")]
        source = "any"
        if "from" in toks:
            i = toks.index("from")
            if i + 1 < len(toks):
                source = toks[i + 1]
        proto = None
        if "proto" in toks:
            i = toks.index("proto")
            if i + 1 < len(toks):
                proto = toks[i + 1].lower()
        if "port" in toks:
            i = toks.index("port")
            ports = toks[i + 1].split(",") if i + 1 < len(toks) else []
            for p in ports:
                pp, _, pr = p.partition("/")
                rules.append((source, pp, (pr or proto) or None))
        elif source != "any":
            # 'ufw allow from SRC' (no port) -> trust the whole source.
            rules.append((source, "all", None))
        else:
            # 'ufw allow 9993' / 'ufw allow 9993/tcp' -> any-source port.
            p = toks[0] if toks else ""
            pp, _, pr = p.partition("/")
            if pp.isdigit():
                rules.append(("any", pp, (pr or proto) or None))
    return rules


# --- P3 synthesis (facts -> proposed conf the operator confirms) ------------------------------

def _zone_name(source: str) -> str:
    """A deterministic, INI-key-safe [zones] name for a source (so re-synthesis is idempotent)."""
    if source == "any":
        return "anyports"
    if source.startswith("iface:"):
        return "iface_" + re.sub(r"[^0-9A-Za-z]", "_", source[len("iface:"):])
    return "net_" + re.sub(r"[^0-9A-Za-z]", "_", source)


def synthesize_zones(ufw_text: str) -> dict[str, str]:
    """Turn a box's existing ufw policy (even disabled) into a proposed ``[zones]`` mapping
    ``name -> 'source -> action'``. Rules are grouped by source: ports merge into one zone, and a
    source-only ('all') rule wins for that source. A PROPOSAL only — the wizard makes the operator
    confirm. Empty when there's nothing to synthesise. (firewalld/listener synthesis can extend this
    later; ufw covers the reference fixture + the common case.)"""
    from collections import OrderedDict
    by_source: "OrderedDict[str, dict]" = OrderedDict()
    for source, port, proto in parse_ufw_show_added(ufw_text):
        ent = by_source.setdefault(source, {"all": False, "ports": []})
        if port == "all":
            ent["all"] = True
        else:
            tok = f"{port}/{proto}" if proto else port
            if tok not in ent["ports"]:
                ent["ports"].append(tok)
    zones: dict[str, str] = {}
    for source, ent in by_source.items():
        action = "all" if ent["all"] else ", ".join(ent["ports"])
        if action:
            zones[_zone_name(source)] = f"{source} -> {action}"
    return zones


def propose_scope(services: dict[str, "ServiceState"],
                  foreign_tables: list[tuple[str, str]]) -> str:
    """``cooperative`` when bastion would otherwise flush co-resident nft state; else ``exclusive``.

    Two triggers, the second a catch-all:
      1. A known self-managing manager's SERVICE is present (libvirt/docker/podman) — forward-looking,
         so it fires even before that manager has loaded an nft table (e.g. Docker with no containers
         running yet).
      2. **Catch-all:** ANY co-resident nft table bastion doesn't own. When *something else* already
         owns nft state — Kubernetes/CNI, Tailscale, a hand-written table, anything — default to NOT
         flushing it. Erring toward cooperative is the non-destructive failure mode: exclusive's
         ``flush ruleset`` would delete every table on the box.

    A proposal; the operator confirms. (Specific managers are still named via ``services`` for clearer
    wizard messaging; the runtime also hard-warns before an exclusive apply that would flush foreign
    tables — see ``layers.base.warn_if_exclusive_flush``.)"""
    for sid in ("libvirt", "docker", "podman"):
        st = services.get(sid)
        if st and st.present:
            return "cooperative"
    if foreign_tables:
        return "cooperative"
    return "exclusive"


def synthesize_scope(detection: "Detection") -> str:
    """The Detection-level wrapper over :func:`propose_scope` (for the wizard + tests)."""
    return propose_scope(detection.services, detection.nft_foreign_tables)


# --- live orchestrator -----------------------------------------------------

def detect(sys: System) -> Detection:
    """Run the read-only detection commands and assemble a Detection. Never mutates."""
    link_text = sys.run("ip", "-o", "link", "show").stdout
    addr_text = sys.run("ip", "-o", "-4", "addr", "show").stdout
    interfaces = parse_interfaces(link_text, addr_text)

    route_text = sys.run("ip", "route", "show", "default").stdout
    default_iface, gateway = parse_default_route(route_text)

    sshd_t = sys.run("sshd", "-T").stdout
    ssh_port = parse_ssh_port(sshd_t, _sshd_config_text(sys))

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

    # P3: co-resident managers + existing intent (all read-only, fail-soft -> empty when absent).
    foreign = foreign_nft_tables(parse_nft_tables(sys.run("nft", "list", "tables").stdout))
    listeners = parse_listeners(sys.run("ss", "-tulnH").stdout)
    co_resident = [sid for sid in ("ufw", "firewalld", "libvirt", "docker", "podman")
                   if services.get(sid) and services[sid].present]
    proposed_scope = propose_scope(services, foreign)
    proposed_zones = synthesize_zones(sys.run("ufw", "show", "added").stdout)

    return Detection(
        distro=distro or "auto", pkg_manager=pkg_manager, interfaces=interfaces,
        default_iface=default_iface, gateway=gateway, ssh_port=ssh_port, services=services,
        proposed_mode=mode, lan_iface=lan_iface, wan_iface=wan_iface,
        lan_ip=lan_ip, lan_cidr=lan_cidr,
        co_resident_firewalls=co_resident, nft_foreign_tables=foreign, listeners=listeners,
        proposed_scope=proposed_scope, proposed_zones=proposed_zones,
    )


def _sshd_config_text(sys: System) -> str:
    """sshd_config plus its drop-ins, drop-ins first. `sshd -T` needs root, so when it is denied
    the wizard falls back to parsing config files — and modern distros set `Port` in a drop-in
    (e.g. /etc/ssh/sshd_config.d/10-hardened.conf), not the main file. The `Include` sits at the
    top of sshd_config and first-match wins, so drop-in values take precedence."""
    parts: list[str] = []
    dropin = sys.path("/etc/ssh/sshd_config.d")
    if dropin.is_dir():
        for f in sorted(dropin.glob("*.conf")):
            try:
                parts.append(f.read_text())
            except OSError:
                pass
    if sys.exists("/etc/ssh/sshd_config"):
        parts.append(sys.read("/etc/ssh/sshd_config"))
    return "\n".join(parts)


def _detect_pkg_binary(sys: System) -> str:
    for binary, name in (("pacman", "pacman"), ("apt-get", "apt"), ("dnf", "dnf")):
        if sys.command_exists(binary):
            return name
    return "auto"
