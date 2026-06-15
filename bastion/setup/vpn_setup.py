"""WireGuard / ZeroTier configuration for `bastion setup` (the L5 VPN step).

L5 owns no committed files: WireGuard configs carry PRIVATE KEYS and the ZeroTier network ID is
installation secret (Commandments #1/#8), so none of it can live in the repo. The L5 layer module
manages only the *interface lifecycle* (`wg-quick@`, `zerotier-one`) for the interfaces named in
machine.conf — it never writes a key. THIS module is the setup-time half that produces the secret
material: it generates a WireGuard keypair (pure crypto — no tunnel is brought up), renders a
complete `/etc/wireguard/<iface>.conf` (chmod 600) from operator-supplied peer details, and joins
a ZeroTier network on the live host.

Pure / IO-thin (mirrors ai_backend.py): every host touch goes through `System`, so the render and
keygen are testable with a fake System — no host access, no network. The wizard does the prompting
and orchestration; this module just turns answers into files.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from ..system import System

WG_DIR = "/etc/wireguard"


@dataclass
class WgConf:
    """Everything needed to render one complete wg interface config (no placeholders)."""
    private_key: str
    address: str                 # this node's tunnel address, CIDR (e.g. 10.8.0.1/24)
    peer_public_key: str
    allowed_ips: str
    listen_port: str = ""        # server side (clients dial in); blank on a pure client
    mtu: str = ""                # interface MTU; blank = wg-quick auto-derives. Lower it (e.g. 1340)
                                 # for CGNAT/PPPoE/nested-tunnel paths where the auto value black-holes.
    peer_endpoint: str = ""      # host:port of the peer; blank when the peer dials in to us
    keepalive: str = "25"        # only emitted when there is an Endpoint (NAT keepalive)


def wg_conf_path(iface: str) -> str:
    return f"{WG_DIR}/{iface}.conf"


def wg_conf_present(sys: System, iface: str) -> bool:
    """True when a wg config already exists — reuse on reinstall, NEVER clobber an existing key."""
    return sys.exists(wg_conf_path(iface))


def wg_keypair(sys: System) -> tuple[str, str] | None:
    """Generate a WireGuard private+public keypair via the `wg` tool. Pure key derivation — no
    interface is created and no tunnel is brought up. Returns (private, public), or None if `wg`
    is unavailable or the generation fails."""
    if not sys.command_exists("wg"):
        return None
    g = sys.run("wg", "genkey")
    private = (g.stdout or "").strip()
    if g.returncode != 0 or not private:
        return None
    p = sys.run("wg", "pubkey", input=private + "\n")
    public = (p.stdout or "").strip()
    if p.returncode != 0 or not public:
        return None
    return private, public


def render_wg_conf(c: WgConf) -> str:
    """Render a complete wg-quick config. Optional lines (ListenPort/Endpoint/PersistentKeepalive)
    are emitted only when their value is present, so the result is always valid wg-quick input."""
    lines = ["[Interface]", f"PrivateKey = {c.private_key}", f"Address = {c.address}"]
    if c.listen_port:
        lines.append(f"ListenPort = {c.listen_port}")
    if c.mtu:
        lines.append(f"MTU = {c.mtu}")
    lines += ["", "[Peer]", f"PublicKey = {c.peer_public_key}"]
    if c.peer_endpoint:
        lines.append(f"Endpoint = {c.peer_endpoint}")
    lines.append(f"AllowedIPs = {c.allowed_ips}")
    if c.peer_endpoint and c.keepalive:
        lines.append(f"PersistentKeepalive = {c.keepalive}")
    return "\n".join(lines) + "\n"


def write_wg_conf(sys: System, iface: str, c: WgConf) -> str:
    """Render + write /etc/wireguard/<iface>.conf chmod 600 (root-prefixed via ``sys.path`` so
    --root staging stays contained). Returns the logical (un-rooted) path written."""
    rel = wg_conf_path(iface)
    dest = sys.path(rel)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(render_wg_conf(c))
    os.chmod(dest, 0o600)
    return rel


def default_server_address(cidr: str) -> str:
    """First host of a WireGuard server subnet, as a CIDR (e.g. 10.8.0.0/24 -> 10.8.0.1/24). Used as
    the proposed Address for a server interface. Returns '' for an unparseable subnet."""
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
    except (ValueError, TypeError):
        return ""
    hosts = list(net.hosts())
    return f"{hosts[0]}/{net.prefixlen}" if hosts else ""


def zt_join(sys: System, network_id: str):
    """Join a ZeroTier network on the live host (talks to the local zerotier-one daemon, which the
    L5 layer install enables first). The network ID is installation secret — never committed; ZeroTier
    persists the membership in its own state, so nothing is stored in machine.conf."""
    return sys.run("zerotier-cli", "join", network_id)
