"""Topology detection for the setup wizard (Phase 5 / detect.py).

Pure parsers are tested against canned command output; the live `detect()` orchestrator is
tested against a fake System that replays scripted command/file results — no host access.
"""
import subprocess

from bastion.setup import detect
from bastion.system import System

# --- canned command output (sanitized RFC1918 / generic) ------------------

LINK = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT
3: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT
4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT
"""

ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo
2: enp3s0    inet 192.168.1.10/24 brd 192.168.1.255 scope global enp3s0
3: enp4s0    inet 10.0.1.1/24 brd 10.0.1.255 scope global enp4s0
4: wg0    inet 10.8.0.1/24 scope global wg0
"""

ROUTE = "default via 192.168.1.1 dev enp3s0 proto dhcp metric 100\n"


# --- pure parser tests -----------------------------------------------------

def test_classify_iface():
    assert detect.classify_iface("lo", {"LOOPBACK", "UP"}) == "loopback"
    assert detect.classify_iface("enp3s0", {"UP"}) == "ethernet"
    assert detect.classify_iface("wlan0", {"UP"}) == "wifi"
    assert detect.classify_iface("wg0", {"UP"}) == "wireguard"
    assert detect.classify_iface("zt5u4", {"UP"}) == "zerotier"
    assert detect.classify_iface("docker0", {"UP"}) == "virtual"


def test_parse_interfaces():
    ifaces = {i.name: i for i in detect.parse_interfaces(LINK, ADDR)}
    assert set(ifaces) == {"lo", "enp3s0", "enp4s0", "wg0", "docker0"}
    assert ifaces["enp3s0"].kind == "ethernet" and ifaces["enp3s0"].up
    assert ifaces["enp3s0"].addrs == ["192.168.1.10/24"]
    assert ifaces["enp4s0"].addrs == ["10.0.1.1/24"]
    assert ifaces["wg0"].kind == "wireguard"
    assert ifaces["docker0"].kind == "virtual"
    # Only the two ethernet NICs are "physical".
    phys = [i.name for i in detect.parse_interfaces(LINK, ADDR) if i.physical]
    assert phys == ["enp3s0", "enp4s0"]


def test_parse_default_route():
    assert detect.parse_default_route(ROUTE) == ("enp3s0", "192.168.1.1")
    assert detect.parse_default_route("") == (None, None)
    # device-only default (no gateway) still yields the iface.
    assert detect.parse_default_route("default dev wg0 scope link\n") == ("wg0", None)


def test_parse_ssh_port():
    assert detect.parse_ssh_port("port 1111\naddressfamily any\n") == 1111
    assert detect.parse_ssh_port("", "Port 2222\n") == 2222
    assert detect.parse_ssh_port("", "#Port 9999\n") == 22   # commented -> default
    assert detect.parse_ssh_port("", "") == 22


def test_sshd_config_text_includes_dropins():
    # The real port often lives in a drop-in, not the main sshd_config; non-root detection
    # (sshd -T denied) must still find it. Drop-ins come first (first-match wins).
    import tempfile
    from pathlib import Path
    from bastion.system import System
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "etc/ssh/sshd_config.d").mkdir(parents=True)
        (root / "etc/ssh/sshd_config").write_text("# main config, no Port line\n")
        (root / "etc/ssh/sshd_config.d/10-hardened.conf").write_text("Port 1111\n")
        text = detect._sshd_config_text(System(root=root))
        assert detect.parse_ssh_port("", text) == 1111


def test_parse_os_release():
    assert detect.parse_os_release('ID=arch\nNAME="Arch Linux"\n') == "arch"
    assert detect.parse_os_release('NAME="Debian"\nID=debian\n') == "debian"
    assert detect.parse_os_release("") == ""


def test_propose_mode():
    ifaces = detect.parse_interfaces(LINK, ADDR)
    assert detect.propose_mode(ifaces, "enp3s0") == "edge"        # 2 physical NICs
    one = detect.parse_interfaces(
        "2: enp3s0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP mode DEFAULT\n", ADDR)
    assert detect.propose_mode(one, "enp3s0") == "endpoint"       # 1 physical NIC


def test_propose_mode_wifi_uplink_is_endpoint():
    # Laptop shape that previously mis-proposed edge: an UP Wi-Fi default route plus a DOWN
    # wired port. A client whose uplink is Wi-Fi is an endpoint, not a router.
    link = ("2: enp1s0: <BROADCAST,MULTICAST> mtu 1500 state DOWN mode DEFAULT\n"
            "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT\n")
    addr = "3: wlan0    inet 192.168.1.175/24 brd 192.168.1.255 scope global wlan0\n"
    ifaces = detect.parse_interfaces(link, addr)
    assert detect.propose_mode(ifaces, "wlan0") == "endpoint"


def test_propose_mode_unplugged_second_nic_is_endpoint():
    # Two wired NICs but the second is admin-UP with NO-CARRIER (cable unplugged) — it is not a
    # live second network, so this is an endpoint, not a router. Guards the carrier-vs-admin-up trap.
    link = ("2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT\n"
            "3: enp4s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN mode DEFAULT\n")
    ifaces = detect.parse_interfaces(link, ADDR)
    assert ifaces[1].up and not ifaces[1].carrier   # admin-up but no link
    assert detect.propose_mode(ifaces, "enp3s0") == "endpoint"


def test_propose_lan_wan_endpoint_prefers_up_addressed_iface():
    # No default route resolved; a DOWN wired port plus an UP+addressed Wi-Fi iface. The LAN
    # must be the live iface so lan_cidr derives a real subnet, not the example placeholder.
    link = ("2: enp1s0: <BROADCAST,MULTICAST> mtu 1500 state DOWN mode DEFAULT\n"
            "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT\n")
    addr = "3: wlan0    inet 192.168.1.175/24 brd 192.168.1.255 scope global wlan0\n"
    ifaces = detect.parse_interfaces(link, addr)
    lan, wan = detect.propose_lan_wan(ifaces, None, "endpoint")
    assert lan == "wlan0" and wan is None
    ip, cidr = detect.lan_addr_of(ifaces, lan)
    assert ip == "192.168.1.175" and cidr == "192.168.1.0/24"


def test_propose_lan_wan_edge():
    ifaces = detect.parse_interfaces(LINK, ADDR)
    lan, wan = detect.propose_lan_wan(ifaces, "enp3s0", "edge")
    assert wan == "enp3s0"          # default-route iface faces upstream
    assert lan == "enp4s0"          # the other physical NIC is LAN-facing


def test_propose_lan_wan_endpoint():
    ifaces = detect.parse_interfaces(LINK, ADDR)
    lan, wan = detect.propose_lan_wan(ifaces, "enp3s0", "endpoint")
    assert lan == "enp3s0" and wan is None


def test_lan_addr_of():
    ifaces = detect.parse_interfaces(LINK, ADDR)
    ip, cidr = detect.lan_addr_of(ifaces, "enp4s0")
    assert ip == "10.0.1.1" and cidr == "10.0.1.0/24"
    assert detect.lan_addr_of(ifaces, None) == (None, None)


# --- live orchestrator against a fake System -------------------------------

class FakeSystem(System):
    """Replays scripted command output + file contents; no real host access."""
    def __init__(self, cmds: dict[tuple, str], files: dict[str, str], have: set):
        super().__init__()
        self._cmds, self._files, self._have = cmds, files, have

    def run(self, *args, capture=True):
        out = self._cmds.get(args, "")
        rc = 0 if args in self._cmds else 1
        return subprocess.CompletedProcess(args, rc, out, "")

    def read(self, p):
        return self._files.get(str(p), "")

    def exists(self, p):
        return str(p) in self._files

    def command_exists(self, name):
        return name in self._have

    def unit_active(self, unit):
        return unit in self._have


def test_detect_edge_topology():
    cmds = {
        ("ip", "-o", "link", "show"): LINK,
        ("ip", "-o", "-4", "addr", "show"): ADDR,
        ("ip", "route", "show", "default"): ROUTE,
        ("sshd", "-T"): "port 1111\n",
    }
    files = {"/etc/os-release": "ID=arch\n", "/etc/ssh/sshd_config": "Port 1111\n"}
    have = {"pacman", "nft", "dnsmasq", "nftables.service"}
    d = detect.detect(FakeSystem(cmds, files, have))

    assert d.distro == "arch" and d.pkg_manager == "pacman"
    assert d.proposed_mode == "edge"
    assert d.wan_iface == "enp3s0" and d.lan_iface == "enp4s0"
    assert d.lan_ip == "10.0.1.1" and d.lan_cidr == "10.0.1.0/24"
    assert d.gateway == "192.168.1.1" and d.ssh_port == 1111
    assert d.services["nftables"].present and d.services["nftables"].active
    assert d.services["dnsmasq"].present and not d.services["dnsmasq"].active
    assert not d.services["crowdsec"].present


def test_detect_falls_back_when_tools_absent():
    # No ip/sshd output, no os-release -> safe defaults, never raises.
    d = detect.detect(FakeSystem({}, {}, set()))
    assert d.interfaces == []
    assert d.proposed_mode == "endpoint"
    assert d.ssh_port == 22
    assert d.distro == "auto" and d.pkg_manager == "auto"
    assert d.lan_iface is None
    assert d.proposed_scope == "exclusive"      # nothing co-resident -> bastion owns the ruleset
    assert d.proposed_zones == {}


# --- P3: categorisation, co-resident detection, listeners, synthesis -------

def test_categorize_iface():
    assert detect.categorize_iface("enp3s0") == "physical"
    assert detect.categorize_iface("wlan0") == "physical"
    assert detect.categorize_iface("virbr0") == "bridge"
    assert detect.categorize_iface("docker0") == "bridge"
    assert detect.categorize_iface("br-abc123") == "bridge"
    assert detect.categorize_iface("wg0") == "overlay"
    assert detect.categorize_iface("ztabc123") == "overlay"
    assert detect.categorize_iface("lo") == "virtual"
    assert detect.categorize_iface("veth7f") == "virtual"
    # category is orthogonal to kind (kind stays as-is for propose_mode)
    ifaces = {i.name: i for i in detect.parse_interfaces(LINK, ADDR)}
    assert ifaces["docker0"].kind == "virtual" and ifaces["docker0"].category == "bridge"
    assert ifaces["enp3s0"].category == "physical"


def test_parse_nft_tables_and_foreign():
    text = "table inet edge\ntable ip edge_nat\ntable ip libvirt_network\ntable ip6 libvirt_network\n"
    tables = detect.parse_nft_tables(text)
    assert ("inet", "edge") in tables and ("ip", "libvirt_network") in tables
    foreign = detect.foreign_nft_tables(tables)
    assert ("ip", "libvirt_network") in foreign
    assert ("inet", "edge") not in foreign and ("ip", "edge_nat") not in foreign


def test_parse_listeners_drops_loopback():
    ss = ("tcp   LISTEN 0 4096  0.0.0.0:8096  0.0.0.0:*\n"
          "tcp   LISTEN 0 128   127.0.0.1:6379 0.0.0.0:*\n"      # loopback -> dropped
          "udp   UNCONN 0 0     0.0.0.0:53    0.0.0.0:*\n"
          "tcp   LISTEN 0 128   [::1]:11211   [::]:*\n")          # v6 loopback -> dropped
    assert detect.parse_listeners(ss) == [("tcp", 8096), ("udp", 53)]


# EM-shaped ufw policy (the validation fixture): LAN->media, ZeroTier->media+ssh, wg->ssh,
# virbr0->all, 9993 global. SSH NOT open from plain LAN.
EM_UFW = """\
Added user rules (see 'ufw status' for running firewall):
ufw allow from 192.168.1.0/24 to any port 8096,8080,8989,7878,9117
ufw allow from 192.168.192.0/24 to any port 8096,1111 proto tcp
ufw allow from 10.0.0.0/24 to any port 22,1111
ufw allow in on virbr0
ufw allow 9993
ufw allow 9993/udp
"""


def test_parse_ufw_show_added():
    rules = detect.parse_ufw_show_added(EM_UFW)
    assert ("192.168.1.0/24", "8096", None) in rules
    assert ("192.168.192.0/24", "1111", "tcp") in rules       # proto carried onto each port
    assert ("iface:virbr0", "all", None) in rules
    assert ("any", "9993", None) in rules and ("any", "9993", "udp") in rules


def test_synthesize_zones_from_em_ufw():
    zones = detect.synthesize_zones(EM_UFW)
    assert zones["net_192_168_1_0_24"] == "192.168.1.0/24 -> 8096, 8080, 8989, 7878, 9117"
    assert zones["net_192_168_192_0_24"] == "192.168.192.0/24 -> 8096/tcp, 1111/tcp"
    assert zones["net_10_0_0_0_24"] == "10.0.0.0/24 -> 22, 1111"
    assert zones["iface_virbr0"] == "iface:virbr0 -> all"
    assert zones["anyports"] == "any -> 9993, 9993/udp"
    assert detect.synthesize_zones("") == {}


def test_propose_scope_cooperative_when_libvirt_present():
    coop = {"libvirt": detect.ServiceState(present=True, active=True)}
    assert detect.propose_scope(coop, []) == "cooperative"        # by service (table not loaded yet)
    # via a co-resident table even if the service probe missed it
    assert detect.propose_scope({}, [("ip", "libvirt_network")]) == "cooperative"
    # CATCH-ALL: ANY foreign nft table -> cooperative (k8s/CNI, Tailscale, hand-written, even ufw's
    # filter table). When something else already owns nft state, default to NOT flushing it.
    assert detect.propose_scope({}, [("ip", "kube_proxy")]) == "cooperative"
    assert detect.propose_scope({}, [("ip", "filter")]) == "cooperative"
    # only when NOTHING foreign exists -> exclusive (bastion owns the whole ruleset)
    assert detect.propose_scope({}, []) == "exclusive"


def test_propose_scope_cooperative_for_named_self_managers():
    # Forward-looking trigger: a self-managing manager's SERVICE present -> cooperative even before
    # it has loaded an nft table (no foreign tables passed). Covers the k8s/CNI + Tailscale naming
    # that previously relied on the foreign-table catch-all alone.
    for sid in ("kubernetes", "k3s", "tailscale", "docker", "podman"):
        present = {sid: detect.ServiceState(present=True, active=False)}
        assert detect.propose_scope(present, []) == "cooperative", sid
    # present=False must NOT trip it (binary/unit absent) -> exclusive
    absent = {"tailscale": detect.ServiceState(present=False, active=False)}
    assert detect.propose_scope(absent, []) == "exclusive"


def test_detect_proposes_cooperative_with_libvirt(monkeypatch):
    cmds = {
        ("ip", "-o", "link", "show"): LINK,
        ("ip", "-o", "-4", "addr", "show"): ADDR,
        ("ip", "route", "show", "default"): ROUTE,
        ("nft", "list", "tables"): "table inet edge\ntable ip libvirt_network\n",
        ("ufw", "show", "added"): EM_UFW,
    }
    have = {"pacman", "nft", "virsh", "libvirtd.service"}     # libvirt present
    d = detect.detect(FakeSystem(cmds, {"/etc/os-release": "ID=arch\n"}, have))
    assert d.proposed_scope == "cooperative"
    assert "libvirt" in d.co_resident_firewalls
    assert ("ip", "libvirt_network") in d.nft_foreign_tables
    assert d.proposed_zones["iface_virbr0"] == "iface:virbr0 -> all"


def test_detect_proposes_cooperative_with_tailscale_no_table_yet():
    # Forward-looking: tailscaled present but it hasn't programmed its nft table yet (none foreign).
    # The named-service trigger must still propose cooperative and surface it for wizard messaging.
    cmds = {
        ("ip", "-o", "link", "show"): LINK,
        ("ip", "-o", "-4", "addr", "show"): ADDR,
        ("ip", "route", "show", "default"): ROUTE,
        ("nft", "list", "tables"): "table inet bastion\n",     # only bastion's own -> nothing foreign
    }
    have = {"pacman", "nft", "tailscale", "tailscaled.service"}
    d = detect.detect(FakeSystem(cmds, {"/etc/os-release": "ID=arch\n"}, have))
    assert d.proposed_scope == "cooperative"
    assert "tailscale" in d.co_resident_firewalls
    assert d.nft_foreign_tables == []                          # proven without the catch-all


def test_detect_catch_all_cooperative_on_unknown_foreign_table():
    # No libvirt/docker/podman service, but a co-resident table bastion doesn't recognize (e.g. a
    # Kubernetes CNI / hand-written table) -> the catch-all proposes cooperative anyway.
    cmds = {
        ("ip", "-o", "link", "show"): LINK,
        ("ip", "-o", "-4", "addr", "show"): ADDR,
        ("nft", "list", "tables"): "table inet bastion\ntable ip cilium_post_nat\n",
    }
    d = detect.detect(FakeSystem(cmds, {"/etc/os-release": "ID=arch\n"}, {"nft"}))
    assert d.proposed_scope == "cooperative"
    assert ("ip", "cilium_post_nat") in d.nft_foreign_tables       # foreign (not bastion's)
    assert ("inet", "bastion") not in d.nft_foreign_tables          # bastion's own, excluded
