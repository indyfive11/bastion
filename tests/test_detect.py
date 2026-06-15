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
