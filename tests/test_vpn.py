"""WireGuard / ZeroTier setup (setup/vpn_setup.py + wizard._wg_configure / _zt_join_step).

Keygen (via an injected fake `wg`), the complete-config render, the chmod-600 write (root-prefixed,
never machine.conf), reuse-on-reinstall, and the ZeroTier join — all offline with a fake System.
Keys here are short non-base64 placeholders so `make leak-check` (44-char base64) stays clean.
"""
import stat
import subprocess
from pathlib import Path

from bastion import state
from bastion.setup import vpn_setup, wizard
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"


class FakeWg(System):
    """Live-ish System rooted at a temp dir: real file IO, but `wg`/`zerotier-cli` are faked."""
    def __init__(self, root, *, have_wg=True, priv="PRIV-KEY", pub="PUB-KEY", zt_rc=0):
        super().__init__(root=root)
        self._have_wg, self._priv, self._pub, self._zt_rc = have_wg, priv, pub, zt_rc
        self.calls = []

    def command_exists(self, name):
        return name == "wg" and self._have_wg

    def run(self, *args, capture=True, input=None):
        self.calls.append((args, input))
        if args[:2] == ("wg", "genkey"):
            return subprocess.CompletedProcess(args, 0, self._priv + "\n", "")
        if args[:2] == ("wg", "pubkey"):
            return subprocess.CompletedProcess(args, 0, self._pub + "\n", "")
        if args[:2] == ("zerotier-cli", "join"):
            return subprocess.CompletedProcess(args, self._zt_rc, "", "")
        return subprocess.CompletedProcess(args, 1, "", "")


# --- pure render / keygen / write ------------------------------------------

def test_wg_keypair_derives_pub_from_priv_via_stdin(tmp_path):
    sys_ = FakeWg(tmp_path)
    kp = vpn_setup.wg_keypair(sys_)
    assert kp == ("PRIV-KEY", "PUB-KEY")
    # `wg pubkey` must receive the private key on stdin
    pubkey_call = [c for c in sys_.calls if c[0][:2] == ("wg", "pubkey")][0]
    assert pubkey_call[1] == "PRIV-KEY\n"


def test_wg_keypair_none_when_wg_absent(tmp_path):
    assert vpn_setup.wg_keypair(FakeWg(tmp_path, have_wg=False)) is None


def test_render_client_conf_has_endpoint_and_keepalive():
    c = vpn_setup.WgConf(private_key="P", address="10.99.0.2/32", peer_public_key="PEER",
                         allowed_ips="0.0.0.0/0", peer_endpoint="vps.example.net:51820")
    body = vpn_setup.render_wg_conf(c)
    assert "PrivateKey = P" in body
    assert "Address = 10.99.0.2/32" in body
    assert "Endpoint = vps.example.net:51820" in body
    assert "AllowedIPs = 0.0.0.0/0" in body
    assert "PersistentKeepalive = 25" in body
    assert "ListenPort" not in body          # no listen port on a pure client


def test_render_server_conf_omits_endpoint_and_keepalive():
    c = vpn_setup.WgConf(private_key="P", address="10.8.0.1/24", peer_public_key="PEER",
                         allowed_ips="10.8.0.2/32", listen_port="51820")
    body = vpn_setup.render_wg_conf(c)
    assert "ListenPort = 51820" in body
    assert "Endpoint" not in body            # clients dial in to the server
    assert "PersistentKeepalive" not in body  # only emitted with an endpoint


def test_render_conf_includes_mtu_when_set():
    c = vpn_setup.WgConf(private_key="P", address="10.8.0.1/24", peer_public_key="PEER",
                         allowed_ips="10.8.0.2/32", mtu="1340")
    body = vpn_setup.render_wg_conf(c)
    assert "MTU = 1340" in body
    assert body.index("MTU") < body.index("[Peer]")   # MTU is an [Interface] directive


def test_render_conf_omits_mtu_when_blank():
    c = vpn_setup.WgConf(private_key="P", address="10.8.0.1/24", peer_public_key="PEER",
                         allowed_ips="10.8.0.2/32")
    assert "MTU" not in vpn_setup.render_wg_conf(c)


def test_write_wg_conf_chmod_600_rooted(tmp_path):
    sys_ = System(root=tmp_path)
    c = vpn_setup.WgConf(private_key="P", address="10.8.0.1/24", peer_public_key="PEER",
                         allowed_ips="10.8.0.2/32")
    rel = vpn_setup.write_wg_conf(sys_, "wg0", c)
    dest = tmp_path / "etc/wireguard/wg0.conf"
    assert rel == "/etc/wireguard/wg0.conf"
    assert dest.is_file() and stat.S_IMODE(dest.stat().st_mode) == 0o600


def test_default_server_address():
    assert vpn_setup.default_server_address("10.8.0.0/24") == "10.8.0.1/24"
    assert vpn_setup.default_server_address("not-a-cidr") == ""


# --- wizard _wg_configure / _zt_join_step ----------------------------------

def _conf(**overrides):
    c = state.load_conf(EXAMPLE)
    for sec, kv in overrides.items():
        c.setdefault(sec, {}).update(kv)
    return c


def _wizard(sys_, *, inp, assume_defaults=False):
    return wizard.Wizard(sys_, dry_run=False, profile="full-edge", assume_defaults=assume_defaults,
                         inp=inp, secret_inp=lambda *_: "", example_conf=str(EXAMPLE))


def _responder(mapping):
    def inp(prompt):
        for needle, value in mapping.items():
            if needle in prompt:
                return value
        return ""
    return inp


def test_wg_configure_writes_both_interfaces(tmp_path):
    sys_ = FakeWg(tmp_path)
    inp = _responder({
        "wg0 peer public key": "PEER0", "wg0 AllowedIPs": "10.8.0.2/32",
        "wg_vps Address": "10.99.0.2/32", "wg_vps peer public key": "PEERVPS",
        "wg_vps peer Endpoint": "vps.example.net:51820",
    })
    notes = _wizard(sys_, inp=inp)._wg_configure(_conf())
    assert notes == []

    server = (tmp_path / "etc/wireguard/wg0.conf").read_text()
    assert "Address = 10.8.0.1/24" in server          # default from wg_server_cidr 10.8.0.0/24
    assert "ListenPort = 51820" in server
    assert "PublicKey = PEER0" in server
    assert "AllowedIPs = 10.8.0.2/32" in server
    assert "Endpoint" not in server

    client = (tmp_path / "etc/wireguard/wg_vps.conf").read_text()
    assert "Address = 10.99.0.2/32" in client
    assert "Endpoint = vps.example.net:51820" in client
    assert "AllowedIPs = 0.0.0.0/0" in client          # client default
    assert "PersistentKeepalive = 25" in client
    # secret WG material never touches machine.conf
    assert not (tmp_path / "etc/bastion/machine.conf").exists()


def test_wg_configure_passes_mtu_through(tmp_path):
    sys_ = FakeWg(tmp_path)
    inp = _responder({
        "wg0 peer public key": "PEER0", "wg0 AllowedIPs": "10.8.0.2/32", "wg0 MTU": "1340",
        "wg_vps Address": "10.99.0.2/32", "wg_vps peer public key": "PV",
        "wg_vps peer Endpoint": "h:1",
    })
    _wizard(sys_, inp=inp)._wg_configure(_conf())
    assert "MTU = 1340" in (tmp_path / "etc/wireguard/wg0.conf").read_text()
    # wg_vps got no MTU answer -> auto-derive (no MTU line)
    assert "MTU" not in (tmp_path / "etc/wireguard/wg_vps.conf").read_text()


def test_wg_configure_reuses_existing_conf(tmp_path):
    existing = tmp_path / "etc/wireguard/wg0.conf"
    existing.parent.mkdir(parents=True)
    existing.write_text("[Interface]\nPrivateKey = KEEP\n")
    sys_ = FakeWg(tmp_path)
    # wg_vps still configured fresh; wg0 must be left untouched.
    inp = _responder({"wg_vps Address": "10.99.0.2/32", "wg_vps peer public key": "PV",
                      "wg_vps peer Endpoint": "h:1"})
    _wizard(sys_, inp=inp)._wg_configure(_conf())
    assert existing.read_text() == "[Interface]\nPrivateKey = KEEP\n"   # untouched, key preserved
    # exactly one keypair generated (for wg_vps) — the reused wg0 didn't trigger one.
    assert [c[0][:2] for c in sys_.calls].count(("wg", "genkey")) == 1
    assert (tmp_path / "etc/wireguard/wg_vps.conf").is_file()


def test_wg_configure_skips_when_no_peer_key(tmp_path):
    sys_ = FakeWg(tmp_path)
    # Only the server iface present; no peer key entered -> no conf, a note instead.
    conf = _conf(interfaces={"wg_server_iface": "wg0", "wg_vps_iface": ""})
    notes = _wizard(sys_, inp=lambda *_: "")._wg_configure(conf)
    assert any("wg0" in n and "no peer public key" in n for n in notes)
    assert not (tmp_path / "etc/wireguard/wg0.conf").exists()


def test_wg_configure_wg_unavailable_notes(tmp_path):
    sys_ = FakeWg(tmp_path, have_wg=False)
    conf = _conf(interfaces={"wg_server_iface": "wg0", "wg_vps_iface": ""})
    notes = _wizard(sys_, inp=lambda *_: "x")._wg_configure(conf)
    assert any("wg tool unavailable" in n for n in notes)


def test_wg_configure_non_interactive_skips(tmp_path):
    sys_ = FakeWg(tmp_path)
    notes = _wizard(sys_, inp=lambda *_: "x", assume_defaults=True)._wg_configure(_conf())
    assert notes and "non-interactive" in notes[0].lower()
    assert not (tmp_path / "etc/wireguard/wg0.conf").exists()


def test_wg_configure_no_l5_is_noop(tmp_path):
    sys_ = FakeWg(tmp_path)
    conf = _conf(machine={"layers": "l0,l1,l6"})
    assert _wizard(sys_, inp=lambda *_: "x")._wg_configure(conf) == []
    assert not (tmp_path / "etc/wireguard/wg0.conf").exists()


def test_zt_join_success(tmp_path):
    sys_ = FakeWg(tmp_path)
    notes = _wizard(sys_, inp=_responder({"ZeroTier network ID": "abc123def456"}))._zt_join_step(_conf())
    assert notes == []
    assert (("zerotier-cli", "join", "abc123def456"), None) in sys_.calls


def test_zt_join_blank_skips(tmp_path):
    sys_ = FakeWg(tmp_path)
    notes = _wizard(sys_, inp=lambda *_: "")._zt_join_step(_conf())
    assert notes == []
    assert not any(c[0][:2] == ("zerotier-cli", "join") for c in sys_.calls)


def test_zt_join_failure_notes(tmp_path):
    sys_ = FakeWg(tmp_path, zt_rc=1)
    notes = _wizard(sys_, inp=_responder({"ZeroTier network ID": "n"}))._zt_join_step(_conf())
    assert any("ZeroTier join failed" in n for n in notes)


def test_zt_join_non_interactive_skips(tmp_path):
    sys_ = FakeWg(tmp_path)
    notes = _wizard(sys_, inp=lambda *_: "x", assume_defaults=True)._zt_join_step(_conf())
    assert notes == []
    assert not any(c[0][:2] == ("zerotier-cli", "join") for c in sys_.calls)
