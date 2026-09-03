"""H27 — the edge ingress DNAT / port-forward primitive ([forwards]).

Covers the renderer (templates._render_forwards), the validate_conf [forwards] block, the offline
`nft -c` load of the real edge template with a forward, and the `bastion forwards` CLI verb.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from bastion import cli, state, templates

TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
EXAMPLE = Path(__file__).resolve().parent.parent / "bastion" / "machine.conf.example"


def _fw(entries, *, mode="edge", wan="ens3"):
    cfg = {"machine": {"mode": mode}, "interfaces": {"wan": wan}, "forwards": entries}
    return templates._derived(cfg)["network"]


# --------------------------------------------------------------------------- renderer

def test_forwards_absent_or_endpoint_renders_blank():
    for key in ("forwards_dnat_rules", "forwards_snat_rules", "forwards_forward_rules"):
        assert templates._derived({"machine": {"mode": "edge"}})["network"][key] == ""
        # a stray [forwards] on an endpoint box renders NOTHING (edge-only, fail-closed)
        assert _fw({"x": "udp/1 -> 10.0.0.1:2"}, mode="endpoint")[key] == ""


def test_forwards_dnat_snat_forward_full():
    net = _fw({"relay": "udp/51822 -> 10.8.0.1:51821 via wg0 snat 10.0.2.1"})
    assert net["forwards_dnat_rules"] == 'iifname "ens3" udp dport 51822 dnat to 10.8.0.1:51821'
    assert net["forwards_snat_rules"] == \
        'oifname "wg0" ip daddr 10.8.0.1 udp dport 51821 snat to 10.0.2.1'
    assert net["forwards_forward_rules"] == (
        'iifname "ens3" ip daddr 10.8.0.1 udp dport 51821 oifname "wg0" '
        "ct state new limit rate over 25/second burst 50 packets drop\n"
        '        iifname "ens3" ip daddr 10.8.0.1 udp dport 51821 oifname "wg0" accept')


def test_forwards_lan_host_no_via_no_snat():
    # A plain LAN-host forward: no via, no snat → DNAT + forward accept, NO snat rule, no oifname.
    net = _fw({"web": "tcp/8080 -> 192.168.1.50:80"})
    assert net["forwards_dnat_rules"] == 'iifname "ens3" tcp dport 8080 dnat to 192.168.1.50:80'
    assert net["forwards_snat_rules"] == ""
    assert 'oifname' not in net["forwards_forward_rules"]
    assert net["forwards_forward_rules"].endswith(
        'iifname "ens3" ip daddr 192.168.1.50 tcp dport 80 accept')


def test_forwards_blank_wan_vanishes_all_three_groups():
    # A blank interfaces.wan must vanish the whole entry — never render `iifname ""` (nft-fatal).
    net = _fw({"relay": "udp/51822 -> 10.8.0.1:51821 via wg0 snat 10.0.2.1"}, wan="")
    assert net["forwards_dnat_rules"] == ""
    assert net["forwards_snat_rules"] == ""
    assert net["forwards_forward_rules"] == ""


def test_forwards_dedups_identical_rules():
    net = _fw({"a": "udp/51822 -> 10.8.0.1:51821", "b": "udp/51822 -> 10.8.0.1:51821"})
    assert net["forwards_dnat_rules"] == 'iifname "ens3" udp dport 51822 dnat to 10.8.0.1:51821'


def test_forwards_proto_lowercased():
    assert _fw({"x": "UDP/53 -> 10.0.0.1:53"})["forwards_dnat_rules"] == \
        'iifname "ens3" udp dport 53 dnat to 10.0.0.1:53'


def test_forwards_derived_not_written_back():
    cfg = {"machine": {"mode": "edge"}, "interfaces": {"wan": "ens3"},
           "forwards": {"r": "udp/1 -> 10.0.0.1:2"}}
    templates._derived(cfg)
    assert "forwards_dnat_rules" not in cfg["forwards"]  # augments a copy only


# --------------------------------------------------------------------------- validate_conf

def _errs(value, *, mode="edge"):
    cfg = {"machine": {"mode": mode}, "interfaces": {"wan": "ens3"},
           "ports": {"ssh": "1111"}, "forwards": {"f": value}}
    return state.validate_conf(cfg)


def test_validate_good_forward_clean():
    errs, warns = _errs("udp/51822 -> 10.8.0.1:51821 via wg0 snat 10.0.2.1")
    assert errs == [] and warns == []


@pytest.mark.parametrize("value", [
    "udp/1 10.0.0.1:2",                 # missing ->
    "sctp/1 -> 10.0.0.1:2",             # bad proto
    "udp/70000 -> 10.0.0.1:2",          # wan port out of range
    "udp/1 -> 10.0.0.1",               # missing dest port
    "udp/1 -> 10.0.0.1:70000",          # dest port out of range
    "udp/1 -> not-an-ip:2",             # bad dest ip
    "udp/1 -> 127.0.0.1:2",             # loopback dest (routes to input, silently fails)
    "udp/1 -> 10.0.0.1:2 snat 10.0.0.9",   # snat without via → oifname "" trap
    "udp/1 -> 10.0.0.1:2 via wg0 snat nope",  # bad snat ip
    "udp/1 -> 10.0.0.1:2 via toolonginterfacename",  # bad iface
    "udp/1 -> 10.0.0.1:2 bogus tok",    # unexpected trailing token
])
def test_validate_rejects_bad_forward(value):
    errs, _ = _errs(value)
    assert errs, f"expected a validation error for {value!r}"


def test_validate_snat_without_via_names_the_trap():
    errs, _ = _errs("udp/1 -> 10.0.0.1:2 snat 10.0.0.9")
    assert any("requires 'via" in e for e in errs)


def test_validate_edge_only_warns_on_endpoint():
    _, warns = _errs("udp/1 -> 10.0.0.1:2", mode="endpoint")
    assert any("edge-only" in w for w in warns)


def test_validate_warns_on_ssh_port_hijack():
    # wan_dport == ports.ssh → DNAT (prerouting, before input) steals the box's own inbound SSH.
    _, warns = _errs("tcp/1111 -> 192.168.1.9:1111")
    assert any("SSH" in w for w in warns)


# --------------------------------------------------------------------------- offline nft load

def _nft_check(text: str):
    if not (shutil.which("nft") and shutil.which("unshare")):
        return False, True, ""
    p = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", "-"],
                       input=text, capture_output=True, text=True)
    return True, p.returncode == 0, p.stderr


def test_edge_template_with_forwards_loads_and_orders():
    cfg = state.load_conf(EXAMPLE)              # mode=edge
    cfg["forwards"] = {"relay": "udp/51822 -> 10.8.0.1:51821 via wg0 snat 10.0.2.1",
                       "web": "tcp/8080 -> 192.168.1.50:80"}
    out = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    assert templates.find_placeholders(out) == set()
    lines = out.splitlines()
    # ordering invariant: the forward accept renders BELOW the block-set drops (bans bite first).
    ban = next(i for i, ln in enumerate(lines) if "@cs_block drop" in ln)
    acc = next(i for i, ln in enumerate(lines) if "daddr 10.8.0.1" in ln and "accept" in ln)
    assert ban < acc
    # and the fixed SNAT renders BEFORE the catch-all `oifname wan masquerade`.
    snat = next(i for i, ln in enumerate(lines) if "snat to 10.0.2.1" in ln)
    masq = next(i for i, ln in enumerate(lines) if 'oifname "eth1" masquerade' in ln)
    assert snat < masq
    ran, ok, err = _nft_check(out)
    assert ok, f"edge template with forwards failed nft -c: {err}"


def test_edge_template_no_forwards_still_loads():
    cfg = state.load_conf(EXAMPLE)
    out = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    assert templates.find_placeholders(out) == set()
    ran, ok, err = _nft_check(out)
    assert ok, f"edge template (empty prerouting chain) failed nft -c: {err}"


# --------------------------------------------------------------------------- CLI

@pytest.fixture
def staged(tmp_path):
    root = tmp_path / "tree"
    (root / "etc/bastion").mkdir(parents=True)
    (root / "etc/bastion/machine.conf").write_text(EXAMPLE.read_text())
    return root


def _conf_of(root):
    return state.load_conf(root / "etc/bastion/machine.conf")


def test_forwards_add_list_remove(staged, capsys):
    assert cli.main(["forwards", "add", "relay", "udp/51822", "10.8.0.1:51821",
                     "--via", "wg0", "--snat", "10.0.2.1", "--root", str(staged)]) == 0
    assert _conf_of(staged)["forwards"]["relay"] == "udp/51822 -> 10.8.0.1:51821 via wg0 snat 10.0.2.1"
    assert cli.main(["forwards", "list", "--root", str(staged)]) == 0
    assert "relay" in capsys.readouterr().out
    assert cli.main(["forwards", "remove", "relay", "--root", str(staged)]) == 0
    assert "forwards" not in _conf_of(staged) or "relay" not in _conf_of(staged).get("forwards", {})


def test_forwards_add_lan_host_no_flags(staged):
    assert cli.main(["forwards", "add", "web", "tcp/8080", "192.168.1.50:80",
                     "--root", str(staged)]) == 0
    assert _conf_of(staged)["forwards"]["web"] == "tcp/8080 -> 192.168.1.50:80"


def test_forwards_add_shows_dnat_delta(staged, capsys):
    assert cli.main(["forwards", "add", "relay", "udp/51822", "10.8.0.1:51821",
                     "--via", "wg0", "--snat", "10.0.2.1", "--root", str(staged)]) == 0
    out = capsys.readouterr().out
    assert "ruleset delta:" in out
    assert "+ iifname" in out and "dnat to 10.8.0.1:51821" in out


def test_forwards_snat_without_via_rejected(staged):
    assert cli.main(["forwards", "add", "bad", "udp/51822", "10.8.0.1:51821",
                     "--snat", "10.0.2.1", "--root", str(staged)]) == 1
    assert "forwards" not in _conf_of(staged)          # nothing written


def test_forwards_dry_run_writes_nothing(staged, capsys):
    assert cli.main(["forwards", "add", "web", "tcp/8080", "192.168.1.50:80",
                     "--dry-run", "--root", str(staged)]) == 0
    assert "NOT written" in capsys.readouterr().out
    assert "web" not in _conf_of(staged).get("forwards", {})


def test_forwards_remove_unknown_no_change(staged, capsys):
    assert cli.main(["forwards", "remove", "ghost", "--root", str(staged)]) == 0
    assert "no change" in capsys.readouterr().out
