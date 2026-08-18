"""`bastion config` CLI — list/get/describe/set, validation, scope, Advanced gating, and the
SCOPED apply (a DNS change must not reload the firewall). The generate + reload steps are
monkeypatched so the test never touches the live system; we assert WHICH step each key triggers.
"""
import types
from pathlib import Path

import pytest

from bastion import cli, state
from bastion.system import System

EXAMPLE = Path(__file__).resolve().parent.parent / "bastion" / "machine.conf.example"


@pytest.fixture
def conf(tmp_path):
    p = tmp_path / "machine.conf"
    p.write_text(EXAMPLE.read_text())
    return p


@pytest.fixture
def recorded(monkeypatch):
    """Capture the apply steps without running them."""
    calls = []
    monkeypatch.setattr(cli, "cmd_generate", lambda ns: calls.append(("generate", ns.out)) or 0)
    monkeypatch.setattr(cli, "cmd_firewall", lambda ns: calls.append(("firewall", ns.action)) or 0)
    monkeypatch.setattr(cli, "cmd_ai", lambda ns: calls.append(("ai", ns.action)) or 0)
    monkeypatch.setattr(System, "run", lambda self, *a, **k:
                        calls.append(("run", a)) or types.SimpleNamespace(returncode=0, stdout="", stderr=""))
    return calls


def test_list_get_describe(conf, capsys):
    assert cli.main(["config", "list", "--conf", str(conf)]) == 0
    out = capsys.readouterr().out
    assert "ports.ssh" in out and "network.lan_cidr" not in out      # Advanced hidden by default
    assert cli.main(["config", "list", "--advanced", "--conf", str(conf)]) == 0
    assert "network.lan_cidr" in capsys.readouterr().out             # revealed with --advanced
    assert cli.main(["config", "get", "ai.timer_interval", "--conf", str(conf)]) == 0
    assert capsys.readouterr().out.strip() == "4h"
    assert cli.main(["config", "describe", "ports.ssh", "--conf", str(conf)]) == 0
    assert "reloads the firewall" in capsys.readouterr().out


def test_set_everyday_scoped_reload(conf, recorded):
    assert cli.main(["config", "set", "ports.ssh", "2222", "--conf", str(conf)]) == 0
    assert state.load_conf(conf)["ports"]["ssh"] == "2222"            # written
    assert ("firewall", "reload") in recorded                        # ssh -> firewall reload
    assert not any(c[0] == "ai" for c in recorded)                   # ...and NOT the ai re-arm


def test_dns_change_does_not_reload_firewall(conf, recorded):
    assert cli.main(["config", "set", "network.dns_upstream", "9.9.9.9#53", "--conf", str(conf)]) == 0
    assert ("run", ("systemctl", "reload", "dnsmasq")) in recorded   # dns -> dnsmasq reload
    assert not any(c[0] == "firewall" for c in recorded)             # the key invariant


def test_ai_interval_rearms(conf, recorded):
    assert cli.main(["config", "set", "ai.timer_interval", "8h", "--conf", str(conf)]) == 0
    assert ("ai", "enable") in recorded


def test_egress_probe_generate_only(conf, recorded):
    assert cli.main(["config", "set", "monitoring.egress_probe", "https://x.example", "--conf", str(conf)]) == 0
    assert any(c[0] == "generate" for c in recorded)
    assert not any(c[0] in ("firewall", "ai") for c in recorded)
    assert not any(c[0] == "run" for c in recorded)


def test_bad_value_blocked_before_write(conf, recorded):
    before = conf.read_text()
    assert cli.main(["config", "set", "ports.ssh", "99999", "--conf", str(conf)]) == 1
    assert conf.read_text() == before                                # file untouched
    assert recorded == []                                            # no apply ran


def test_scope_refusal_on_endpoint(conf, recorded):
    c = state.load_conf(conf); c["machine"]["mode"] = "endpoint"; state.write_conf(c, conf)
    assert cli.main(["config", "set", "network.dhcp_range_start", "10.0.1.50", "--conf", str(conf)]) == 1
    assert not any(x[0] == "generate" for x in recorded)


def test_advanced_gating(conf, recorded):
    assert cli.main(["config", "set", "network.lan_ip", "10.0.1.9", "--conf", str(conf)]) == 1   # gated
    assert state.load_conf(conf)["network"]["lan_ip"] != "10.0.1.9"
    assert cli.main(["config", "set", "network.lan_ip", "10.0.1.9", "--advanced", "--conf", str(conf)]) == 0
    assert state.load_conf(conf)["network"]["lan_ip"] == "10.0.1.9"


def test_dry_run_writes_nothing(conf, recorded):
    before = conf.read_text()
    assert cli.main(["config", "set", "ports.ssh", "2222", "--dry-run", "--conf", str(conf)]) == 0
    assert conf.read_text() == before
    assert recorded == []


# --------------------------------------------------------------------------- Phase 2 verbs
@pytest.fixture
def staged(tmp_path):
    """A staged --root tree (conf under <root>/etc/bastion); live reloads are skipped, generate
    writes into the tree — so the verbs run end-to-end without touching the host."""
    root = tmp_path / "tree"
    (root / "etc/bastion").mkdir(parents=True)
    (root / "etc/bastion/machine.conf").write_text(EXAMPLE.read_text())
    return root


def _conf_of(root):
    return state.load_conf(root / "etc/bastion/machine.conf")


def test_ai_set_interval_and_depth(staged):
    assert cli.main(["ai", "set-interval", "6h", "--root", str(staged)]) == 0
    assert _conf_of(staged)["ai"]["timer_interval"] == "6h"
    assert cli.main(["ai", "set-depth", "expert", "--root", str(staged)]) == 0
    assert _conf_of(staged)["ai"]["depth"] == "expert"
    assert cli.main(["ai", "set-depth", "godmode", "--root", str(staged)]) == 1   # bad choice


def test_allow_deny_list(staged, capsys):
    assert cli.main(["allow", "10.9.9.9", "--root", str(staged)]) == 0
    assert "10.9.9.9" in _conf_of(staged)["network"]["trusted_hosts"]
    capsys.readouterr()
    assert cli.main(["allow", "--list", "--root", str(staged)]) == 0
    assert "10.9.9.9" in capsys.readouterr().out
    assert cli.main(["deny", "10.9.9.9", "--root", str(staged)]) == 0
    assert "10.9.9.9" not in _conf_of(staged)["network"]["trusted_hosts"]


def test_dns_upstream_get_set(staged, capsys):
    assert cli.main(["dns", "upstream", "--root", str(staged)]) == 0
    assert capsys.readouterr().out.strip() == "127.0.0.1#5335"
    assert cli.main(["dns", "upstream", "9.9.9.9#53", "--root", str(staged)]) == 0
    assert _conf_of(staged)["network"]["dns_upstream"] == "9.9.9.9#53"


def test_dnsblock_add_list_remove(staged, capsys):
    assert cli.main(["dnsblock", "add", "https://ex.com/h", "--root", str(staged)]) == 0
    assert "https://ex.com/h" in _conf_of(staged)["monitoring"]["dnsblock_sources"]
    capsys.readouterr()
    assert cli.main(["dnsblock", "list", "--root", str(staged)]) == 0
    assert "https://ex.com/h" in capsys.readouterr().out
    assert cli.main(["dnsblock", "remove", "https://ex.com/h", "--root", str(staged)]) == 0
    assert "https://ex.com/h" not in (_conf_of(staged)["monitoring"].get("dnsblock_sources") or "")


def test_feeds_add_list_remove(staged, capsys):
    assert cli.main(["feeds", "add", "https://ex.com/ips.netset", "--root", str(staged)]) == 0
    assert "https://ex.com/ips.netset" in _conf_of(staged)["monitoring"]["feed_sources"]
    capsys.readouterr()
    assert cli.main(["feeds", "list", "--root", str(staged)]) == 0
    assert "https://ex.com/ips.netset" in capsys.readouterr().out
    assert cli.main(["feeds", "remove", "https://ex.com/ips.netset", "--root", str(staged)]) == 0
    assert "https://ex.com/ips.netset" not in (_conf_of(staged)["monitoring"].get("feed_sources") or "")


def test_feeds_bad_url_rejected(staged):
    assert cli.main(["feeds", "add", "not-a-url", "--root", str(staged)]) == 1
    assert not (_conf_of(staged)["monitoring"].get("feed_sources") or "")   # nothing written


def test_zones_add_list_remove(staged, capsys):
    assert cli.main(["zones", "add", "lan", "192.168.1.0/24", "8096", "8989", "--root", str(staged)]) == 0
    assert _conf_of(staged)["zones"]["lan"] == "192.168.1.0/24 -> 8096 8989"
    capsys.readouterr()
    assert cli.main(["zones", "list", "--root", str(staged)]) == 0
    assert "lan = 192.168.1.0/24 -> 8096 8989" in capsys.readouterr().out
    assert cli.main(["zones", "remove", "lan", "--root", str(staged)]) == 0
    assert "zones" not in _conf_of(staged) or "lan" not in _conf_of(staged).get("zones", {})


def test_zones_add_iface_all(staged):
    assert cli.main(["zones", "add", "vms", "iface:virbr0", "all", "--root", str(staged)]) == 0
    assert _conf_of(staged)["zones"]["vms"] == "iface:virbr0 -> all"


def test_zones_bad_source_rejected(staged):
    assert cli.main(["zones", "add", "bad", "not-an-ip", "8096", "--root", str(staged)]) == 1
    assert "zones" not in _conf_of(staged)              # nothing written


def test_zones_remove_unknown_no_change(staged, capsys):
    assert cli.main(["zones", "remove", "ghost", "--root", str(staged)]) == 0
    assert "no change" in capsys.readouterr().out


# --------------------------------------------------------------------------- M-E safe-apply envelope
def test_zones_add_shows_rule_delta(staged, capsys):
    assert cli.main(["zones", "add", "mon", "192.168.9.9", "9090", "--root", str(staged)]) == 0
    out = capsys.readouterr().out
    assert "ruleset delta:" in out
    assert "+ ip saddr 192.168.9.9 tcp dport { 9090 } accept" in out


def test_zones_dry_run_writes_nothing(staged, capsys):
    assert cli.main(["zones", "add", "mon", "192.168.9.9", "9090", "--dry-run", "--root", str(staged)]) == 0
    out = capsys.readouterr().out
    assert "+ ip saddr 192.168.9.9 tcp dport { 9090 } accept" in out
    assert "NOT written" in out and "NOT reloaded" in out
    assert "mon" not in _conf_of(staged).get("zones", {})          # nothing persisted


def test_zones_remove_delta_not_a_clobber(staged, capsys):
    """A legitimate remove shows the removed rule in the delta but must NOT trip the clobber gate
    (which is about live-kernel drift, not operator-intended removals)."""
    assert cli.main(["zones", "add", "lan", "192.168.1.0/24", "8096", "--root", str(staged)]) == 0
    capsys.readouterr()
    assert cli.main(["zones", "remove", "lan", "--root", str(staged)]) == 0
    out = capsys.readouterr().out
    assert "- ip saddr 192.168.1.0/24 tcp dport { 8096 } accept" in out
    assert "DISCARD those live-only rules" not in out              # no clobber warning on a normal remove


def test_zones_clobber_gate_refuses_noninteractive(staged, monkeypatch, capsys):
    """When the live kernel diverges (H6 _ruleset_stale True), a non-interactive add refuses and
    writes nothing unless --yes is given."""
    monkeypatch.setattr(cli, "_ruleset_stale", lambda ctx: (True, "inet bastion"))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["zones", "add", "mon", "192.168.9.9", "9090", "--root", str(staged)]) == 1
    assert "mon" not in _conf_of(staged).get("zones", {})          # refused → nothing written
    assert "refusing to clobber" in capsys.readouterr().err
    # --yes overrides the gate and the change lands.
    assert cli.main(["zones", "add", "mon", "192.168.9.9", "9090", "--yes", "--root", str(staged)]) == 0
    assert _conf_of(staged)["zones"]["mon"] == "192.168.9.9 -> 9090"


def _warns(zones, ssh="22", mode="endpoint"):
    cfg = {"machine": {"mode": mode}, "ports": {"ssh": ssh}, "zones": zones}
    _errs, warns = state.validate_conf(cfg)
    return [w for w in warns if "exposes" in w]


def test_zones_public_ssh_exposure_warning():
    # WARN: default route / any / public subnet granting SSH; ALL-ports variant.
    assert any("ENTIRE internet" in w and "SSH (tcp/22)" in w for w in _warns({"z": "0.0.0.0/0 -> 22"}))
    assert any("ENTIRE internet" in w for w in _warns({"z": "any -> 22"}))
    assert any("public subnet (8.8.8.0/24)" in w for w in _warns({"z": "8.8.8.0/24 -> 22"}))
    assert any("ALL listening services" in w for w in _warns({"z": "0.0.0.0/0 -> all"}))
    assert any("SSH (tcp/1111)" in w for w in _warns({"z": "0.0.0.0/0 -> 1111"}, ssh="1111"))
    # NO WARN: local iface, pinned public /32 (jump host), private subnet, udp-only, non-ssh port.
    assert not _warns({"z": "iface:lan -> 22"})
    assert not _warns({"z": "1.1.1.1/32 -> 22"})
    assert not _warns({"z": "192.168.1.0/24 -> 22"})
    assert not _warns({"z": "0.0.0.0/0 -> 22/udp"})               # ssh is tcp; udp/22 does not grant it
    assert not _warns({"z": "0.0.0.0/0 -> 8096"})                 # public, but not the ssh port


def test_layer_disable_delists(staged):
    assert cli.main(["layer", "disable", "l4", "--root", str(staged)]) == 0
    assert "l4" not in _conf_of(staged)["machine"]["layers"].split(",")


def test_layer_disable_blocked_by_dependent(staged):
    # install l0 + l1 into the tree so l1 (which depends on l0) reports installed
    sc = str(staged / "etc/bastion/machine.conf")
    cli.main(["layer", "install", "l0", "--conf", sc, "--root", str(staged)])
    cli.main(["layer", "install", "l1", "--conf", sc, "--root", str(staged)])
    assert cli.main(["layer", "disable", "l0", "--root", str(staged)]) == 1   # l1 still depends on l0
    assert "l0" in _conf_of(staged)["machine"]["layers"].split(",")           # not delisted
