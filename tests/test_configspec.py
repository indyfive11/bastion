"""configspec registry + validators + scope/validate engine (pure, no live system)."""
import pytest

from bastion import configspec as cfg
from bastion import state

EXAMPLE = __import__("pathlib").Path(__file__).resolve().parent.parent / "bastion" / "machine.conf.example"


def test_registry_integrity():
    keys = [s.key for s in cfg.SETTINGS]
    assert len(keys) == len(set(keys))                       # no dup keys
    for s in cfg.SETTINGS:
        assert s.key == f"{s.section}.{s.option}"
        assert s.apply in cfg._APPLY_TAGS
        assert s.tier in (cfg.EVERYDAY, cfg.ADVANCED)
        assert callable(s.validator)
        if s.choices:
            assert all(s.validator(c) for c in s.choices)    # every declared choice validates


def test_every_example_value_validates():
    config = state.load_conf(EXAMPLE)
    for s in cfg.SETTINGS:
        v = cfg.current_value(config, s)
        if v:
            norm, err = cfg.validate_value(s, v)
            assert err is None, f"{s.key}={v!r} rejected: {err}"


@pytest.mark.parametrize("key,good,bad", [
    ("ports.ssh", "2222", "99999"),
    ("network.trusted_hosts", "10.0.0.1, 10.0.0.0/8", "not-an-ip"),
    ("network.lan_cidr", "10.0.0.0/24", "10.0.0.0/99"),
    ("network.lan_ip", "10.0.0.1", "10.0.0.999"),
    ("ai.timer_interval", "8h", "8q"),
    ("ai.depth", "expert", "godmode"),
    ("recovery.window_seconds", "900", "-5"),
    ("monitoring.egress_probe", "https://example.com", "ftp:bad"),
    ("monitoring.dnsblock_sources", "https://a/x https://b/y", "noturl"),
    ("network.service_ports", "8096 53/udp 7878/tcp", "8096 99999"),
    ("interfaces.lan", "eth0", "this-iface-name-is-too-long-x"),
    ("machine.firewall_scope", "cooperative", "shared"),
])
def test_validators_accept_good_reject_bad(key, good, bad):
    s = cfg.get(key)
    assert cfg.validate_value(s, good)[1] is None
    assert cfg.validate_value(s, bad)[1] is not None


def test_timer_interval_normalizes():
    s = cfg.get("ai.timer_interval")
    assert cfg.validate_value(s, "8h")[0] == "8h"
    assert cfg.validate_value(s, "  90s ")[0] == "90s"      # normalizer trims


def test_applies_to_scope_and_layer_gate():
    edge = {"machine": {"mode": "edge", "layers": "l0,l1,l3,l4"}}
    endpoint = {"machine": {"mode": "endpoint", "layers": "l0"}}
    # dhcp is edge-only -> hard refuse on an endpoint
    ok, why = cfg.applies_to(cfg.get("network.dhcp_range_start"), endpoint)
    assert ok is False and "edge" in why
    # ai.timer_interval needs l3 -> warns (but proceeds) when l3 is absent
    ok, why = cfg.applies_to(cfg.get("ai.timer_interval"), endpoint)
    assert ok is True and "l3" in why
    # applies cleanly when scope+layer match
    assert cfg.applies_to(cfg.get("network.dhcp_range_start"), edge) == (True, "")
    assert cfg.applies_to(cfg.get("ports.ssh"), endpoint)[0] is True   # both-scope, no gate
    # feed_sources is BOTH-scope (L1 runs in every profile), gated on l1 — unlike edge-only dnsblock:
    # it applies cleanly on an endpoint that has l1, and only warns (never refuses) when l1 is absent.
    ep_l1 = {"machine": {"mode": "endpoint", "layers": "l0,l1"}}
    assert cfg.applies_to(cfg.get("monitoring.feed_sources"), ep_l1) == (True, "")
    ok, why = cfg.applies_to(cfg.get("monitoring.feed_sources"), endpoint)
    assert ok is True and "l1" in why
    assert cfg.applies_to(cfg.get("monitoring.dnsblock_sources"), ep_l1)[0] is False   # edge-only
    # M12: prefer_ipv4 is endpoint-only -> hard refuse on an edge box, applies on an endpoint.
    assert cfg.applies_to(cfg.get("network.prefer_ipv4"), edge)[0] is False
    assert cfg.applies_to(cfg.get("network.prefer_ipv4"), endpoint) == (True, "")


def test_apply_tag_selection():
    assert cfg.get("ports.ssh").apply == cfg.APPLY_GENERATE_FIREWALL
    assert cfg.get("network.dns_upstream").apply == cfg.APPLY_GENERATE_DNSMASQ
    assert cfg.get("ai.timer_interval").apply == cfg.APPLY_GENERATE_AI
    assert cfg.get("monitoring.egress_probe").apply == cfg.APPLY_GENERATE
    assert cfg.get("ai.expert_canary_seconds").apply == cfg.APPLY_NONE
    assert cfg.get("network.prefer_ipv4").apply == cfg.APPLY_GENERATE_PREFER_IPV4


def test_list_helpers():
    assert cfg.list_add("10.0.0.1", "10.0.0.2", ",") == "10.0.0.1, 10.0.0.2"
    assert cfg.list_add("10.0.0.1", "10.0.0.1", ",") == "10.0.0.1"      # idempotent
    assert cfg.list_remove("10.0.0.1, 10.0.0.2", "10.0.0.1", ",") == "10.0.0.2"
    assert cfg.list_add("https://a", "https://b", " ") == "https://a https://b"


def test_h24_failed_render_leaves_conf_unchanged(tmp_path, monkeypatch):
    # H24: apply_change must NOT persist machine.conf when the staged render would fail — a failed
    # apply must leave config == live, never a silent half-applied drift. Simulate ANY render/nft -c
    # failure via the pre-check's generate --check and assert the conf on disk is untouched.
    from bastion import cli
    conf = tmp_path / "machine.conf"
    state.write_conf(state.load_conf(EXAMPLE), conf)
    before = conf.read_text()
    monkeypatch.setattr(cli, "cmd_generate", lambda args: 1)
    res = cfg.apply_change("network.trusted_hosts", "10.9.9.9", conf=str(conf),
                           assume_yes=True, out=lambda *a: None)
    assert res.rc == 1
    assert res.wrote is False
    assert conf.read_text() == before          # not written — no config-vs-live drift


def test_h24_successful_render_writes(tmp_path, monkeypatch):
    # H24 positive: a clean staged render lets the change persist and apply as before.
    from bastion import cli
    conf = tmp_path / "machine.conf"
    state.write_conf(state.load_conf(EXAMPLE), conf)
    monkeypatch.setattr(cli, "cmd_generate", lambda args: 0)   # pre-check + _run_apply both clean
    res = cfg.apply_change("network.trusted_hosts", "10.9.9.9", conf=str(conf), root=str(tmp_path),
                           assume_yes=True, out=lambda *a: None)
    assert res.rc == 0 and res.wrote is True
    assert "10.9.9.9" in state.load_conf(conf).get("network", {}).get("trusted_hosts", "")


def test_h24_apply_none_key_skips_precheck(tmp_path, monkeypatch):
    # H24 refinement: an APPLY_NONE (stored-only) key must NOT be gated by the render pre-check —
    # an unrelated latent render problem must not false-refuse an inert config write. Monkeypatch
    # generate to FAIL and assert it is never called for an APPLY_NONE key (which still persists).
    from bastion import cli
    conf = tmp_path / "machine.conf"
    state.write_conf(state.load_conf(EXAMPLE), conf)     # example has l3 active
    calls = []

    def _boom(args):
        calls.append(1)
        return 1
    monkeypatch.setattr(cli, "cmd_generate", _boom)
    res = cfg.apply_change("ai.expert_canary_seconds", "5", conf=str(conf), root=str(tmp_path),
                           advanced=True, assume_yes=True, out=lambda *a: None)
    assert res.rc == 0 and res.wrote is True
    assert calls == []                          # pre-check skipped for APPLY_NONE
