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
    ("interfaces.lan", "eth0", "this-iface-name-is-too-long-x"),
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


def test_apply_tag_selection():
    assert cfg.get("ports.ssh").apply == cfg.APPLY_GENERATE_FIREWALL
    assert cfg.get("network.dns_upstream").apply == cfg.APPLY_GENERATE_DNSMASQ
    assert cfg.get("ai.timer_interval").apply == cfg.APPLY_GENERATE_AI
    assert cfg.get("monitoring.egress_probe").apply == cfg.APPLY_GENERATE
    assert cfg.get("ai.expert_canary_seconds").apply == cfg.APPLY_NONE


def test_list_helpers():
    assert cfg.list_add("10.0.0.1", "10.0.0.2", ",") == "10.0.0.1, 10.0.0.2"
    assert cfg.list_add("10.0.0.1", "10.0.0.1", ",") == "10.0.0.1"      # idempotent
    assert cfg.list_remove("10.0.0.1, 10.0.0.2", "10.0.0.1", ",") == "10.0.0.2"
    assert cfg.list_add("https://a", "https://b", " ") == "https://a https://b"
