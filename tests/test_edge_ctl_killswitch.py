"""D6 — the kill switch reaches both families, but a missing IPv6 sibling is not a failure.

A node whose nft ruleset predates the IPv6 sets legitimately lacks the `…6` sets; flushing a
v6 set that isn't there must NOT make `panic`/`ai-disable` report failure. A missing MANDATORY
v4 set still does (the managed sets shouldn't have vanished).
"""
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-ctl"


def _load():
    loader = SourceFileLoader("edge_ctl_ks_mod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("edge_ctl_ks_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture
def ctl():
    return _load()


def test_ai_sets_cover_both_families(ctl):
    assert ctl.AI_SETS_V4 == ["ai_block", "ai_ratelimit", "ai_tarpit"]
    assert ctl.AI_SETS6 == ["ai_block6", "ai_ratelimit6", "ai_tarpit6"]
    assert ctl.AI_SETS == ctl.AI_SETS_V4 + ctl.AI_SETS6


def test_set_absent_detects_missing(ctl):
    assert ctl._set_absent("Error: set 'ai_block6' does not exist in table inet edge")
    assert ctl._set_absent("Error: No such file or directory")
    assert not ctl._set_absent("Error: permission denied")
    assert not ctl._set_absent("")


def test_absent_v6_sibling_is_not_a_failure(ctl):
    res = {"ai_block": "flushed", "ai_block6": "absent", "ai_tarpit6": "absent"}
    assert ctl._flush_failures(res) == []


def test_absent_v4_set_is_a_failure(ctl):
    assert ctl._flush_failures({"ai_block": "absent"}) == ["ai_block"]


def test_real_error_on_either_family_fails(ctl):
    res = {"ai_block": "flushed", "ai_ratelimit6": "ERR:boom"}
    assert ctl._flush_failures(res) == ["ai_ratelimit6"]


def test_flush_classifies_results(ctl, monkeypatch):
    # missing v6 sets -> "absent"; present v4 sets -> "flushed".
    class P:
        def __init__(self, rc, err=""):
            self.returncode, self.stderr, self.stdout = rc, err, ""

    def fake_nft(*args):
        setname = args[-1]
        if setname.endswith("6"):
            return P(1, f"Error: set '{setname}' does not exist")
        return P(0)

    monkeypatch.setattr(ctl, "nft", fake_nft)
    res = ctl.flush_ai_sets()
    assert res["ai_block"] == "flushed" and res["ai_block6"] == "absent"
    assert ctl._flush_failures(res) == []   # clean v4 flush + absent v6 == success
