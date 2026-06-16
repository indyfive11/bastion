"""D6 — edge-reconciler IPv6 parity: per-family validation/floors + routing to the `…6` sets.

edge-reconciler is a standalone root script; load it as a module (top level only reads NFT_TABLE
from the env with a fallback, so import is side-effect-free) and exercise its pure logic with no
root and no nft.
"""
import importlib.util
import ipaddress
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-reconciler"


def _load():
    loader = SourceFileLoader("edge_reconciler_mod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("edge_reconciler_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture
def rec():
    return _load()


@pytest.fixture
def allow():
    return [ipaddress.ip_network(x) for x in
            ("127.0.0.0/8", "10.0.0.0/8", "::1/128", "fe80::/10", "fc00::/7")]


FLOOR = {4: 24, 6: 64}


def test_validate_accepts_both_families(rec, allow):
    assert rec.validate("203.0.113.5", allow, FLOOR) == (True, "", "203.0.113.5/32")
    assert rec.validate("2001:db8::1", allow, FLOOR) == (True, "", "2001:db8::1/128")
    assert rec.validate("2001:db8::/64", allow, FLOOR)[0] is True


def test_validate_per_family_floor(rec, allow):
    # v6 /48 is broader than the /64 floor -> rejected; v4 /20 is broader than /24 -> rejected.
    ok6, reason6, _ = rec.validate("2001:db8::/48", allow, FLOOR)
    assert ok6 is False and "too-broad" in reason6
    ok4, reason4, _ = rec.validate("198.51.100.0/20", allow, FLOOR)
    assert ok4 is False and "too-broad" in reason4


def test_validate_allowlist_is_family_scoped(rec, allow):
    assert rec.validate("fe80::1", allow, FLOOR)[1].startswith("allowlisted")
    assert rec.validate("10.1.2.3", allow, FLOOR)[1].startswith("allowlisted")
    # a public v6 that overlaps no v6 allowlist entry passes
    assert rec.validate("2606:4700::/64", allow, FLOOR)[0] is True


def test_validate_failclosed_without_allowlist(rec):
    assert rec.validate("203.0.113.5", None, FLOOR) == (False, "allowlist-missing-failclosed", None)


def test_split_by_family(rec):
    v4, v6 = rec.split_by_family({"203.0.113.5/32": 100, "2001:db8::/64": 200, "198.51.100.0/24": 50})
    assert v4 == {"203.0.113.5/32": 100, "198.51.100.0/24": 50}
    assert v6 == {"2001:db8::/64": 200}


def test_dedupe_collapses_per_family(rec):
    # two adjacent /64s collapse to a /63 (same family, uniform ttl)
    assert rec.dedupe_intervals({"2001:db8::/64": 100, "2001:db8:0:1::/64": 100}) == {"2001:db8::/63": 100}


def test_reconcile_set_builds_v6_transaction(rec):
    # DRYRUN short-circuits before touching nft; just prove the v6 path forms a transaction.
    rec.DRYRUN = True
    ok, detail = rec.reconcile_set("ai_block6", {"2001:db8::/64": 300})
    assert ok is True and detail == "dry-run"


def test_current_set_parses_v6_prefix(rec, monkeypatch):
    # the nft -j JSON for a v6 set carries {"prefix":{"addr":"...","len":N}} elements
    payload = {"nftables": [{"set": {"name": "ai_block6", "elem": [
        {"elem": {"val": {"prefix": {"addr": "2001:db8::", "len": 64}}}},
        {"elem": {"val": "2001:db8:1::1"}},
    ]}}]}

    class P:
        returncode = 0
        stdout = json.dumps(payload)

    monkeypatch.setattr(rec.subprocess, "run", lambda *a, **k: P())
    assert rec.current_set("ai_block6") == {"2001:db8::/64", "2001:db8:1::1"}
