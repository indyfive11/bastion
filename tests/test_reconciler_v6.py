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


def test_desired_cscli_excludes_simulated(rec, allow, monkeypatch):
    # H9: crowdsec's `cscli decisions list` INCLUDES simulated decisions by default; the reconciler
    # must NOT enforce them into cs_block (else simulation-first silently becomes enforcement).
    # Real (simulated:false) and no-field (older crowdsec) bans ARE enforced; simulated:true is
    # excluded and counted. Fixture matches real cscli JSON: top-level list of alerts, each with a
    # `decisions` array, crowdsec's exact key case (type "ban", scope "Ip"), values /32 outside the
    # allowlist. Asserting the REAL ban is PRESENT proves the fixture reaches the enforce path (so a
    # subtly-wrong shape can't make the "simulated absent" assertion pass vacuously).
    payload = [{"simulated": False, "decisions": [
        {"type": "ban", "scope": "Ip", "value": "203.0.113.10", "duration": "3h59m59s", "simulated": False},
        {"type": "ban", "scope": "Ip", "value": "203.0.113.20", "duration": "3h59m59s", "simulated": True},
        {"type": "ban", "scope": "Ip", "value": "203.0.113.30", "duration": "3h59m59s"},
    ]}]

    class P:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(rec.subprocess, "run", lambda *a, **k: P())
    desired, rejected, n_simulated, n_cdn_rej = rec.desired_cscli(allow, {4: 24, 6: 64})
    assert "203.0.113.10/32" in desired       # real decision -> enforced (proves fixture reaches enforce path)
    assert "203.0.113.30/32" in desired       # no `simulated` field (older crowdsec) -> enforced
    assert "203.0.113.20/32" not in desired    # simulated:true -> excluded
    assert n_simulated == 1
    assert rejected == []                      # a simulated skip is NOT a validation rejection


def test_desired_cscli_simulated_not_counted_as_rejection(rec, allow, monkeypatch):
    # A simulated decision that would ALSO fail validation (allowlisted) must be counted as a
    # simulated-skip, not an allowlist rejection — the simulated check runs FIRST. Guards the
    # audit-accounting (rejected_count vs simulated_skipped stay distinct).
    payload = [{"decisions": [
        {"type": "ban", "scope": "Ip", "value": "10.0.0.5", "duration": "3h", "simulated": True},
    ]}]

    class P:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(rec.subprocess, "run", lambda *a, **k: P())
    desired, rejected, n_simulated, n_cdn_rej = rec.desired_cscli(allow, {4: 24, 6: 64})
    assert desired == {}
    assert n_simulated == 1
    assert rejected == []                      # counted as simulated, NOT as an allowlist rejection


# ---- H14: trusted-proxy (CDN/XFF) belt + detection-blind signal --------------------------------

def test_trusted_proxies_folded_into_never_block(rec, monkeypatch):
    # H14 belt: TRUSTED_PROXIES (CDN edge ranges) must be folded into the reconciler's never-block
    # set (env-fold), both v4 and v6, so a ban keyed on a CDN edge can never reach cs_block.
    monkeypatch.setenv("TRUSTED_PROXIES", "104.16.0.0/13, 2606:4700::/32")
    # cleared other env vars this helper also reads shouldn't matter, but be explicit.
    for v in ("TRUSTED_HOSTS", "RELAY_DST", "RELAY_ENDPOINT", "GATEWAY"):
        monkeypatch.delenv(v, raising=False)
    nets = rec.env_protected_nets()
    assert ipaddress.ip_network("104.16.0.0/13") in nets      # v4 CF range folded in
    assert ipaddress.ip_network("2606:4700::/32") in nets     # v6 CF range folded in (F4)
    # a CF edge IP now overlaps a never-block entry -> validate() rejects it as allowlisted
    ok, reason, _ = rec.validate("104.16.5.5", nets, FLOOR)
    assert ok is False and reason.startswith("allowlisted")


def test_desired_cscli_flags_cdn_blind_when_all_bans_are_cdn_edges(rec, monkeypatch):
    # H14 signal: when every enforceable ban targets a trusted-proxy/CDN edge, it is belt-rejected,
    # cs_block ends EMPTY, and n_cdn_rej reflects it -> the detection-blind-behind-CDN condition.
    monkeypatch.setenv("TRUSTED_PROXIES", "104.16.0.0/13, 2606:4700::/32")
    allow = [ipaddress.ip_network("104.16.0.0/13"), ipaddress.ip_network("2606:4700::/32")]
    payload = [{"decisions": [
        {"type": "ban", "scope": "Ip", "value": "104.16.5.5", "duration": "3h", "simulated": False},
        {"type": "ban", "scope": "Ip", "value": "2606:4700::1234", "duration": "3h"},
    ]}]

    class P:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(rec.subprocess, "run", lambda *a, **k: P())
    desired, rejected, n_simulated, n_cdn_rej = rec.desired_cscli(allow, FLOOR)
    assert desired == {}                        # both CDN edges belt-rejected -> cs_block empty
    assert n_cdn_rej == 2                        # both counted as CDN-edge rejections (v4 AND v6)
    assert n_simulated == 0
    assert len(rejected) == 2                    # they are still ordinary allowlist rejections too


def test_desired_cscli_not_blind_when_a_real_ban_reaches_cs_block(rec, monkeypatch):
    # A CDN edge is rejected+counted, but a real (non-proxy) client ban still enforces -> desired is
    # non-empty, so the caller must NOT flag cdn_blind (raw_count>0). Guards a false-positive "blind".
    monkeypatch.setenv("TRUSTED_PROXIES", "104.16.0.0/13")
    allow = [ipaddress.ip_network("104.16.0.0/13")]
    payload = [{"decisions": [
        {"type": "ban", "scope": "Ip", "value": "104.16.5.5", "duration": "3h"},      # CDN edge
        {"type": "ban", "scope": "Ip", "value": "203.0.113.7", "duration": "3h"},     # real client
    ]}]

    class P:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(rec.subprocess, "run", lambda *a, **k: P())
    desired, rejected, n_simulated, n_cdn_rej = rec.desired_cscli(allow, FLOOR)
    assert "203.0.113.7/32" in desired          # real ban enforced (raw_count>0 -> caller: not blind)
    assert n_cdn_rej == 1                        # the CDN edge still counted (informative)


def test_desired_cscli_no_trusted_proxies_never_counts_cdn(rec, allow, monkeypatch):
    # Narrowest-scope default: with no TRUSTED_PROXIES set, the CDN accounting is inert — a normal
    # allowlist rejection (RFC1918) is NOT miscounted as a CDN-edge rejection.
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    payload = [{"decisions": [
        {"type": "ban", "scope": "Ip", "value": "10.0.0.9", "duration": "3h"},   # allowlisted RFC1918
    ]}]

    class P:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(rec.subprocess, "run", lambda *a, **k: P())
    desired, rejected, n_simulated, n_cdn_rej = rec.desired_cscli(allow, FLOOR)
    assert n_cdn_rej == 0                        # no trusted_proxies -> nothing attributed to CDN
    assert len(rejected) == 1                    # still an ordinary allowlist rejection
