"""`bastion feeds` (promote the hardcoded threat-feed URLs into machine.conf) + F3 (IP-feed
self-lockout guard): edge-feed-fetch honours FEED_SOURCES and applies the supply-chain collapse/
explosion caps, and edge-reconciler folds the box's own inbound mgmt hosts into the never-block
allowlist so a poisoned feed can never blackhole the operator.

edge-feed-fetch is driven via the project's bash idiom — redefine the external commands (curl,
logger) as shell functions (PATH stubs don't work: /tmp is noexec) and drive inputs via the env
seams the script already reads (FEED_SOURCES, STATE_DIRECTORY, FEED_MIN_RATIO, FEED_MAX, plus a
test-only CURL_OUT the stubbed curl emits).
"""
import importlib.util
import ipaddress
import subprocess
import textwrap
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

FETCH = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-feed-fetch"
RECON = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-reconciler"


def _run_fetch(curl_out: str, *, state_dir: Path, env: dict | None = None):
    """Source edge-feed-fetch with curl/logger stubbed; returns (rc, out_file_contents-or-None)."""
    driver = textwrap.dedent("""
        logger(){ :; }                       # silence journal/stderr
        curl(){ printf '%s' "$CURL_OUT"; }   # emit canned feed content for any URL
    """) + f"\nsource {FETCH}\n"
    full_env = {
        "PATH": "/usr/bin:/bin",
        "STATE_DIRECTORY": str(state_dir),
        "FEED_SOURCES": "https://example.test/feed",   # single dummy URL -> curl called once
        "CURL_OUT": curl_out,
    }
    full_env.update(env or {})
    p = subprocess.run(["bash", "-c", driver], capture_output=True, text=True, env=full_env)
    out = state_dir / "blk_feed.list"
    return p.returncode, (out.read_text() if out.exists() else None)


def test_fetch_writes_parsed_candidates(tmp_path):
    rc, body = _run_fetch("203.0.113.4\n198.51.100.0/24\n# comment\n203.0.113.4\n", state_dir=tmp_path)
    assert rc == 0
    assert sorted(body.split()) == ["198.51.100.0/24", "203.0.113.4"]      # deduped + sorted


def test_fetch_honours_feed_sources_env(tmp_path):
    # FEED_SOURCES drives the fetch; a single dummy URL still produces output (proves it's read,
    # not the baked-in defaults — those URLs would have to resolve on the network).
    rc, body = _run_fetch("10.10.10.10\n", state_dir=tmp_path)
    assert rc == 0 and "10.10.10.10" in body


def test_fetch_refuses_collapse(tmp_path):
    # Pre-seed a large current list; a source that suddenly returns almost nothing must be REFUSED
    # (truncated/poisoned feed would otherwise unblock everyone), keeping the current list intact.
    out = tmp_path / "blk_feed.list"
    out.write_text("\n".join(f"203.0.113.{a}/32" if a < 256 else f"198.51.{a//256}.{a%256}/32"
                             for a in range(2000)) + "\n")
    before = out.read_text()
    rc, body = _run_fetch("203.0.113.4\n203.0.113.5\n", state_dir=tmp_path)
    assert rc == 1
    assert body == before                                                  # current list untouched
    assert not (tmp_path / "blk_feed.list.new").exists()                    # staging cleaned up


def test_fetch_refuses_explosion(tmp_path):
    big = "\n".join(f"203.0.113.{i % 256}/32" if i < 256 else f"198.51.{i // 256}.{i % 256}"
                    for i in range(50)) + "\n"
    rc, body = _run_fetch(big, state_dir=tmp_path, env={"FEED_MAX": "5"})
    assert rc == 1 and body is None                                        # nothing written


def test_fetch_collapse_skipped_when_current_small(tmp_path):
    # The collapse guard only triggers once the current list is sizeable (>=1000), so a fresh
    # install (no/tiny current list) can shrink freely without a false REFUSE.
    (tmp_path / "blk_feed.list").write_text("203.0.113.1/32\n203.0.113.2/32\n")
    rc, body = _run_fetch("203.0.113.9\n", state_dir=tmp_path)
    assert rc == 0 and body.strip() == "203.0.113.9"


def test_fetch_script_references_feed_sources():
    body = FETCH.read_text()
    assert "FEED_SOURCES" in body and "DEFAULT_FEEDS" in body
    assert "REFUSED" in body                                               # supply-chain cap present


# --------------------------------------------------------------------------- F3 reconciler fold
def _load_recon():
    loader = SourceFileLoader("edge_reconciler_f3", str(RECON))
    spec = importlib.util.spec_from_loader("edge_reconciler_f3", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_env_protected_nets_parses_mgmt_sources(monkeypatch):
    m = _load_recon()
    monkeypatch.setenv("TRUSTED_HOSTS", "203.0.113.7, 10.5.5.0/24")
    monkeypatch.setenv("RELAY_DST", "198.51.100.2")
    monkeypatch.setenv("RELAY_ENDPOINT", "198.51.100.9")        # G2: public relay far end
    monkeypatch.setenv("GATEWAY", "10.0.1.254")
    nets = {str(n) for n in m.env_protected_nets()}
    assert nets == {"203.0.113.7/32", "10.5.5.0/24", "198.51.100.2/32",
                    "198.51.100.9/32", "10.0.1.254/32"}


def test_env_protected_nets_ignores_blank_and_garbage(monkeypatch):
    m = _load_recon()
    monkeypatch.setenv("TRUSTED_HOSTS", "not-an-ip, 203.0.113.8")
    monkeypatch.delenv("RELAY_DST", raising=False)
    monkeypatch.delenv("RELAY_ENDPOINT", raising=False)
    monkeypatch.delenv("GATEWAY", raising=False)
    assert {str(n) for n in m.env_protected_nets()} == {"203.0.113.8/32"}   # garbage dropped, never raises


def test_relay_endpoint_folds_and_blocks_lockout(tmp_path, monkeypatch):
    # G2: a poisoned feed listing the operator's OWN upstream relay public endpoint must be rejected.
    m = _load_recon()
    allow_file = tmp_path / "policy.allowlist"
    allow_file.write_text("127.0.0.0/8\n10.0.0.0/8\n")          # shipped floors only (no public IP)
    monkeypatch.setattr(m, "ALLOWLIST", str(allow_file))
    for v in ("TRUSTED_HOSTS", "RELAY_DST", "GATEWAY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("RELAY_ENDPOINT", "45.33.32.156")        # a public relay far end
    allow = m.load_allowlist()
    assert any(str(n) == "45.33.32.156/32" for n in allow)
    ok, reason, _ = m.validate("45.33.32.156", allow, {4: 8, 6: 19})
    assert ok is False and "allowlisted" in reason


def test_load_allowlist_folds_env_and_blocks_lockout(tmp_path, monkeypatch):
    m = _load_recon()
    allow_file = tmp_path / "policy.allowlist"
    allow_file.write_text("127.0.0.0/8\n10.0.0.0/8\n")          # shipped floors only (no public mgmt IP)
    monkeypatch.setattr(m, "ALLOWLIST", str(allow_file))
    monkeypatch.setenv("TRUSTED_HOSTS", "203.0.113.7")          # a PUBLIC management host
    monkeypatch.delenv("RELAY_DST", raising=False)
    monkeypatch.delenv("RELAY_ENDPOINT", raising=False)
    monkeypatch.delenv("GATEWAY", raising=False)
    allow = m.load_allowlist()
    assert any(str(n) == "203.0.113.7/32" for n in allow)       # folded in from machine.env
    # a poisoned feed listing the operator's own mgmt host is now REJECTED (self-lockout prevented)
    ok, reason, _ = m.validate("203.0.113.7", allow, {4: 8, 6: 19})
    assert ok is False and "allowlisted" in reason
    # an unrelated address is still accepted (the fold only ADDS protection)
    ok, _, norm = m.validate("45.45.45.0/24", allow, {4: 8, 6: 19})
    assert ok is True and norm == "45.45.45.0/24"
