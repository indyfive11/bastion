"""M1 — atomic 0600 secret writer.

state.atomic_write_private is the shared temp+fsync+replace helper the three setup secret writers now
route through (edge-ai EnvironmentFile, notify-alert.conf, wireguard <iface>.conf). It pins the two
properties the old `os.open(final, O_TRUNC, 0o600)` idiom lacked and that the existing per-site tests
CANNOT catch (they only do a clean overwrite, which passes even against the buggy in-place writer):

  1. a crash/EIO/ENOSPC mid-write never leaves a truncated FINAL file (the consumer would otherwise
     read a keyless/partial config and fail silently);
  2. the secret is 0600 from the first byte, and overwriting an over-permissioned pre-existing file
     still yields 0600 (the dropped-post-chmod regression guard).

Plus a delegation guard per site so a future reintroduced inline writer (correct-looking but
non-atomic — which the existing 0600 tests would NOT flag) can't silently undo M1.
"""
import os
import stat

import pytest

from bastion import state
from bastion.setup import ai_backend, alerts, vpn_setup
from bastion.system import System


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def _boom(*a, **k):
    raise OSError("simulated ENOSPC/EIO mid-write")


# --- the helper ------------------------------------------------------------

def test_success_writes_content_and_0600(tmp_path):
    dest = tmp_path / "sub" / "claude.env"          # parent absent -> helper must mkdir it
    state.atomic_write_private(dest, "ANTHROPIC_API_KEY=sk-abc\n")
    assert dest.read_text() == "ANTHROPIC_API_KEY=sk-abc\n"
    assert _mode(dest) == 0o600
    assert list(dest.parent.glob(".*.tmp")) == []   # no temp residue


def test_overwrite_existing_0644_becomes_0600(tmp_path):
    dest = tmp_path / "conf"
    dest.write_text("old")
    os.chmod(dest, 0o644)                            # pre-existing world-readable file
    state.atomic_write_private(dest, "new")
    assert dest.read_text() == "new"
    assert _mode(dest) == 0o600                      # replace gave dest the temp's fresh 0600 inode


def test_mode_is_0600_regardless_of_umask(tmp_path):
    old = os.umask(0)                                # most permissive umask can't loosen the 0600 ceiling
    try:
        dest = tmp_path / "k"
        state.atomic_write_private(dest, "x")
        assert _mode(dest) == 0o600
    finally:
        os.umask(old)


def test_crash_midwrite_leaves_original_intact(tmp_path, monkeypatch):
    dest = tmp_path / "claude.env"
    dest.write_text("KEY=good\n")
    os.chmod(dest, 0o600)
    monkeypatch.setattr(state.os, "replace", _boom)  # fail at the atomic swap, temp already written
    with pytest.raises(OSError):
        state.atomic_write_private(dest, "KEY=partial\n")
    assert dest.read_text() == "KEY=good\n"          # original NEVER truncated — the actual M1 bug
    assert _mode(dest) == 0o600
    assert list(dest.parent.glob(".*.tmp")) == []    # finally cleaned the temp


def test_crash_when_dest_absent_leaves_no_stub(tmp_path, monkeypatch):
    dest = tmp_path / "claude.env"                   # never existed
    monkeypatch.setattr(state.os, "replace", _boom)
    with pytest.raises(OSError):
        state.atomic_write_private(dest, "KEY=x\n")
    assert not dest.exists()                          # absent, not a 0-byte stub
    assert list(dest.parent.glob(".*.tmp")) == []


def test_temp_is_0600_at_swap_time(tmp_path, monkeypatch):
    """The secret must hit disk 0600 from creation — capture the temp's mode while it still exists."""
    dest = tmp_path / "wg0.conf"
    seen = {}
    real_replace = state.os.replace

    def spy(src, dst):
        seen["tmp_mode"] = _mode(state.Path(src))    # temp present at replace time
        return real_replace(src, dst)

    monkeypatch.setattr(state.os, "replace", spy)
    state.atomic_write_private(dest, "PrivateKey = SECRET\n")
    assert seen["tmp_mode"] == 0o600


# --- delegation: each site routes through the helper -----------------------

def test_write_env_file_delegates_to_atomic_helper(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(state, "atomic_write_private", lambda out, text: calls.append((out, text)))
    p = tmp_path / "claude.env"
    ai_backend.write_env_file(p, {"ANTHROPIC_API_KEY": "sk-1"})
    assert calls == [(p, "ANTHROPIC_API_KEY=sk-1\n")]


def test_apply_alerts_delegates_to_atomic_helper(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(state, "atomic_write_private", lambda out, text: calls.append((out, text)))
    sys_ = System(root=tmp_path)
    rel = alerts.apply_alerts(sys_, {"NTFY_TOPIC": "t"})
    assert rel == alerts.ALERT_CONF
    assert calls and calls[0][0] == sys_.path(alerts.ALERT_CONF)
    assert "NTFY_TOPIC=" in calls[0][1]


def test_write_wg_conf_delegates_to_atomic_helper(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(state, "atomic_write_private", lambda out, text: calls.append((out, text)))
    sys_ = System(root=tmp_path)
    c = vpn_setup.WgConf(private_key="P", address="10.8.0.1/24", peer_public_key="PEER",
                         allowed_ips="10.8.0.2/32")
    rel = vpn_setup.write_wg_conf(sys_, "wg0", c)
    assert rel == "/etc/wireguard/wg0.conf"
    assert calls and calls[0][0] == sys_.path(rel)
    assert "PrivateKey = P" in calls[0][1]           # the sensitive key flows through the helper
