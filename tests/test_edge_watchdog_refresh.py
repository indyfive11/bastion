"""N2 — the known-good snapshot auto-refresh (maybe_refresh).

Two failures this guards, driven via the project's bash-script-test idiom (sed the function out,
source it in a child bash with externals redefined as shell functions):

  * the refresh must CAPTURE (call net-snapshot directly, the idiom every other caller uses) instead
    of the old `systemctl start net-snapshot.service` — a silent no-op, since that unit never existed.
  * the refresh must NOT bake a detected host-resolver leak into the known-good slot (net-snapshot
    copies /etc/resolv.conf; a refresh mid-leak would make a later net-rollback RESTORE the leak).
    The DNS-leak hold mirrors dns_leak_watch's applicability (edge mode + a loopback stub chain).

The behavioral tests sed the absolute `/usr/local/sbin/net-snapshot` path down to a `net_snapshot`
stub so the control flow can be exercised off-host; the static test (below) pins the REAL absolute
path and proves the dead systemctl call is gone, so the stub can't mask a divergence.
"""
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-watchdog"


def _maybe_refresh() -> str:
    out = subprocess.run(["sed", "-n", "/^maybe_refresh()/,/^}/p", str(SCRIPT)],
                         capture_output=True, text=True, check=True).stdout
    assert "maybe_refresh()" in out, "could not extract maybe_refresh from edge-watchdog"
    # Redirect the absolute net-snapshot invocation to a stub function we control in the driver.
    return out.replace("/usr/local/sbin/net-snapshot", "net_snapshot")


def _run(tmp_path, *, mode="edge", dns_upstream="127.0.0.1#5335", dryrun="0",
         refresh_after="0", last="0", leak=False, snap_rc=0) -> subprocess.CompletedProcess:
    run = tmp_path / "run"; run.mkdir()
    (run / "last-good-snapshot").write_text(last + "\n")
    leak_fn = ('resolv_leak(){ echo "203.0.113.9"; return 0; }' if leak
               else "resolv_leak(){ return 1; }")
    driver = textwrap.dedent(f"""
        set -u
        RUN="{run}"
        MODE="{mode}"; DNS_UPSTREAM="{dns_upstream}"; DRYRUN="{dryrun}"; REFRESH_AFTER="{refresh_after}"
        date(){{ echo 1000000; }}                 # deterministic now=1000000
        config_ok(){{ return 0; }}                # config intact
        lan_relay_broken(){{ return 1; }}         # relay fine
        {leak_fn}
        log(){{ echo "LOG: $*"; }}
        # net-snapshot stub: record the call via a FILE (the real call redirects stdout to /dev/null,
        # so a stdout marker would be swallowed), and return the requested rc.
        net_snapshot(){{ : > "$RUN/snapshot-called"; return {snap_rc}; }}
    """) + _maybe_refresh() + textwrap.dedent("""
        maybe_refresh
        [ -e "$RUN/snapshot-called" ] && echo "SNAPSHOT=called" || echo "SNAPSHOT=not-called"
        echo "LASTGOOD=$(cat "$RUN/last-good-snapshot")"
    """)
    return subprocess.run(["bash", "-c", driver], capture_output=True, text=True, check=True)


def test_refresh_captures_directly_and_stamps_on_success(tmp_path):
    r = _run(tmp_path, snap_rc=0)
    assert "SNAPSHOT=called" in r.stdout            # net-snapshot invoked directly (no systemctl)
    assert "LASTGOOD=1000000" in r.stdout           # stamped with `now` on success
    assert "known-good snapshot refreshed" in r.stdout


def test_refresh_does_not_stamp_when_capture_fails(tmp_path):
    r = _run(tmp_path, snap_rc=1)
    assert "SNAPSHOT=called" in r.stdout            # attempted
    assert "LASTGOOD=0" in r.stdout                 # && gate: NOT stamped on a failed capture
    assert "known-good snapshot refreshed" not in r.stdout


def test_refresh_held_on_dns_leak(tmp_path):
    # edge mode + loopback upstream + a live resolv.conf leak → HOLD (don't snapshot a leaked
    # resolv.conf into the known-good slot).
    r = _run(tmp_path, mode="edge", dns_upstream="127.0.0.1#5335", leak=True)
    assert "SNAPSHOT=not-called" in r.stdout
    assert "LASTGOOD=0" in r.stdout                 # not stamped — the slot is left as-is
    assert "refresh HELD" in r.stdout


def test_refresh_proceeds_when_no_leak(tmp_path):
    r = _run(tmp_path, mode="edge", dns_upstream="127.0.0.1#5335", leak=False)
    assert "SNAPSHOT=called" in r.stdout


def test_leak_gate_is_edge_only(tmp_path):
    # The DNS-leak concept is edge-only (endpoint has no hardened local chain). Even with resolv_leak
    # signalling a leak, an endpoint must not be held by it — the gate is guarded on MODE.
    r = _run(tmp_path, mode="endpoint", leak=True)
    assert "SNAPSHOT=called" in r.stdout
    assert "refresh HELD" not in r.stdout


def test_leak_gate_skipped_for_external_upstream(tmp_path):
    # An operator legitimately using an external (non-loopback) DNS upstream has no local chain to
    # leak past — resolv.conf pointing at that upstream is not a "leak", so the gate must not fire
    # (else every refresh would be frozen forever).
    r = _run(tmp_path, mode="edge", dns_upstream="9.9.9.9", leak=True)
    assert "SNAPSHOT=called" in r.stdout
    assert "refresh HELD" not in r.stdout


def test_held_log_latches(tmp_path):
    # A sustained leak is polled every cycle; the HELD notice must log ONCE per episode (the daemon
    # idiom), not spam the journal every poll. Two consecutive held calls → exactly one HELD line.
    run = tmp_path / "run"; run.mkdir()
    (run / "last-good-snapshot").write_text("0\n")
    driver = textwrap.dedent(f"""
        set -u
        RUN="{run}"
        MODE="edge"; DNS_UPSTREAM="127.0.0.1#5335"; DRYRUN="0"; REFRESH_AFTER="0"
        date(){{ echo 1000000; }}
        config_ok(){{ return 0; }}
        lan_relay_broken(){{ return 1; }}
        resolv_leak(){{ echo "203.0.113.9"; return 0; }}   # leak persists across both polls
        log(){{ echo "LOG: $*"; }}
        net_snapshot(){{ : > "$RUN/snapshot-called"; return 0; }}
    """) + _maybe_refresh() + textwrap.dedent("""
        maybe_refresh
        maybe_refresh
    """)
    r = subprocess.run(["bash", "-c", driver], capture_output=True, text=True, check=True)
    assert r.stdout.count("refresh HELD") == 1        # latched — not once per poll
    assert not (run / "snapshot-called").exists()      # never captured while leaking


def test_dryrun_does_not_capture(tmp_path):
    r = _run(tmp_path, dryrun="1")
    assert "SNAPSHOT=not-called" in r.stdout
    assert "would refresh known-good snapshot" in r.stdout


def test_refresh_respects_interval(tmp_path):
    # now-last (1000000-999999=1) < REFRESH_AFTER(1800) → too soon, no capture.
    r = _run(tmp_path, refresh_after="1800", last="999999")
    assert "SNAPSHOT=not-called" in r.stdout


def test_no_phantom_service_call_and_real_path_present(tmp_path):
    # Static fidelity pin (the behavioral tests stub the absolute path): the dead unit call is gone
    # from the whole script, and maybe_refresh calls the REAL absolute net-snapshot path.
    whole = SCRIPT.read_text()
    assert "systemctl start net-snapshot.service" not in whole
    body = subprocess.run(["sed", "-n", "/^maybe_refresh()/,/^}/p", str(SCRIPT)],
                          capture_output=True, text=True, check=True).stdout
    assert "/usr/local/sbin/net-snapshot" in body
