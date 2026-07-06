"""C7 — snapshot completeness. net-snapshot clears `taken-at` at capture start and rewrites it as its
final act; net-rollback treats a slot with no `taken-at` as an interrupted/partial capture: it still
restores best-effort but exits 1 so no caller mistakes it for a clean rollback.

Project idiom (see test_net_rollback_scope / test_flowcheck_optional_tools): run the WHOLE script in a
child bash with every external command redefined as a stub shell function, and — crucially — DROP the
`. /etc/bastion/machine.env` source line rather than appending after it, so the dev box's own live
machine.env (this repo builds on a live endpoint node) can't leak MODE/NFT_TABLE into the run.
"""
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"
SOURCE_LINE = "[ -r /etc/bastion/machine.env ] && . /etc/bastion/machine.env\n"


def _run(script_name, testdir, argv, extra_stubs="", pre=""):
    """Copy <script_name> to a hermetic form (source line -> stubs), run it, return (rc, log_text)."""
    src = (SCRIPTS / script_name).read_text()
    log = testdir / "log.txt"
    # Stubs that stand in for every external the scripts shell out to. `logger` records what log()
    # emits; the network/service/firewall tools are inert no-ops. `date` and the shell builtins
    # (cat, rm, mkdir, [, grep -q on files) stay real.
    stubs = (
        f'STATE="{testdir}"; SNAP="$STATE/snapshot"\n'
        f'logger(){{ printf "%s\\n" "$*" >> "{log}"; }}\n'
        'nft(){ return 1; }\n'            # no bastion table loaded (edge_loaded -> false)
        'ip(){ return 0; }\n'
        'systemctl(){ return 1; }\n'      # every service reads inactive
        'nmcli(){ return 0; }\n'
        'iptables(){ return 1; }\n'
        'cp(){ return 0; }\n'
        'chmod(){ return 0; }\n'
        'cmp(){ return 1; }\n'
        'diff(){ return 1; }\n'
        f'{extra_stubs}'
    )
    assert SOURCE_LINE in src, f"{script_name}: machine.env source line moved — update the test"
    src = src.replace(SOURCE_LINE, stubs + pre)
    script = testdir / f"copy-{script_name}"
    script.write_text(src)
    r = subprocess.run(["bash", str(script), *argv], capture_output=True, text=True)
    return r.returncode, (log.read_text() if log.exists() else "")


def _seed(testdir, *, taken_at=True, fw_marker=True):
    snap = testdir / "snapshot"
    snap.mkdir(parents=True, exist_ok=True)
    (snap / "default-route.txt").write_text("default via 10.0.0.1 dev eth0\n")
    if fw_marker:
        (snap / "fw-nftables-active").write_text("")
    if taken_at:
        (snap / "taken-at").write_text("2026-07-06T12:00:00-05:00\n")
    return snap


# ---------- net-rollback: the C7 gate ----------

def test_incomplete_snapshot_exits_1_and_warns(tmp_path):
    """A slot with no taken-at (interrupted capture) -> best-effort restore + exit 1, never a clean
    'restore complete — applied changes'."""
    _seed(tmp_path, taken_at=False)
    rc, log = _run("net-rollback", tmp_path, ["test-incomplete"])
    assert rc == 1, log
    assert "INCOMPLETE" in log
    assert "reporting FAILURE" in log
    assert "NOT a verified rollback" in log
    # the false-success line must NOT appear
    assert "restore complete — applied changes" not in log
    assert "restore complete — state already matched" not in log


def test_complete_snapshot_exits_0(tmp_path):
    """A slot with taken-at present is trusted; net-rollback runs to a clean exit 0."""
    _seed(tmp_path, taken_at=True)
    rc, log = _run("net-rollback", tmp_path, ["test-complete"])
    assert rc == 0, log
    assert "INCOMPLETE" not in log
    assert "restore complete" in log


def test_firewallless_snapshot_with_taken_at_is_complete(tmp_path):
    """A box with NO firewall writes neither fw marker; that alone must not read as incomplete —
    only a missing taken-at does."""
    _seed(tmp_path, taken_at=True, fw_marker=False)
    rc, log = _run("net-rollback", tmp_path, ["test-nofw"])
    assert rc == 0, log
    assert "INCOMPLETE" not in log


def test_missing_dir_still_hard_refuses(tmp_path):
    """Unchanged behavior: no slot at all -> exit 1 'NO SNAPSHOT' (regression guard)."""
    rc, log = _run("net-rollback", tmp_path, ["test-nodir"])  # never created snapshot/
    assert rc == 1
    assert "NO SNAPSHOT" in log


# ---------- net-snapshot: clear-first, write-last ----------

def test_net_snapshot_clears_taken_at_first_and_rewrites_last(tmp_path):
    """taken-at is removed up front (so a mid-capture crash reads as incomplete) and present again
    after a full run. A probe stub fired mid-script proves taken-at is absent while the capture runs.
    The stub block points SNAP at $STATE/snapshot, so seed the prior slot there."""
    slot = tmp_path / "snapshot"
    slot.mkdir()
    (slot / "taken-at").write_text("STALE-PRIOR-VALUE\n")   # a prior good slot being refreshed
    probe = tmp_path / "probe.txt"
    # `ip` is called (routes/addrs) AFTER the up-front rm but BEFORE taken-at is rewritten. If the rm
    # ran first, taken-at is absent at that moment -> the probe stays empty. Also silence the
    # unprivileged mkdir of /run/net-safe and stub the hyphenated *-save forensic dumps.
    extra = (f'ip(){{ [ -f "$SNAP/taken-at" ] && printf PRESENT >> "{probe}"; return 0; }}\n'
             'mkdir(){ command mkdir -p "$SNAP/nm-system-connections" 2>/dev/null; }\n'
             'iptables-save(){ return 0; }\n'
             'ip6tables-save(){ return 0; }\n')
    rc, _ = _run("net-snapshot", tmp_path, [], extra_stubs=extra)
    assert rc == 0
    assert not probe.exists() or probe.read_text() == "", "taken-at was present mid-capture — not cleared first"
    assert (slot / "taken-at").read_text().strip() != "STALE-PRIOR-VALUE"  # rewritten
    assert (slot / "taken-at").exists()  # present after a completed run
