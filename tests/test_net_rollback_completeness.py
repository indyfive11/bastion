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


# ---------- net-snapshot: atomic temp-dir swap (item 3) ----------

def test_net_snapshot_swaps_in_complete_capture(tmp_path):
    """A complete capture replaces the slot via the temp-dir swap: the slot ends up with a FRESH
    taken-at (not the stale prior), and no swap temps (`.snapshot.new.*` / `.snapshot.prev`) are left
    lying around under /var/lib/net-safe."""
    slot = tmp_path / "snapshot"
    slot.mkdir()
    (slot / "taken-at").write_text("STALE-PRIOR-VALUE\n")   # a prior good slot being refreshed
    rc, _ = _run("net-snapshot", tmp_path, [])
    assert rc == 0
    assert (slot / "taken-at").exists()
    assert (slot / "taken-at").read_text().strip() != "STALE-PRIOR-VALUE"   # swapped in fresh
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".snapshot.")]
    assert leftovers == [], f"swap temps left behind: {leftovers}"


def test_net_snapshot_keeps_prior_when_capture_incomplete(tmp_path):
    """If the completion witness can't be written (disk full → `date > taken-at` fails), the PRIOR
    slot is left byte-for-byte intact and the run exits 1 — a complete-stale slot beats a torn-fresh
    one. No swap happens; the temp is cleaned up."""
    slot = tmp_path / "snapshot"
    slot.mkdir()
    (slot / "taken-at").write_text("PRIOR-GOOD\n")
    (slot / "marker").write_text("keep-me\n")
    rc, _ = _run("net-snapshot", tmp_path, [], extra_stubs="date(){ return 1; }\n")
    assert rc == 1
    assert (slot / "taken-at").read_text() == "PRIOR-GOOD\n"   # untouched
    assert (slot / "marker").read_text() == "keep-me\n"
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".snapshot.")]
    assert leftovers == [], f"temp left behind after a failed capture: {leftovers}"


def test_net_rollback_reconciles_orphaned_prev(tmp_path):
    """A crash between net-snapshot's two renames leaves the slot absent but the prior good copy in
    `.snapshot.prev`. net-rollback promotes it before its no-snapshot gate, so recovery never sees a
    false 'cannot roll back'."""
    prev = tmp_path / ".snapshot.prev"
    prev.mkdir()
    (prev / "default-route.txt").write_text("default via 10.0.0.1 dev eth0\n")
    (prev / "fw-nftables-active").write_text("")
    (prev / "taken-at").write_text("2026-08-10T09:00:00-06:00\n")
    assert not (tmp_path / "snapshot").exists()             # slot orphaned
    rc, log = _run("net-rollback", tmp_path, [])
    assert rc == 0                                          # complete slot recovered → clean rollback
    assert "recovered snapshot from an interrupted swap" in log
    assert (tmp_path / "snapshot" / "taken-at").exists()    # .prev promoted into the slot
    assert not prev.exists()
    assert "NO SNAPSHOT" not in log
