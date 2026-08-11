"""H2 — net-snapshot content-completeness gate. A capture WRITE can fail silently (disk pressure, a
transient EIO) while the tiny `taken-at` write still succeeds — which would swap a content-INCOMPLETE
slot in as known-good and let a later net-rollback "restore" from it and report success. net-snapshot
now verifies the restore-relevant captures (NM profiles, resolv.conf, the firewall known-good marker)
actually landed before stamping the slot — while SKIPPING each check when its source is legitimately
absent, so a sparse-but-valid host (NM-less endpoint, resolv-as-symlink) never false-fails and disables
its own safety net.

Same whole-script-in-child-bash idiom as test_net_rollback_completeness.py, but `cp`/`date` are left
REAL so fixtures actually copy — the point is to exercise the REAL gate. (test_edge_watchdog_refresh.py
stubs net-snapshot wholesale and would stay green under a false-incomplete bug, so it can't cover this.)
"""
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"
SOURCE_LINE = "[ -r /etc/bastion/machine.env ] && . /etc/bastion/machine.env\n"


def _run(testdir, *, nm_dir=None, resolv_conf=None, extra_stubs=""):
    """Run the real net-snapshot with the completeness seams pointed at fixtures. cp/date stay real."""
    src = (SCRIPTS / "net-snapshot").read_text()
    log = testdir / "log.txt"
    nm_dir = nm_dir if nm_dir is not None else testdir / "nm-absent"
    resolv_conf = resolv_conf if resolv_conf is not None else testdir / "resolv-absent"
    stubs = (
        f'STATE="{testdir}"; SNAP="$STATE/snapshot"\n'
        f'NM_DIR="{nm_dir}"; RESOLV_CONF="{resolv_conf}"\n'
        f'logger(){{ printf "%s\\n" "$*" >> "{log}"; }}\n'
        'nft(){ return 1; }\n'             # no bastion table loaded / empty ruleset dump
        'systemctl(){ return 1; }\n'       # every service reads inactive
        'ip(){ return 0; }\n'
        'iptables-save(){ return 0; }\n'
        'ip6tables-save(){ return 0; }\n'
        f'{extra_stubs}'
    )
    assert SOURCE_LINE in src, "net-snapshot: machine.env source line moved — update the test"
    script = testdir / "copy-net-snapshot"
    script.write_text(src.replace(SOURCE_LINE, stubs))
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    return r.returncode, (log.read_text() if log.exists() else "")


def _nm(testdir, names):
    d = testdir / "nm-src"; d.mkdir()
    for n in names:
        (d / n).write_text("[connection]\nid=x\n")   # a non-empty profile
    return d


def _prior(testdir):
    """A prior known-good slot being refreshed; asserts stay to prove it is left byte-for-byte intact."""
    slot = testdir / "snapshot"; slot.mkdir()
    (slot / "taken-at").write_text("PRIOR-GOOD\n")
    (slot / "marker").write_text("keep-me\n")
    return slot


def _no_temps(testdir):
    return [p.name for p in testdir.iterdir() if p.name.startswith(".snapshot.")]


# ---------- healthy / legitimately-sparse hosts PASS (no false-incomplete) ----------

def test_healthy_capture_swaps_in(tmp_path):
    nm = _nm(tmp_path, ["a.nmconnection", "b.nmconnection"])
    resolv = tmp_path / "resolv.conf"; resolv.write_text("nameserver 127.0.0.1\n")
    slot = _prior(tmp_path)
    rc, log = _run(tmp_path, nm_dir=nm, resolv_conf=resolv)
    assert rc == 0, log
    assert "incomplete" not in log
    assert (slot / "taken-at").read_text().strip() != "PRIOR-GOOD"   # swapped in fresh
    assert _no_temps(tmp_path) == []


def test_nm_less_host_is_complete(tmp_path):
    """systemd-networkd box (no NM dir) — the NM clause must SKIP, not false-fail."""
    resolv = tmp_path / "resolv.conf"; resolv.write_text("nameserver 127.0.0.1\n")
    rc, log = _run(tmp_path, resolv_conf=resolv)     # nm_dir defaults to an absent path
    assert rc == 0, log
    assert "incomplete" not in log


def test_resolv_dangling_symlink_is_complete(tmp_path):
    """THE false-incomplete regression guard: resolv.conf is a RELATIVE symlink whose target does not
    resolve under the temp capture dir (systemd-resolved stub). A `-s`/deref test would false-fail and
    permanently self-disable net-snapshot in the field while passing in dev; `-e || -L` passes."""
    link = tmp_path / "resolv.conf"
    link.symlink_to("../run/systemd/resolve/stub-resolv.conf")   # relative + dangling, by design
    rc, log = _run(tmp_path, resolv_conf=link)       # nm absent -> NM clause skips
    assert rc == 0, log
    assert "incomplete" not in log


def test_empty_source_profile_is_complete(tmp_path):
    """A stray 0-byte `.nmconnection` in the SOURCE is faithfully copied empty — that must NOT read as a
    truncated capture (else one stray file disables snapshotting forever). Only an empty COPY of a
    non-empty source is a failure."""
    nm = _nm(tmp_path, ["a.nmconnection"])
    (nm / "empty.nmconnection").write_text("")       # a legitimately-empty source profile
    resolv = tmp_path / "resolv.conf"; resolv.write_text("nameserver 127.0.0.1\n")
    rc, log = _run(tmp_path, nm_dir=nm, resolv_conf=resolv)
    assert rc == 0, log
    assert "incomplete" not in log


def test_concurrent_add_is_complete(tmp_path):
    """A profile ADDED between the pre-cp source sample and the copy (dst > src) is not a failure — the
    `min(before, now)` floor must let it pass. Guards against an exact-match (`-ne`) regression."""
    nm = _nm(tmp_path, ["a.nmconnection"])           # src sampled = 1
    cp_stub = ('cp(){ case "$*" in *nm-system-connections*) mkdir -p "$NEW/nm-system-connections"; '
               'printf x > "$NEW/nm-system-connections/a.nmconnection"; '
               'printf x > "$NEW/nm-system-connections/b.nmconnection";; esac; return 0; }\n')
    rc, log = _run(tmp_path, nm_dir=nm, extra_stubs=cp_stub)   # copy lands 2
    assert rc == 0, log
    assert "incomplete" not in log


# ---------- genuine incomplete captures FAIL (keep prior slot, exit 1) ----------

def test_nm_short_copy_is_incomplete(tmp_path):
    """Source has 2 profiles but the copy landed 0 (a disk-full drop) -> dst<src -> incomplete."""
    nm = _nm(tmp_path, ["a.nmconnection", "b.nmconnection"])
    slot = _prior(tmp_path)
    rc, log = _run(tmp_path, nm_dir=nm, extra_stubs="cp(){ return 0; }\n")   # cp no-op = nothing lands
    assert rc == 1, log
    assert "NM profiles captured 0 of 2" in log
    assert (slot / "taken-at").read_text() == "PRIOR-GOOD\n"    # prior slot byte-for-byte intact
    assert (slot / "marker").read_text() == "keep-me\n"
    assert _no_temps(tmp_path) == []


def test_nm_zero_length_profile_is_incomplete(tmp_path):
    """Count matches but a profile copied as 0 bytes (a truncated write) -> incomplete."""
    nm = _nm(tmp_path, ["a.nmconnection"])
    slot = _prior(tmp_path)
    cp_stub = ('cp(){ case "$*" in *nm-system-connections*) mkdir -p "$NEW/nm-system-connections"; '
               ': > "$NEW/nm-system-connections/a.nmconnection";; esac; return 0; }\n')
    rc, log = _run(tmp_path, nm_dir=nm, extra_stubs=cp_stub)
    assert rc == 1, log
    assert "copied empty" in log
    assert (slot / "taken-at").read_text() == "PRIOR-GOOD\n"
    assert (slot / "marker").read_text() == "keep-me\n"
    assert _no_temps(tmp_path) == []


def test_resolv_copy_missing_is_incomplete(tmp_path):
    """resolv.conf present at source but the copy didn't land -> incomplete."""
    resolv = tmp_path / "resolv.conf"; resolv.write_text("nameserver 127.0.0.1\n")
    slot = _prior(tmp_path)
    rc, log = _run(tmp_path, resolv_conf=resolv, extra_stubs="cp(){ return 0; }\n")
    assert rc == 1, log
    assert "resolv.conf copy missing" in log
    assert (slot / "taken-at").read_text() == "PRIOR-GOOD\n"
    assert _no_temps(tmp_path) == []


def test_fw_marker_write_failure_is_incomplete(tmp_path):
    """Firewall detected active but the tiny marker write fails (transient EIO) -> incomplete, so
    net-rollback can never restore NO firewall from a slot that got stamped known-good."""
    slot = _prior(tmp_path)
    rc, log = _run(tmp_path, extra_stubs="nft(){ return 0; }\nwrite_marker(){ return 1; }\n")
    assert rc == 1, log
    assert "firewall known-good marker not written" in log
    assert (slot / "taken-at").read_text() == "PRIOR-GOOD\n"
    assert _no_temps(tmp_path) == []
