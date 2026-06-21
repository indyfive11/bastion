"""D4 — first-class named snapshots (`bastion snapshot --name`, `snapshots`, `rollback <name>`).

net-snapshot/net-rollback aren't actually run (recorded by a System subclass returning rc 0); the
save/restore/list layer operates on real files under a temp root.
"""
import subprocess
from pathlib import Path

from bastion import cli
from bastion.layers.base import Context
from bastion.system import System

TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"


class RecordingSystem(System):
    """Real path/exists under root; run() is recorded and returns rc 0 (so the wrapped net-*
    scripts don't actually execute)."""
    def __init__(self, root: Path):
        super().__init__(root=root)
        self.calls: list[tuple] = []

    def run(self, *args, capture=True):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")


def _ctx(monkeypatch, sys_):
    ctx = Context(system=sys_, config={}, templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)
    return sys_


def _seed_sbin(root: Path, *names):
    d = root / "usr/local/sbin"
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_text("#!/bin/sh\n")


def _seed_canonical(root: Path, taken="2026-06-15T10:00:00+00:00", marker="x"):
    snap = root / "var/lib/net-safe/snapshot"
    snap.mkdir(parents=True, exist_ok=True)
    (snap / "taken-at").write_text(taken + "\n")
    (snap / "marker").write_text(marker)
    return snap


def test_valid_snapshot_name():
    assert cli._valid_snapshot_name("good-1.2_x")
    assert not cli._valid_snapshot_name("../etc")
    assert not cli._valid_snapshot_name("has space")
    assert not cli._valid_snapshot_name("")


def test_snapshot_with_name_saves_named_copy(tmp_path, monkeypatch):
    _seed_sbin(tmp_path, "net-snapshot")
    canon = _seed_canonical(tmp_path, taken="2026-06-15T10:00:00+00:00", marker="auto-content")
    sys_ = _ctx(monkeypatch, RecordingSystem(tmp_path))
    args = cli.build_parser().parse_args(["snapshot", "--name", "before-ssh", "--root", str(tmp_path)])
    assert cli.cmd_snapshot(args) == 0
    # F10: net-snapshot is invoked with the NAMED slot as its target ($1), and the AUTO slot is left
    # untouched — a named snapshot must never clobber the rollback target.
    call = next(c for c in sys_.calls if str(c[0]).endswith("/net-snapshot"))
    assert call[1].endswith("/var/lib/net-safe/snapshots/before-ssh")
    assert (canon / "taken-at").read_text() == "2026-06-15T10:00:00+00:00\n"   # auto slot unchanged
    assert (canon / "marker").read_text() == "auto-content"


def test_snapshot_rejects_reserved_name(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-snapshot")
    sys_ = _ctx(monkeypatch, RecordingSystem(tmp_path))
    args = cli.build_parser().parse_args(["snapshot", "--name", "current", "--root", str(tmp_path)])
    assert cli.cmd_snapshot(args) == 1
    assert "reserved" in capsys.readouterr().err
    assert sys_.calls == []                                   # never ran net-snapshot


def test_rollback_current_restores_auto_slot(tmp_path, monkeypatch):
    # F10 cosmetic: `bastion rollback current` restores the auto slot (no "no named snapshot" error).
    _seed_sbin(tmp_path, "net-rollback")
    _seed_canonical(tmp_path, marker="auto")
    sys_ = _ctx(monkeypatch, RecordingSystem(tmp_path))
    args = cli.build_parser().parse_args(["rollback", "current", "--root", str(tmp_path)])
    assert cli.cmd_rollback(args) == 0
    assert any(str(c[0]).endswith("/net-rollback") for c in sys_.calls)


def test_snapshot_rejects_bad_name(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-snapshot")
    sys_ = _ctx(monkeypatch, RecordingSystem(tmp_path))
    args = cli.build_parser().parse_args(["snapshot", "--name", "../evil", "--root", str(tmp_path)])
    assert cli.cmd_snapshot(args) == 1
    assert "invalid name" in capsys.readouterr().err
    assert sys_.calls == []   # never even ran net-snapshot


def test_snapshots_lists_current_and_named(tmp_path, monkeypatch, capsys):
    _seed_canonical(tmp_path, taken="2026-06-15T10:00:00+00:00")
    (tmp_path / "var/lib/net-safe/snapshots/keep").mkdir(parents=True)
    (tmp_path / "var/lib/net-safe/snapshots/keep/taken-at").write_text("2026-06-14T09:00:00+00:00\n")
    _ctx(monkeypatch, RecordingSystem(tmp_path))
    args = cli.build_parser().parse_args(["snapshots", "--root", str(tmp_path)])
    assert cli.cmd_snapshots(args) == 0
    out = capsys.readouterr().out
    assert "current (auto)" in out and "2026-06-15T10:00:00" in out
    assert "keep" in out and "2026-06-14T09:00:00" in out


def test_rollback_named_restores_then_runs_net_rollback(tmp_path, monkeypatch):
    _seed_sbin(tmp_path, "net-rollback")
    _seed_canonical(tmp_path, marker="stale")
    named = tmp_path / "var/lib/net-safe/snapshots/known-good"
    named.mkdir(parents=True)
    (named / "marker").write_text("good")
    (named / "taken-at").write_text("2026-06-13T08:00:00+00:00\n")
    sys_ = _ctx(monkeypatch, RecordingSystem(tmp_path))
    args = cli.build_parser().parse_args(["rollback", "known-good", "--root", str(tmp_path)])
    assert cli.cmd_rollback(args) == 0
    # named snapshot was copied over the canonical slot, then net-rollback ran with a rollback reason.
    assert (tmp_path / "var/lib/net-safe/snapshot/marker").read_text() == "good"
    call = next(c for c in sys_.calls if str(c[0]).endswith("/net-rollback"))
    assert call[1] == "rollback:known-good"


def test_rollback_unknown_named_errors(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-rollback")
    sys_ = _ctx(monkeypatch, RecordingSystem(tmp_path))
    args = cli.build_parser().parse_args(["rollback", "nope", "--root", str(tmp_path)])
    assert cli.cmd_rollback(args) == 1
    assert "no named snapshot" in capsys.readouterr().err
    assert sys_.calls == []   # never ran net-rollback
