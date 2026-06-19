"""P4 — `bastion switch` deadman cutover + `bastion confirm` disarm.

net-snapshot/net-rollback/net-confirm aren't actually run (a System subclass records run() and
returns rc 0); cmd_generate/cmd_firewall are stubbed (no live /etc touch). We assert the ORDER and
arguments of the cutover: manual one-liner first, snapshot, apply, then arm `systemd-run` with the
right `--on-active`; and that `bastion confirm` stops the transient timer.
"""
import subprocess
from pathlib import Path

from bastion import cli
from bastion.layers.base import Context
from bastion.system import System

TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"


class LiveRecordingSystem(System):
    """Claims is_live + is_root so the live cutover path runs; run() is recorded and returns rc 0
    (or rc 1 for any basename in `fail`), so the wrapped net-* scripts never actually execute."""
    def __init__(self, root: Path, fail=()):
        super().__init__(root=root)
        self.calls: list[tuple] = []
        self._fail = set(fail)

    @property
    def is_live(self) -> bool:
        return True

    @property
    def is_root(self) -> bool:
        return True

    def run(self, *args, capture=True):
        self.calls.append(args)
        rc = 1 if Path(str(args[0])).name in self._fail else 0
        return subprocess.CompletedProcess(args, rc, "", "")


def _seed_sbin(root: Path, *names):
    d = root / "usr/local/sbin"
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_text("#!/bin/sh\n")


def _wire(monkeypatch, sys_, config, *, gen_rc=0, fw_rc=0):
    ctx = Context(system=sys_, config=config, templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)
    gen_fw = []
    monkeypatch.setattr(cli, "cmd_generate", lambda ns: gen_fw.append("generate") or gen_rc)
    monkeypatch.setattr(cli, "cmd_firewall", lambda ns: gen_fw.append("firewall") or fw_rc)
    return gen_fw


def _basenames(calls):
    return [Path(str(c[0])).name for c in calls]


def test_switch_applies_behind_deadman_in_order(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-snapshot", "net-rollback")
    sys_ = LiveRecordingSystem(tmp_path)
    gen_fw = _wire(monkeypatch, sys_, {"machine": {"mode": "edge", "firewall_scope": "exclusive"}})
    args = cli.build_parser().parse_args(["switch", "--minutes", "2"])
    assert cli.cmd_switch(args) == 0
    out = capsys.readouterr().out
    # (1) the manual rollback one-liner is printed FIRST (exclusive => flush ruleset)
    assert "sudo nft flush ruleset" in out
    # (2)+(4) snapshot ran, then the deadman timer was armed — in that order
    names = _basenames(sys_.calls)
    assert names.index("net-snapshot") < names.index("systemd-run")
    # (3) generate + firewall reload happened between
    assert gen_fw == ["generate", "firewall"]
    # the systemd-run invocation carries the right window + runs net-rollback with a deadman reason
    run = next(c for c in sys_.calls if Path(str(c[0])).name == "systemd-run")
    assert "--unit=bastion-switch-deadman" in run and "--on-active=2min" in run
    assert any(str(a).endswith("/net-rollback") for a in run) and "switch-deadman" in run


def test_switch_one_liner_is_scope_and_mode_aware(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-snapshot", "net-rollback")
    sys_ = LiveRecordingSystem(tmp_path)
    _wire(monkeypatch, sys_, {"machine": {"mode": "edge", "firewall_scope": "cooperative"}})
    assert cli.cmd_switch(cli.build_parser().parse_args(["switch"])) == 0
    out = capsys.readouterr().out
    # cooperative => delete bastion's own tables (both edge tables), NOT a global flush
    assert "sudo nft delete table inet edge" in out and "ip edge_nat" in out
    assert "flush ruleset" not in out


def test_switch_dry_run_changes_nothing(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-snapshot", "net-rollback")
    sys_ = LiveRecordingSystem(tmp_path)
    gen_fw = _wire(monkeypatch, sys_, {"machine": {"mode": "edge"}})
    assert cli.cmd_switch(cli.build_parser().parse_args(["switch", "--dry-run"])) == 0
    assert "preview" in capsys.readouterr().out
    assert sys_.calls == [] and gen_fw == []          # nothing snapshotted, applied, or armed


def test_switch_rolls_back_when_apply_fails(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-snapshot", "net-rollback")
    sys_ = LiveRecordingSystem(tmp_path)
    _wire(monkeypatch, sys_, {"machine": {"mode": "edge"}}, fw_rc=1)   # firewall reload fails
    assert cli.cmd_switch(cli.build_parser().parse_args(["switch", "--minutes", "5"])) == 1
    names = _basenames(sys_.calls)
    assert "net-rollback" in names                    # rolled back on failure
    assert "systemd-run" not in names                 # never armed a deadman over a failed apply
    rb = next(c for c in sys_.calls if Path(str(c[0])).name == "net-rollback")
    assert "switch-apply-failed" in rb


def test_switch_rejects_nonpositive_minutes(tmp_path, monkeypatch, capsys):
    _seed_sbin(tmp_path, "net-snapshot")
    sys_ = LiveRecordingSystem(tmp_path)
    _wire(monkeypatch, sys_, {"machine": {"mode": "edge"}})
    assert cli.cmd_switch(cli.build_parser().parse_args(["switch", "--minutes", "0"])) == 1
    assert sys_.calls == []


def test_confirm_disarms_deadman_on_clean_egress(tmp_path, monkeypatch):
    _seed_sbin(tmp_path, "net-confirm")
    sys_ = LiveRecordingSystem(tmp_path)
    _wire(monkeypatch, sys_, {"machine": {"mode": "edge"}})
    assert cli.cmd_confirm(cli.build_parser().parse_args(["confirm"])) == 0
    assert ("systemctl", "stop", "bastion-switch-deadman.timer") in sys_.calls


def test_confirm_keeps_deadman_when_egress_still_down(tmp_path, monkeypatch):
    # net-confirm fails (egress not yet up) => leave the deadman armed so it can still revert.
    _seed_sbin(tmp_path, "net-confirm")
    sys_ = LiveRecordingSystem(tmp_path, fail=("net-confirm",))
    _wire(monkeypatch, sys_, {"machine": {"mode": "edge"}})
    assert cli.cmd_confirm(cli.build_parser().parse_args(["confirm"])) == 1
    assert not any(c[:2] == ("systemctl", "stop") for c in sys_.calls)
