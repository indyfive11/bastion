"""A1 — thin top-level wrappers (`bastion snapshot|rollback|confirm|recovery|update`) over the
operational scripts. A recording FakeSystem captures the argv the wrapper shells out, so the
mapping is checked without a live host. --root skips the euid guard (root only when root == /).
"""
import subprocess
from pathlib import Path

import pytest

from bastion import cli
from bastion.layers.base import Context
from bastion.system import System

TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"


class FakeSystem(System):
    def __init__(self, root: Path, have: bool = True):
        super().__init__(root=root)
        self._have = have
        self.calls: list[tuple] = []

    def exists(self, p: str) -> bool:
        return self._have

    def run(self, *args, capture=True):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")


def _ctx(monkeypatch, sys_):
    ctx = Context(system=sys_, config={}, templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)


def _ran(fake, suffix):
    return next((c for c in fake.calls if str(c[0]).endswith(suffix)), None)


def test_snapshot_runs_net_snapshot(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["snapshot", "--root", "/staged"])
    assert cli.cmd_snapshot(args) == 0
    assert _ran(fake, "/usr/local/sbin/net-snapshot") is not None


def test_confirm_runs_net_confirm(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["confirm", "--root", "/staged"])
    assert cli.cmd_confirm(args) == 0
    assert _ran(fake, "/usr/local/sbin/net-confirm") is not None


def test_rollback_passes_reason(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["rollback", "egress-blip", "--root", "/staged"])
    assert cli.cmd_rollback(args) == 0
    assert _ran(fake, "/usr/local/sbin/net-rollback")[1] == "egress-blip"


def test_rollback_defaults_reason_to_manual(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["rollback", "--root", "/staged"])
    cli.cmd_rollback(args)
    assert _ran(fake, "/usr/local/sbin/net-rollback")[1] == "manual"


def test_recovery_status_runs_without_root(monkeypatch):
    # status is read-only (need_root=False), so it runs even when root == / and euid != 0.
    fake = FakeSystem(Path("/"))
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["recovery", "status"])
    assert cli.cmd_recovery(args) == 0
    assert _ran(fake, "/usr/local/sbin/bastion-recovery")[1] == "status"


def test_recovery_extend_maps_action(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["recovery", "extend", "--root", "/staged"])
    assert cli.cmd_recovery(args) == 0
    assert _ran(fake, "/usr/local/sbin/bastion-recovery")[1] == "extend"


def test_wrapper_errors_when_script_absent(monkeypatch, capsys):
    fake = FakeSystem(Path("/staged"), have=False)
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["snapshot", "--root", "/staged"])
    assert cli.cmd_snapshot(args) == 1
    assert "not installed" in capsys.readouterr().err
    assert fake.calls == []   # never shelled out


@pytest.mark.parametrize("target,unit", [("feeds", "edge-feed.service"),
                                         ("dnsblock", "edge-dnsblock.service")])
def test_update_triggers_oneshot_unit(monkeypatch, target, unit):
    fake = FakeSystem(Path("/staged"))
    _ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["update", target, "--root", "/staged"])
    assert cli.cmd_update(args) == 0
    assert ("systemctl", "start", unit) in fake.calls


def test_parsers_wire_funcs():
    p = cli.build_parser()
    assert p.parse_args(["snapshot"]).func is cli.cmd_snapshot
    assert p.parse_args(["rollback"]).func is cli.cmd_rollback
    assert p.parse_args(["confirm"]).func is cli.cmd_confirm
    assert p.parse_args(["recovery", "start"]).func is cli.cmd_recovery
    assert p.parse_args(["update", "feeds"]).func is cli.cmd_update
    assert p.parse_args(["verify"]).func is cli.cmd_verify
    assert p.parse_args(["doctor"]).func is cli.cmd_doctor
