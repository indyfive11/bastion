"""`bastion check` — connectivity/flow checks wrapping the read-only L6 scripts.

A recording FakeSystem captures which script cmd_check shells out to, so the flag->target
mapping (default flowcheck / --lan lan-verify / --full both) and the not-installed and
return-code paths are checked without a live system. Uses --root so the suite runs unprivileged.
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
    def __init__(self, root: Path, *, present=("flowcheck", "lan-verify"), rc=0):
        super().__init__(root=root)
        self._present = set(present)
        self._rc = rc
        self.calls: list[tuple] = []

    def exists(self, p: str) -> bool:
        return Path(str(p)).name in self._present

    def run(self, *args, capture=True):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, self._rc, "", "")


def _patch_ctx(monkeypatch, sys_):
    ctx = Context(system=sys_, config={}, templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)


def _ran(fake) -> list[str]:
    return [Path(c[0]).name for c in fake.calls]


def test_check_parser_wires_command():
    args = cli.build_parser().parse_args(["check", "--full"])
    assert args.func is cli.cmd_check and args.full is True and args.lan is False


def test_check_default_runs_flowcheck_only(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["check", "--root", "/staged"])
    assert cli.cmd_check(args) == 0
    assert _ran(fake) == ["flowcheck"]


def test_check_lan_runs_lan_verify_only(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["check", "--lan", "--root", "/staged"])
    assert cli.cmd_check(args) == 0
    assert _ran(fake) == ["lan-verify"]


def test_check_full_runs_both(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["check", "--full", "--root", "/staged"])
    assert cli.cmd_check(args) == 0
    assert _ran(fake) == ["flowcheck", "lan-verify"]


def test_check_missing_script_errors_without_running(monkeypatch, capsys):
    fake = FakeSystem(Path("/staged"), present=())
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["check", "--root", "/staged"])
    assert cli.cmd_check(args) == 1
    assert "flowcheck not installed" in capsys.readouterr().err
    assert fake.calls == []


def test_check_propagates_nonzero_exit(monkeypatch):
    fake = FakeSystem(Path("/staged"), rc=3)
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["check", "--root", "/staged"])
    assert cli.cmd_check(args) == 3
