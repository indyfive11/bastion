"""`bastion ai` — the L3 operator kill switch on the top-level CLI (wraps edge-ctl).

A recording FakeSystem captures the argv cmd_ai shells out, so the action->edge-ctl mapping
is checked without a live system. Uses --root so the euid guard (root only when root == /) is
skipped and the suite runs unprivileged.
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
    def __init__(self, root: Path, have_edge_ctl: bool = True):
        super().__init__(root=root)
        self._have = have_edge_ctl
        self.calls: list[tuple] = []

    def exists(self, p: str) -> bool:
        return self._have if str(p).endswith("edge-ctl") else False

    def run(self, *args, capture=True):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")


def _patch_ctx(monkeypatch, sys_):
    ctx = Context(system=sys_, config={}, templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)


def test_ai_parser_wires_command():
    args = cli.build_parser().parse_args(["ai", "panic"])
    assert args.action == "panic" and args.func is cli.cmd_ai


def test_ai_rejects_unknown_action():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["ai", "bogus"])


@pytest.mark.parametrize("action,expected", [
    ("enable", "ai-enable"),
    ("disable", "ai-disable"),
    ("panic", "panic"),
    ("status", "status"),
])
def test_ai_action_maps_to_edge_ctl(monkeypatch, action, expected):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["ai", action, "--root", "/staged"])
    assert cli.cmd_ai(args) == 0
    assert any(c[0].endswith("/usr/local/sbin/edge-ctl") and c[1] == expected
               for c in fake.calls), fake.calls


def test_ai_errors_when_edge_ctl_absent(monkeypatch, capsys):
    fake = FakeSystem(Path("/staged"), have_edge_ctl=False)
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["ai", "status", "--root", "/staged"])
    assert cli.cmd_ai(args) == 1
    assert "edge-ctl not installed" in capsys.readouterr().err
    assert fake.calls == []   # never shelled out


def test_ai_proposals_maps_to_edge_ctl(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["ai", "proposals", "--root", "/staged"])
    assert cli.cmd_ai(args) == 0
    assert any(c[1] == "proposals" for c in fake.calls), fake.calls


def test_ai_rollback_passes_id(monkeypatch):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["ai", "rollback", "1234-99-ai_block", "--root", "/staged"])
    assert cli.cmd_ai(args) == 0
    call = next(c for c in fake.calls if c[1] == "rollback")
    assert call[2] == "1234-99-ai_block"


def test_ai_rollback_without_id_errors(monkeypatch, capsys):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["ai", "rollback", "--root", "/staged"])
    assert cli.cmd_ai(args) == 1
    assert "needs an id" in capsys.readouterr().err
    assert fake.calls == []   # never shelled out


@pytest.mark.parametrize("action", ["accept", "reject"])
def test_ai_accept_reject_pass_id(monkeypatch, action):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["ai", action, "abc123", "--root", "/staged"])
    assert cli.cmd_ai(args) == 0
    call = next(c for c in fake.calls if c[1] == action)
    assert call[2] == "abc123"


@pytest.mark.parametrize("action", ["accept", "reject"])
def test_ai_accept_reject_without_id_errors(monkeypatch, action, capsys):
    fake = FakeSystem(Path("/staged"))
    _patch_ctx(monkeypatch, fake)
    args = cli.build_parser().parse_args(["ai", action, "--root", "/staged"])
    assert cli.cmd_ai(args) == 1
    assert "needs an id" in capsys.readouterr().err
    assert fake.calls == []
