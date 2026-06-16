"""The UI-agnostic action layer (bastion/actions.py) — the command surface the TUI/GUI consume.

These are the real substance behind `bastion tui`: the registry covers the whole CLI, argv is
built correctly from parameters, the risk tiers drive confirmation gating, and run_action shells
out to the bastion CLI capturing (rc, output). No Textual / terminal needed.
"""
import subprocess
from pathlib import Path

import pytest

from bastion import actions
from bastion.layers.base import Context
from bastion.system import System

TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"


class RecordingSystem(System):
    def __init__(self, root: Path, rc=0, out="ok"):
        super().__init__(root=root)
        self._rc, self._out = rc, out
        self.ran = []

    def run(self, *args, capture=True, input=None):
        self.ran.append(args)
        return subprocess.CompletedProcess(args, self._rc, self._out, "")


def _ctx(root="/"):
    return Context(system=RecordingSystem(Path(root)), config={},
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


# --- registry completeness ------------------------------------------------------------------
CLI_SUBCOMMANDS = {  # every top-level subcommand except `tui` itself
    "setup", "generate", "status", "layer", "firewall", "ai", "snapshot", "snapshots",
    "rollback", "confirm", "recovery", "update", "verify", "doctor", "check",
}


def test_registry_covers_every_cli_subcommand():
    covered = {a.argv[0] for a in actions.ACTIONS}
    assert CLI_SUBCOMMANDS <= covered, f"uncovered: {CLI_SUBCOMMANDS - covered}"


def test_ids_unique_and_lookup():
    ids = [a.id for a in actions.ACTIONS]
    assert len(ids) == len(set(ids))
    assert actions.get("layer.install").argv == ("layer", "install")
    assert actions.get("nope") is None


def test_risk_tiers_assigned_sanely():
    # layer teardown + network rollback + setup are the typed-confirm destructive ones
    for dest in ("layer.install", "layer.uninstall", "firewall.reload", "rollback", "setup"):
        a = actions.get(dest)
        assert a.risk == actions.DESTRUCTIVE and a.needs_typed_confirm
    # reads never confirm
    for r in ("status", "verify", "doctor", "ai.status", "snapshots"):
        assert not actions.get(r).needs_confirm
    # the AI kill switch mutates -> at least a single confirm
    assert actions.get("ai.panic").needs_confirm and not actions.get("ai.panic").needs_typed_confirm


# --- argv building --------------------------------------------------------------------------
def test_positional_param_appended():
    a = actions.get("layer.install")
    assert a.build_subargv({"layer": "l3"}) == ["layer", "install", "l3"]


def test_flag_param_emitted_as_flag():
    a = actions.get("snapshot")
    assert a.build_subargv({"name": "pre-ssh"}) == ["snapshot", "--name", "pre-ssh"]
    assert a.build_subargv({}) == ["snapshot"]            # optional, omitted when blank


def test_missing_required_param_raises():
    with pytest.raises(actions.ActionError):
        actions.get("ai.accept").build_subargv({})


def test_bad_choice_rejected():
    with pytest.raises(actions.ActionError):
        actions.get("layer.install").build_subargv({"layer": "l9"})


def test_confirm_phrase_is_primary_target():
    assert actions.get("layer.uninstall").confirm_phrase({"layer": "l0"}) == "l0"
    assert actions.get("firewall.reload").confirm_phrase({}) == "yes"   # no positional target


# --- execution ------------------------------------------------------------------------------
def test_run_action_builds_full_argv_and_captures(monkeypatch):
    monkeypatch.setattr(actions, "resolve_entrypoint", lambda: ["bastion"])
    ctx = _ctx()
    res = actions.run_action(ctx, actions.get("ai.panic"))
    assert ctx.system.ran[-1] == ("bastion", "ai", "panic")
    assert res.ok and res.output == "ok"


def test_run_action_passes_staged_root(monkeypatch):
    monkeypatch.setattr(actions, "resolve_entrypoint", lambda: ["bastion"])
    ctx = _ctx(root="/staged")
    actions.run_action(ctx, actions.get("status"))
    assert ctx.system.ran[-1] == ("bastion", "status", "--health", "--root", "/staged")


def test_generate_uses_out_not_root_for_staging(monkeypatch):
    monkeypatch.setattr(actions, "resolve_entrypoint", lambda: ["bastion"])
    ctx = _ctx(root="/staged")
    actions.run_action(ctx, actions.get("generate"))
    assert ctx.system.ran[-1] == ("bastion", "generate", "--out", "/staged")


def test_run_action_refuses_interactive(monkeypatch):
    monkeypatch.setattr(actions, "resolve_entrypoint", lambda: ["bastion"])
    with pytest.raises(actions.ActionError):
        actions.run_action(_ctx(), actions.get("setup"))


def test_resolve_entrypoint_prefers_installed(monkeypatch):
    monkeypatch.setattr(actions.shutil, "which", lambda n: "/usr/bin/bastion")
    assert actions.resolve_entrypoint() == ["/usr/bin/bastion"]
    monkeypatch.setattr(actions.shutil, "which", lambda n: None)
    assert actions.resolve_entrypoint()[1:] == ["-m", "bastion"]


def test_by_group_preserves_and_partitions():
    groups = actions.by_group()
    assert "Layers" in groups and "AI" in groups
    flat = [a.id for items in groups.values() for a in items]
    assert sorted(flat) == sorted(a.id for a in actions.ACTIONS)
