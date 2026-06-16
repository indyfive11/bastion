"""Sprint-2 'engine' items: E3, E4, E5, and #2 (schema_version + bastion migrate + artifact-drift)."""
import json
from pathlib import Path

import pytest

from bastion import cli, state
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


# --------------------------------------------------------------------------- E5
class _Sys(System):
    def __init__(self, root, *, live, root_uid):
        super().__init__(root=Path(root))
        self._live = live
        self._root = root_uid

    @property
    def is_live(self):  return self._live
    @property
    def is_root(self):  return self._root


def test_require_root_blocks_only_live_nonroot(tmp_path, capsys):
    assert cli._require_root(_Sys(tmp_path, live=True, root_uid=True), "x") is True     # root
    assert cli._require_root(_Sys(tmp_path, live=False, root_uid=False), "x") is True   # staged
    assert cli._require_root(_Sys(tmp_path, live=True, root_uid=False), "bastion ai") is False
    assert "needs root" in capsys.readouterr().err


# --------------------------------------------------------------------------- #2 schema/migrate
def test_example_conf_is_current_schema():
    cfg = state.load_conf(EXAMPLE)
    assert state.conf_schema_version(cfg) == state.CONF_SCHEMA_VERSION == 1


def test_conf_schema_version_absent_is_zero():
    assert state.conf_schema_version({"machine": {}}) == 0
    assert state.conf_schema_version({}) == 0


def test_migrate_conf_stamps_and_is_idempotent():
    old = {"machine": {"mode": "edge"}}
    new, changes, start = state.migrate_conf(old)
    assert start == 0 and new["machine"]["schema_version"] == "1" and changes
    assert old == {"machine": {"mode": "edge"}}          # input not mutated
    again, changes2, start2 = state.migrate_conf(new)
    assert start2 == 1 and changes2 == []                # already current


def test_wizard_stamps_schema_version():
    # the wizard writes schema_version into every freshly-built conf (so new installs are current)
    assert 'put("machine", "schema_version"' in (REPO / "bastion" / "setup" / "wizard.py").read_text()


def test_cmd_migrate_check_then_write(tmp_path, capsys):
    conf = tmp_path / "machine.conf"
    conf.write_text("\n".join(l for l in EXAMPLE.read_text().splitlines()
                              if not l.strip().startswith("schema_version")) + "\n")
    assert cli.main(["migrate", "--check", "--conf", str(conf)]) == 1     # due
    assert cli.main(["migrate", "--conf", str(conf)]) == 0                # writes
    assert state.conf_schema_version(state.load_conf(conf)) == 1
    assert cli.main(["migrate", "--check", "--conf", str(conf)]) == 0     # now current


# --------------------------------------------------------------------------- #2 artifact drift
def _staged_ctx(root: Path) -> Context:
    return Context(system=System(root=root), config=state.load_conf(EXAMPLE),
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_artifact_drift_detects_stale_script(tmp_path):
    from bastion import layers
    ctx = _staged_ctx(tmp_path)
    layers.get("l0").install(ctx)                        # stages bastion-recovery into the tree
    assert cli._artifact_drift(ctx) == []                # fresh install matches the package
    # simulate a package upgrade without re-running `layer install`: the deployed copy is now stale
    sbin = tmp_path / "usr/local/sbin/bastion-recovery"
    sbin.write_text(sbin.read_text() + "\n# stale deployed copy\n")
    assert dict(cli._artifact_drift(ctx)).get("bastion-recovery") == "STALE"


def test_doctor_reports_schema_and_artifact_lines(tmp_path, capsys):
    from bastion import layers
    ctx = _staged_ctx(tmp_path)
    layers.get("l0").install(ctx)
    cli.main(["doctor", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert "config schema" in out and "artifact drift" in out


# --------------------------------------------------------------------------- E3 / E4
def test_run_tui_has_no_dead_code_after_return():
    body = (REPO / "bastion" / "tui.py").read_text()
    # the unreachable block referenced ACTIONS/BastionTUI which don't exist in tui.py
    assert "BastionTUI(ctx).run()" not in body
    assert "for a in ACTIONS:" not in body


def test_tui_app_runs_action_off_the_event_loop():
    body = (REPO / "bastion" / "_tui_app.py").read_text()
    assert "asyncio.to_thread(actmod.run_action" in body   # E3: blocking call offloaded to a thread
