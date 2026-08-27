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
    assert state.conf_schema_version(cfg) == state.CONF_SCHEMA_VERSION == 2


def test_conf_schema_version_absent_is_zero():
    assert state.conf_schema_version({"machine": {}}) == 0
    assert state.conf_schema_version({}) == 0


def test_migrate_conf_stamps_and_is_idempotent():
    old = {"machine": {"mode": "edge"}}
    new, changes, start = state.migrate_conf(old)
    # v0 -> v2 runs both steps: stamps schema_version AND adds the v2 firewall_scope default.
    assert start == 0 and new["machine"]["schema_version"] == "2" and changes
    assert new["machine"]["firewall_scope"] == "exclusive"
    assert old == {"machine": {"mode": "edge"}}          # input not mutated
    again, changes2, start2 = state.migrate_conf(new)
    assert start2 == 2 and changes2 == []                # already current


def test_wizard_stamps_schema_version():
    # the wizard writes schema_version into every freshly-built conf (so new installs are current)
    assert 'put("machine", "schema_version"' in (REPO / "bastion" / "setup" / "wizard.py").read_text()


def test_cmd_migrate_check_then_write(tmp_path, capsys):
    conf = tmp_path / "machine.conf"
    conf.write_text("\n".join(l for l in EXAMPLE.read_text().splitlines()
                              if not l.strip().startswith("schema_version")) + "\n")
    assert cli.main(["migrate", "--check", "--conf", str(conf)]) == 1     # due
    assert cli.main(["migrate", "--conf", str(conf)]) == 0                # writes
    assert state.conf_schema_version(state.load_conf(conf)) == 2
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


# --------------------------------------------------------------------------- W4: bastion upgrade
def _install_l0(tmp_path):
    from bastion import layers
    layers.get("l0").install(_staged_ctx(tmp_path))          # deploys bastion-recovery to the tree
    return tmp_path / "usr/local/sbin/bastion-recovery"


def test_upgrade_redeploys_stale_script(tmp_path, capsys):
    sbin = _install_l0(tmp_path)
    pkg = (SCRIPTS / "bastion-recovery").read_bytes()
    sbin.write_text(sbin.read_text() + "\n# stale deployed copy\n")   # simulate wheel upgrade
    assert sbin.read_bytes() != pkg
    rc = cli.main(["upgrade", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert sbin.read_bytes() == pkg                          # redeployed to the package copy
    assert "bastion-recovery (STALE)" in out and "redeployed" in out


def test_upgrade_check_touches_nothing(tmp_path, capsys):
    sbin = _install_l0(tmp_path)
    stale = sbin.read_text() + "\n# stale\n"
    sbin.write_text(stale)
    rc = cli.main(["upgrade", "--check", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1                                           # drift present ⇒ action-needed signal
    assert sbin.read_text() == stale                         # --check wrote nothing
    assert "would redeploy" in out


def test_upgrade_reinstalls_missing_script(tmp_path, capsys, monkeypatch):
    # MISSING is reachable only when a layer reports INSTALLED yet one of its scripts is absent
    # (a real layer's status() gates on all its scripts, so a deleted sole-script reads uninstalled
    # and is skipped — the correct H13 boundary: pacman -U never DELETES the sbin copy). Prove the
    # branch at the unit level with a layer that reports installed but was never deployed.
    from types import SimpleNamespace
    from bastion.layers.base import Layer, LayerStatus

    real_install_script = Layer.install_script
    lx = SimpleNamespace(
        name="lx", scripts=("bastion-recovery",),
        status=lambda ctx: LayerStatus("lx", "x", installed=True, active=False),
        install_script=lambda ctx, name: real_install_script(lx, ctx, name),
    )
    monkeypatch.setattr(cli.layermod, "all_layers", lambda: [lx])
    sbin = tmp_path / "usr/local/sbin/bastion-recovery"
    assert not sbin.exists()
    rc = cli.main(["upgrade", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert sbin.read_bytes() == (SCRIPTS / "bastion-recovery").read_bytes()
    assert "bastion-recovery (MISSING)" in out


def test_upgrade_clean_is_noop(tmp_path, capsys):
    _install_l0(tmp_path)                                    # fresh install already matches package
    rc = cli.main(["upgrade", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0 and "nothing to redeploy" in out


def test_upgrade_undeterminable_is_loud_not_silent_clean(tmp_path, capsys, monkeypatch):
    # F4 / distrust-your-negatives: a layer whose status() throws must WARN + exit non-zero, never
    # read as "nothing to redeploy".
    from types import SimpleNamespace

    def _boom(ctx):
        raise RuntimeError("status exploded")

    bad = SimpleNamespace(name="lx", scripts=("edge-reconciler",), status=_boom)
    monkeypatch.setattr(cli.layermod, "all_layers", lambda: [bad])
    rc = cli.main(["upgrade", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "could not check" in err and "lx" in err


# --------------------------------------------------------------------------- E3 / E4
def test_run_tui_has_no_dead_code_after_return():
    body = (REPO / "bastion" / "tui.py").read_text()
    # the unreachable block referenced ACTIONS/BastionTUI which don't exist in tui.py
    assert "BastionTUI(ctx).run()" not in body
    assert "for a in ACTIONS:" not in body


def test_tui_app_runs_action_off_the_event_loop():
    body = (REPO / "bastion" / "_tui_app.py").read_text()
    assert "asyncio.to_thread(actmod.run_action" in body   # E3: blocking call offloaded to a thread
