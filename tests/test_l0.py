"""L0 core layer + `bastion status` (Phase 3 gate)."""
from pathlib import Path

from bastion import cli, layers, state
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict, dry_run=True) -> Context:
    return Context(system=System(root=root, dry_run=dry_run), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l0_in_registry():
    assert "l0" in layers.REGISTRY
    assert layers.get("l0").title == "core"


def test_l0_status_fresh_system_not_installed(tmp_path):
    st = layers.get("l0").status(_ctx(tmp_path, {}))
    assert st.installed is False
    assert "missing" in st.detail


def test_l0_install_then_status_installed(tmp_path):
    config = state.load_conf(EXAMPLE)
    ctx = _ctx(tmp_path, config)
    layers.get("l0").install(ctx)

    # All declared artifacts now exist under the staged root.
    assert (tmp_path / "etc/nftables.conf").is_file()
    assert (tmp_path / "etc/edge-reconciler/policy.allowlist").is_file()
    recovery = tmp_path / "usr/local/sbin/bastion-recovery"
    assert recovery.is_file() and recovery.stat().st_mode & 0o111  # executable
    assert (tmp_path / "etc/systemd/system/bastion-recovery.service").is_file()

    # Rendered ruleset is fully resolved.
    assert "{{" not in (tmp_path / "etc/nftables.conf").read_text()

    st = layers.get("l0").status(ctx)
    assert st.installed is True


def test_l0_endpoint_mode_installs_input_only_ruleset(tmp_path):
    config = state.load_conf(EXAMPLE)
    config["machine"]["mode"] = "endpoint"
    ctx = _ctx(tmp_path, config)
    layers.get("l0").install(ctx)
    body = (tmp_path / "etc/nftables.conf").read_text()
    assert "chain forward" not in body and "edge_nat" not in body


def test_cli_status_on_fresh_root_returns_zero(tmp_path, capsys):
    rc = cli.main(["status", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "l0" in out
    assert "no layers installed yet" in out
