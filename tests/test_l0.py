"""L0 core layer + `bastion status` (Phase 3 gate)."""
import subprocess
from pathlib import Path

import pytest

from bastion import cli, layers, state
from bastion.layers.base import Context, FirewallConflict
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


class _FwSys(System):
    """A live-claiming System whose chosen firewall reports active; run/command are stubbed so no
    real systemctl/nft runs. Lets us exercise the L0 live firewall-conflict guard in a test."""
    def __init__(self, root, active_fw=None):
        super().__init__(root=root)
        self._active_fw = active_fw

    @property
    def is_live(self) -> bool:
        return True

    def unit_active(self, unit: str) -> bool:
        return unit == self._active_fw

    def command_exists(self, name: str) -> bool:
        return True

    def run(self, *args, **kwargs):
        return subprocess.CompletedProcess(args, 0, "", "")


def _fw_ctx(root, active_fw):
    return Context(system=_FwSys(root, active_fw=active_fw), config=state.load_conf(EXAMPLE),
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l0_install_aborts_when_ufw_active(tmp_path):
    # bastion's ruleset would `flush ruleset` and wipe ufw — refuse, before touching anything.
    with pytest.raises(FirewallConflict) as exc:
        layers.get("l0").install(_fw_ctx(tmp_path, "ufw"))
    assert exc.value.firewall == "ufw"
    assert not (tmp_path / "etc/nftables.conf").exists()  # guard fired before any render


def test_l0_install_aborts_when_firewalld_active(tmp_path):
    with pytest.raises(FirewallConflict):
        layers.get("l0").install(_fw_ctx(tmp_path, "firewalld"))


def test_l0_install_override_env_allows_takeover(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_ALLOW_FIREWALL_TAKEOVER", "1")
    layers.get("l0").install(_fw_ctx(tmp_path, "ufw"))   # override → no raise
    assert (tmp_path / "etc/nftables.conf").is_file()


def test_l0_install_no_conflict_proceeds(tmp_path):
    layers.get("l0").install(_fw_ctx(tmp_path, None))    # nothing active
    assert (tmp_path / "etc/nftables.conf").is_file()


def test_cli_status_on_fresh_root_returns_zero(tmp_path, capsys):
    rc = cli.main(["status", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "l0" in out
    assert "no layers installed yet" in out
