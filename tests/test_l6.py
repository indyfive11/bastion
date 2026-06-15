"""L6 monitoring layer (Phase 4 / L6 gate)."""
from pathlib import Path

from bastion import layers, state
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict, dry_run=True) -> Context:
    return Context(system=System(root=root, dry_run=dry_run), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l6_in_registry():
    l6 = layers.get("l6")
    assert "l6" in layers.REGISTRY
    assert l6.title == "monitoring"


def test_l6_install_writes_full_monitoring_surface(tmp_path):
    config = state.load_conf(EXAMPLE)
    ctx = _ctx(tmp_path, config)
    layers.get("l6").install(ctx)

    for s in ("edge-watchdog", "net-snapshot", "net-rollback", "flowcheck",
              "lan-verify", "net-confirm", "notify-alert", "notify-failure"):
        p = tmp_path / f"usr/local/sbin/{s}"
        assert p.is_file() and p.stat().st_mode & 0o111

    # Both units, including the OnFailure shim template (extracted this layer).
    assert (tmp_path / "etc/systemd/system/edge-watchdog.service").is_file()
    assert (tmp_path / "etc/systemd/system/notify-failure@.service").is_file()

    # edge-watchdog.service had a {{ interfaces.wg_vps_iface }} placeholder — fully resolved.
    wd = (tmp_path / "etc/systemd/system/edge-watchdog.service").read_text()
    assert "{{" not in wd

    st = layers.get("l6").status(ctx)
    assert st.installed is True


def test_l6_does_not_install_operator_alert_conf(tmp_path):
    # notify-alert.conf holds the ntfy topic / email (operator secret) — never installed by L6.
    layers.get("l6").install(_ctx(tmp_path, state.load_conf(EXAMPLE)))
    assert not (tmp_path / "etc/bastion/notify-alert.conf").exists()
    assert layers.get("l6").template_dests == ()
