"""L5 vpn layer (Phase 4 / L5 gate).

L5 owns no bastion files — WireGuard keys and the ZeroTier network ID are secrets and can
never enter the repo (Commandments #1/#8); the firewall's VPN policy routing already lives in
L0's nft template. The deterministic tests assert that no-files invariant and the machine.conf
interface discovery; live tunnel state is validated on ES.
"""
from pathlib import Path

from bastion import layers, state
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict) -> Context:
    return Context(system=System(root=root, dry_run=True), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l5_in_registry():
    l5 = layers.get("l5")
    assert "l5" in layers.REGISTRY
    assert l5.title == "vpn"
    assert l5.prerequisites == ("l0",)


def test_l5_owns_no_committed_files():
    # No keys / configs / units in the repo — VPN material is secret.
    l5 = layers.get("l5")
    assert l5.scripts == ()
    assert l5.units == ()
    assert l5.template_dests == ()


def test_l5_discovers_configured_interfaces():
    l5 = layers.get("l5")
    ctx = _ctx(Path("/"), state.load_conf(EXAMPLE))
    assert l5._wg_ifaces(ctx) == ["wg0", "wg_vps"]
    assert l5._zt_configured(ctx) is True


def test_l5_no_interfaces_when_unconfigured():
    l5 = layers.get("l5")
    ctx = _ctx(Path("/"), {"interfaces": {}})
    assert l5._wg_ifaces(ctx) == []
    assert l5._zt_configured(ctx) is False


def test_l5_staged_install_writes_nothing(tmp_path):
    layers.get("l5").install(_ctx(tmp_path, state.load_conf(EXAMPLE)))
    assert not any(tmp_path.iterdir())
