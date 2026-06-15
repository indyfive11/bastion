"""L2 crowdsec layer (Phase 4 / L2 gate).

L2 owns no bastion files — it manages the distro-packaged crowdsec.service and reuses the L1
reconciler as the bouncer. Its live checks (cscli present, unit active) query the real host
regardless of --root, so the deterministic tests assert the structural invariants; health_check
correctness against a running agent is validated separately on ES (the reference machine).
"""
from pathlib import Path

from bastion import layers
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict) -> Context:
    return Context(system=System(root=root, dry_run=True), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l2_in_registry():
    l2 = layers.get("l2")
    assert "l2" in layers.REGISTRY
    assert l2.title == "crowdsec"
    assert l2.prerequisites == ("l0", "l1")


def test_l2_owns_no_bastion_files():
    # Commandment #7: no second nft writer. L2 installs no script/unit/template — the L1
    # reconciler is the sole bouncer. This invariant guards against a firewall-bouncer creeping in.
    l2 = layers.get("l2")
    assert l2.scripts == ()
    assert l2.units == ()
    assert l2.template_dests == ()


def test_l2_staged_install_writes_nothing(tmp_path):
    # A non-live install only manages the system crowdsec.service; it must not touch the tree.
    layers.get("l2").install(_ctx(tmp_path, {}))
    assert not any(tmp_path.iterdir())


def test_l2_table_selection_by_mode():
    l2 = layers.get("l2")
    assert l2._table(_ctx(Path("/"), {"machine": {"mode": "edge"}})) == ("inet", "edge")
    assert l2._table(_ctx(Path("/"), {"machine": {"mode": "endpoint"}})) == ("inet", "bastion")
