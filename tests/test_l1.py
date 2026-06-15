"""L1 feeds layer + the NFT_TABLE machine.env derivation (Phase 4 / L1 gate)."""
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


def test_l1_in_registry():
    assert "l1" in layers.REGISTRY
    assert layers.get("l1").title == "feeds"
    assert layers.get("l1").prerequisites == ("l0",)


def test_l1_status_fresh_system_not_installed(tmp_path):
    st = layers.get("l1").status(_ctx(tmp_path, {}))
    assert st.installed is False
    assert "missing" in st.detail


def test_l1_install_then_status_installed(tmp_path):
    config = state.load_conf(EXAMPLE)
    ctx = _ctx(tmp_path, config)
    layers.get("l1").install(ctx)

    # Scripts installed + executable.
    for s in ("edge-reconciler", "edge-feed-fetch"):
        p = tmp_path / f"usr/local/sbin/{s}"
        assert p.is_file() and p.stat().st_mode & 0o111

    # Units installed.
    for u in ("edge-reconciler.service", "edge-reconciler.timer",
              "edge-feed.service", "edge-feed.timer"):
        assert (tmp_path / f"etc/systemd/system/{u}").is_file()

    # Runtime dirs created.
    assert (tmp_path / "var/lib/edge-reconciler").is_dir()
    assert (tmp_path / "var/log/edge-reconciler").is_dir()

    st = layers.get("l1").status(ctx)
    assert st.installed is True


def test_machine_env_nft_table_edge_vs_endpoint():
    config = state.load_conf(EXAMPLE)
    config.setdefault("machine", {})["mode"] = "edge"
    assert "NFT_TABLE='inet edge'" in state.render_machine_env(config)

    config["machine"]["mode"] = "endpoint"
    assert "NFT_TABLE='inet bastion'" in state.render_machine_env(config)


def test_reconciler_reads_nft_table_env():
    # The reconciler must not hardcode the table — it reads NFT_TABLE (machine-agnostic /
    # endpoint support). Guard against a regression back to a literal.
    body = (SCRIPTS / "edge-reconciler").read_text()
    assert 'os.environ.get("NFT_TABLE"' in body
