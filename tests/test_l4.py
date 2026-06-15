"""L4 dns-dhcp layer (Phase 4 / L4 gate). Edge-mode only; skipped on endpoint."""
from pathlib import Path

from bastion import layers, state, templates
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict, dry_run=True) -> Context:
    return Context(system=System(root=root, dry_run=dry_run), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l4_in_registry():
    l4 = layers.get("l4")
    assert "l4" in layers.REGISTRY
    assert l4.title == "dns-dhcp"


def test_l4_install_edge_writes_configs_and_seeds_blocklist(tmp_path):
    config = state.load_conf(EXAMPLE)          # mode = edge
    ctx = _ctx(tmp_path, config)
    layers.get("l4").install(ctx)

    assert (tmp_path / "usr/local/sbin/edge-dnsblock-update").is_file()
    assert (tmp_path / "etc/dnsmasq.conf").is_file()
    assert (tmp_path / "etc/unbound/unbound.conf").is_file()
    for u in ("edge-dnsblock.service", "edge-dnsblock.timer"):
        assert (tmp_path / f"etc/systemd/system/{u}").is_file()

    # dnsmasq.conf is fully resolved — no real {{ section.key }} placeholders remain.
    # (A literal "{{ }}" in a doc comment is not a placeholder and is left as-is.)
    assert templates.find_placeholders((tmp_path / "etc/dnsmasq.conf").read_text()) == set()
    # Empty sinkhole file seeded so unbound's include: starts before the first run.
    blk = tmp_path / "etc/unbound/blocklist.conf"
    assert blk.is_file() and "edge-dnsblock-update" in blk.read_text()

    st = layers.get("l4").status(ctx)
    assert st.installed is True


def test_l4_skipped_on_endpoint(tmp_path):
    config = state.load_conf(EXAMPLE)
    config["machine"]["mode"] = "endpoint"
    ctx = _ctx(tmp_path, config)
    layers.get("l4").install(ctx)
    # Nothing written under an endpoint install.
    assert not any(tmp_path.iterdir())

    st = layers.get("l4").status(ctx)
    assert st.installed is False
    assert "edge mode only" in st.detail
    # health_check returns a single N/A check, all ok.
    checks = layers.get("l4").health_check(ctx)
    assert len(checks) == 1 and checks[0].ok is True
