"""L3 ai-analysis layer (Phase 4 / L3 gate).

Staged install writes the full pipeline (scripts, units, backend.conf, intent.schema.json) but
applies no live user/ownership/timer changes. The AI timer is opt-in: install must NOT enable it.
"""
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


def test_l3_in_registry():
    l3 = layers.get("l3")
    assert "l3" in layers.REGISTRY
    assert l3.title == "ai-analysis"
    assert l3.prerequisites == ("l0", "l1")


def test_l3_status_fresh_system_not_installed(tmp_path):
    st = layers.get("l3").status(_ctx(tmp_path, {}))
    assert st.installed is False
    assert "missing" in st.detail


def test_l3_install_writes_full_pipeline(tmp_path):
    config = state.load_conf(EXAMPLE)
    ctx = _ctx(tmp_path, config)
    layers.get("l3").install(ctx)

    for s in ("edge-ai-collect", "edge-ai-analyze", "edge-ai-backend-claude",
              "edge-ai-backend-mock", "edge-ctl"):
        p = tmp_path / f"usr/local/sbin/{s}"
        assert p.is_file() and p.stat().st_mode & 0o111

    for u in ("edge-ai-collect.service", "edge-ai.service", "edge-ai.timer"):
        assert (tmp_path / f"etc/systemd/system/{u}").is_file()

    # Configs rendered (intent.schema.json must be extracted + installed — the analyzer needs it).
    assert (tmp_path / "etc/edge-ai/backend.conf").is_file()
    schema = tmp_path / "etc/edge-ai/intent.schema.json"
    assert schema.is_file()
    assert '"intents"' in schema.read_text()      # is the real schema, fully resolved
    assert "{{" not in schema.read_text()

    st = layers.get("l3").status(ctx)
    assert st.installed is True
    # AI is opt-in: a staged install reports disarmed, never armed.
    assert st.active is False


def test_l3_pipeline_requires_is_internal_only():
    # The canonical §3#3 exception: edge-ai.service Requires= its OWN collector, nothing external.
    svc = (TEMPLATES / "systemd/edge-ai.service").read_text()
    assert "Requires=edge-ai-collect.service" in svc
    # No hard dep on anything outside the L3 subsystem.
    for external in ("Requires=crowdsec", "Requires=nftables", "BindsTo="):
        assert external not in svc
