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


def test_collector_reads_nft_table_env():
    # The collector must not hardcode the managed table — on an endpoint it is `inet bastion`,
    # so a hardcoded `inet edge` makes every `nft list set` fail and `already_acted` go empty.
    body = (SCRIPTS / "edge-ai-collect").read_text()
    assert 'os.environ.get("NFT_TABLE"' in body
    assert 'TABLE_FAM, TABLE_NAME = "inet", "edge"' not in body


def test_collector_unit_supplies_machine_env():
    # NFT_TABLE only reaches the collector if its unit sources machine.env (`-` => optional).
    unit = (TEMPLATES / "systemd/edge-ai-collect.service").read_text()
    assert "EnvironmentFile=-/etc/bastion/machine.env" in unit


def test_killswitch_panic_fails_loud_on_flush_error():
    # `edge-ctl panic`/`ai-disable` must NOT report success when a flush errors (silent kill
    # switch). The error sets are collected and a non-zero exit is returned.
    body = (SCRIPTS / "edge-ctl").read_text()
    assert "_flush_failures" in body
    # both kill-switch paths return 1 on failure
    assert body.count("return 1 if (failed or not spool_ok) else 0") >= 1
    assert "PANIC INCOMPLETE" in body


def test_rollback_spool_prune_does_not_use_rstrip():
    # `str.rstrip("/32")` strips a CHARACTER CLASS ({/,3,2}), not the literal "/32": e.g.
    # "1.2.3.23/32".rstrip("/32") -> "1.2.3.". That would make the spool-prune miss the intent
    # and let the reconciler RE-ADD a rolled-back block. The fix must use suffix slicing instead.
    assert "1.2.3.23/32".rstrip("/32") == "1.2.3."        # the documented footgun, pinned
    body = (SCRIPTS / "edge-ctl").read_text()
    assert '.rstrip("/32")' not in body
    assert 'e[:-3] if e.endswith("/32") else e' in body
