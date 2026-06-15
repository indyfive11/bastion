"""Integration tests for `bastion generate`, including the Phase 2 gate."""
from pathlib import Path

from bastion import cli

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"


def test_generate_check_passes_against_example():
    """Phase 2 GATE: every template placeholder resolves against machine.conf.example."""
    rc = cli.main(["generate", "--check", "--conf", str(EXAMPLE), "--templates", str(TEMPLATES)])
    assert rc == 0


def test_generate_check_fails_on_incomplete_conf(tmp_path):
    bad = tmp_path / "machine.conf"
    bad.write_text("[machine]\nmode = edge\n")  # missing everything the templates need
    rc = cli.main(["generate", "--check", "--conf", str(bad), "--templates", str(TEMPLATES)])
    assert rc == 1


def test_generate_writes_resolved_files_under_out(tmp_path):
    rc = cli.main(["generate", "--conf", str(EXAMPLE), "--templates", str(TEMPLATES), "--out", str(tmp_path)])
    assert rc == 0
    nft = tmp_path / "etc/nftables.conf"           # edge mode -> nftables-edge.nft
    assert nft.is_file()
    body = nft.read_text()
    assert "{{" not in body                         # fully resolved
    assert 'iifname "eth0"' in body                 # interfaces.lan rendered
    assert (tmp_path / "etc/bastion/machine.env").is_file()
    assert (tmp_path / "etc/systemd/system/edge-ai.service").is_file()


def test_generate_endpoint_mode_picks_endpoint_template(tmp_path):
    conf = tmp_path / "machine.conf"
    text = EXAMPLE.read_text().replace("mode = edge", "mode = endpoint")
    conf.write_text(text)
    rc = cli.main(["generate", "--conf", str(conf), "--templates", str(TEMPLATES), "--out", str(tmp_path)])
    assert rc == 0
    body = (tmp_path / "etc/nftables.conf").read_text()
    # endpoint template has an input chain but no forward chain / NAT table
    assert "chain input" in body
    assert "chain forward" not in body
    assert "edge_nat" not in body


def _partial_endpoint_conf(tmp_path) -> Path:
    """minimal-endpoint: mode=endpoint, layers=l0,l1,l6 (no L3/L4)."""
    conf = tmp_path / "machine.conf"
    text = (EXAMPLE.read_text().replace("mode = edge", "mode = endpoint")
            .replace("layers = l0,l1,l2,l3,l4,l5,l6", "layers = l0,l1,l6"))
    conf.write_text(text)
    return conf


def test_generate_partial_profile_writes_only_active_layer_configs(tmp_path):
    # The reconcile fix: an endpoint profile without L3/L4 must NOT write dnsmasq/unbound/edge-ai.
    conf = _partial_endpoint_conf(tmp_path)
    rc = cli.main(["generate", "--conf", str(conf), "--templates", str(TEMPLATES), "--out", str(tmp_path)])
    assert rc == 0
    # active (L0/L1/L6) — written
    assert (tmp_path / "etc/nftables.conf").is_file()
    assert (tmp_path / "etc/edge-reconciler/policy.allowlist").is_file()
    assert (tmp_path / "etc/systemd/system/edge-reconciler.service").is_file()
    assert (tmp_path / "etc/systemd/system/edge-watchdog.service").is_file()
    assert (tmp_path / "etc/bastion/machine.env").is_file()
    # inactive (L3 AI / L4 dns-dhcp) — NOT written
    assert not (tmp_path / "etc/dnsmasq.conf").exists()
    assert not (tmp_path / "etc/unbound/unbound.conf").exists()
    assert not (tmp_path / "etc/edge-ai/backend.conf").exists()
    assert not (tmp_path / "etc/systemd/system/edge-ai.service").exists()
    assert not (tmp_path / "etc/systemd/system/edge-dnsblock.service").exists()


def test_generate_check_scoped_to_active_layers(tmp_path):
    # A conf that resolves the active layers' templates passes --check even if it lacked keys an
    # inactive layer would need (here the example has all keys, so this just confirms scoping runs).
    conf = _partial_endpoint_conf(tmp_path)
    rc = cli.main(["generate", "--check", "--conf", str(conf), "--templates", str(TEMPLATES)])
    assert rc == 0


def test_real_nft_templates_render_valid_with_blank_trusted_hosts():
    # Regression: blank trusted_hosts (wizard offers "blank = none") must not emit the invalid
    # `elements = {  }`. The shipped example has trusted_hosts set, so generate-check never hit
    # this — render the real edge AND endpoint rulesets with it blanked and assert validity.
    from bastion import state, templates
    cfg = state.load_conf(EXAMPLE)
    cfg["network"]["trusted_hosts"] = ""
    for tmpl in ("nftables-edge.nft", "nftables-endpoint.nft"):
        out = templates.render_file(TEMPLATES / tmpl, cfg)
        assert "elements = {  }" not in out, f"{tmpl} emitted empty-brace elements"
        assert "set trusted_hosts" in out
        assert templates.find_placeholders(out) == set()


def test_active_template_rels_excludes_inactive_layers():
    from bastion import state
    conf = {"machine": {"mode": "endpoint", "layers": "l0,l1,l6"}}
    rels = cli.active_template_rels(conf, "endpoint")
    assert "nftables-endpoint.nft" in rels and "policy.allowlist" in rels
    assert "systemd/edge-watchdog.service" in rels
    assert "dnsmasq.conf" not in rels            # L4 inactive
    assert "backend.conf" not in rels            # L3 inactive
    # unset layers -> all layers (back-compat)
    allrels = cli.active_template_rels({"machine": {}}, "edge")
    assert "dnsmasq.conf" in allrels and "backend.conf" in allrels
