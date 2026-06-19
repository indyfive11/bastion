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


def _nft_check(text: str):
    """Run `nft -c -f -` in an unprivileged netns if available; return (ran, ok). Skips cleanly when
    nft/unshare aren't present (CI bare runners) — the render+placeholder asserts still gate syntax."""
    import shutil
    import subprocess
    if not (shutil.which("nft") and shutil.which("unshare")):
        return False, True
    p = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", "-"],
                       input=text, capture_output=True, text=True)
    return True, p.returncode == 0, p.stderr


def test_real_nft_templates_render_valid_with_service_ports():
    # The service_ports allowlist must render into BOTH rulesets as valid `dport { } accept` lines,
    # and a blank value must leave NO empty-brace `dport { }` (an nft syntax error).
    from bastion import state, templates
    cfg = state.load_conf(EXAMPLE)
    cfg["network"]["service_ports"] = "8096, 7878/tcp, 53/udp"
    for tmpl in ("nftables-edge.nft", "nftables-endpoint.nft"):
        out = templates.render_file(TEMPLATES / tmpl, cfg)
        assert "tcp dport { 8096, 7878 } accept" in out, tmpl
        assert "udp dport { 53 } accept" in out, tmpl
        assert templates.find_placeholders(out) == set()
        ran, ok, *err = _nft_check(out)
        assert ok, f"{tmpl} failed nft -c: {err}"

    cfg["network"]["service_ports"] = ""               # blank -> both accept lines vanish
    for tmpl in ("nftables-edge.nft", "nftables-endpoint.nft"):
        out = templates.render_file(TEMPLATES / tmpl, cfg)
        assert "dport {  } accept" not in out and "dport { } accept" not in out, tmpl
        ran, ok, *err = _nft_check(out)
        assert ok, f"{tmpl} (blank service_ports) failed nft -c: {err}"


def test_real_nft_templates_render_valid_with_zones():
    # The zones primitive must render the full source->action matrix into BOTH rulesets as valid
    # inline rules, and a blank [zones] must leave the chain syntactically valid. Models the EM
    # validation fixture (CIDR/iface/any sources; ports + `all`) — proving the trusted_hosts CIDR
    # named-set bug is sidestepped (inline `ip saddr <cidr>` needs no `flags interval`).
    from bastion import state, templates
    cfg = state.load_conf(EXAMPLE)
    cfg["zones"] = {
        "lan": "192.168.1.0/24 -> 8096, 8989, 7878",
        "ztmedia": "192.168.192.0/24 -> 8096, 1111",
        "wg": "10.0.0.0/24 -> 22, 1111",
        "ztctl": "any -> 9993",
        "vms": "iface:virbr0 -> all",
    }
    for tmpl in ("nftables-edge.nft", "nftables-endpoint.nft"):
        out = templates.render_file(TEMPLATES / tmpl, cfg)
        assert "ip saddr 192.168.1.0/24 tcp dport { 8096, 8989, 7878 } accept" in out, tmpl
        assert 'iifname "virbr0" accept' in out, tmpl
        assert "tcp dport { 9993 } accept" in out, tmpl
        assert templates.find_placeholders(out) == set()
        ran, ok, *err = _nft_check(out)
        assert ok, f"{tmpl} (zones matrix) failed nft -c: {err}"

    cfg["zones"] = {}                                  # blank [zones] -> chain still valid
    for tmpl in ("nftables-edge.nft", "nftables-endpoint.nft"):
        out = templates.render_file(TEMPLATES / tmpl, cfg)
        assert templates.find_placeholders(out) == set()
        ran, ok, *err = _nft_check(out)
        assert ok, f"{tmpl} (blank zones) failed nft -c: {err}"


def _load_with_seeded_libvirt(ruleset_text: str):
    """In a fresh netns: seed a foreign `table ip libvirt_network`, load `ruleset_text` via a real
    `nft -f`, then return (returncode, tables_listing). Returns None when nft/unshare are absent
    (CI bare runner) so the caller can skip. Proves at unit level whether the load preserves or
    wipes a co-resident table — the cooperative-vs-exclusive differentiator."""
    import os, shutil, subprocess, tempfile
    if not (shutil.which("nft") and shutil.which("unshare")):
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(ruleset_text); path = f.name
    seed = ("nft add table ip libvirt_network; "
            "nft add chain ip libvirt_network pr '{ type nat hook postrouting priority 100; }'; ")
    try:
        p = subprocess.run(["unshare", "-rn", "bash", "-c",
                            f"{seed} nft -f {path} && nft list tables"],
                           capture_output=True, text=True)
    finally:
        os.unlink(path)
    return p.returncode, p.stdout + p.stderr


def test_cooperative_preamble_preserves_libvirt_exclusive_wipes_it():
    # The P2 differentiator at unit level: load the rendered edge ruleset into a netns that already
    # has a foreign `table ip libvirt_network`. Cooperative scope must leave it intact (and recreate
    # bastion's OWN tables fresh); exclusive scope's `flush ruleset` must wipe it.
    from bastion import state, templates
    cfg = state.load_conf(EXAMPLE)

    cfg["machine"]["firewall_scope"] = "cooperative"
    coop = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    assert "flush ruleset" not in coop and "delete table inet edge" in coop
    res = _load_with_seeded_libvirt(coop)
    if res is not None:
        rc, tables = res
        assert rc == 0, f"cooperative load failed: {tables}"
        assert "libvirt_network" in tables, "cooperative scope WIPED the co-resident libvirt table"
        assert "table inet edge" in tables and "table ip edge_nat" in tables  # bastion's own, fresh

    cfg["machine"]["firewall_scope"] = "exclusive"
    excl = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    assert "flush ruleset" in excl and "delete table inet edge" not in excl
    res = _load_with_seeded_libvirt(excl)
    if res is not None:
        rc, tables = res
        assert rc == 0, f"exclusive load failed: {tables}"
        assert "libvirt_network" not in tables, "exclusive `flush ruleset` should wipe libvirt"
        assert "table inet edge" in tables


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
