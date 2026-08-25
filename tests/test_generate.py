"""Integration tests for `bastion generate`, including the Phase 2 gate."""
import shutil
from pathlib import Path

from bastion import cli, state, templates

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
WATCHDOG = TEMPLATES / "systemd" / "edge-watchdog.service"


# --- L33: edge-watchdog After= wg-quick ordering (blank-safe, both iface roles) ---

def test_watchdog_wg_after_matrix():
    """_watchdog_wg_after covers BOTH iface roles, dedupes, and vanishes when neither is set."""
    from bastion.templates import _watchdog_wg_after
    # both blank -> empty string (no trailing token, no empty instance)
    assert _watchdog_wg_after({"interfaces": {"wg_server_iface": "", "wg_vps_iface": ""}}) == ""
    assert _watchdog_wg_after({"interfaces": {}}) == ""
    # server only (the 1.5.16 endpoint WG-server case) -> orders after wg0
    assert _watchdog_wg_after(
        {"interfaces": {"wg_server_iface": "wg0", "wg_vps_iface": ""}}) == " wg-quick@wg0.service"
    # relay only -> orders after the relay
    assert _watchdog_wg_after(
        {"interfaces": {"wg_server_iface": "", "wg_vps_iface": "wg_vps"}}) == " wg-quick@wg_vps.service"
    # both set -> both tokens, server first (deterministic order)
    assert _watchdog_wg_after({"interfaces": {"wg_server_iface": "wg0", "wg_vps_iface": "wg_vps"}}) \
        == " wg-quick@wg0.service wg-quick@wg_vps.service"
    # same iface for both roles -> a SINGLE token (dedup, no wg-quick@wg0.service twice)
    assert _watchdog_wg_after(
        {"interfaces": {"wg_server_iface": "wg0", "wg_vps_iface": "wg0"}}) == " wg-quick@wg0.service"


def test_watchdog_render_never_empty_instance():
    """RED-PROVER: a blank-iface box must NOT render `wg-quick@.service`.

    This FAILS against the old hardcoded `wg-quick@{{ interfaces.wg_vps_iface }}.service` template
    (blank wg_vps_iface -> empty instance). generate-check on the example can never reach this — the
    example sets wg_vps_iface — so this blank-iface fixture is the actual L33 regression guard.
    """
    cfg = {"machine": {"mode": "endpoint"}, "interfaces": {"wg_server_iface": "wg0", "wg_vps_iface": ""}}
    out = templates.render_file(WATCHDOG, cfg)
    after = next(ln for ln in out.splitlines() if ln.startswith("After="))
    assert "wg-quick@.service" not in after           # the L33 defect
    assert after == "After=network.target nftables.service wg-quick@wg0.service"  # ordered after the real iface
    assert templates.find_placeholders(out) == set()  # nothing left unresolved
    # both blank -> the clause vanishes cleanly, no trailing space, no wg-quick token
    out2 = templates.render_file(WATCHDOG, {"machine": {"mode": "endpoint"}, "interfaces": {}})
    after2 = next(ln for ln in out2.splitlines() if ln.startswith("After="))
    assert after2 == "After=network.target nftables.service"


# --- L33: the generalizable empty-@-instance guard ---

def test_empty_instance_deps_detects_and_ignores():
    """empty_instance_deps flags only empty-instance tokens in DEPENDENCY directive values."""
    ei = templates.empty_instance_deps
    # offender last among multiple tokens (edge-watchdog's real shape) -> caught
    assert ei("After=network.target nftables.service wg-quick@.service") == ["wg-quick@.service"]
    assert ei("Wants=foo@.service\nRequires=bar@.socket") == ["foo@.service", "bar@.socket"]
    # NON-empty instance must NOT match (the '.' is not immediately after '@')
    assert ei("After=wg-quick@wg0.service") == []
    assert ei("Requires=getty@tty1.service foo@bar.service") == []
    # a plain (non-template) unit is fine
    assert ei("After=network.target nftables.service") == []
    # '@.' outside a dependency directive is harmless and ignored (ExecStart arg, comment, filename)
    assert ei("ExecStart=/usr/bin/x --unit foo@.service") == []
    assert ei("# see notify-failure@.service") == []
    assert ei("Description=notify-failure@.service shim") == []


def test_no_shipped_unit_has_empty_instance_dep():
    """Bound the guard's blast radius: EVERY shipped systemd unit, rendered against the example,
    has zero empty-instance dependencies (so the guard never false-fails a real generate)."""
    cfg = state.load_conf(EXAMPLE)
    units = sorted((TEMPLATES / "systemd").glob("*"))
    assert units, "no systemd unit templates found"
    for unit in units:
        offenders = templates.empty_instance_deps(templates.render_file(unit, cfg))
        assert offenders == [], f"{unit.name} renders an empty-instance dep: {offenders}"


def test_generate_guard_rejects_empty_instance_unit(tmp_path):
    """END-TO-END RED/GREEN: `generate --check` fails (rc 1) when a rendered unit would carry an
    empty template instance, and passes once the value is present."""
    # A blank-wg_vps_iface conf (the real-world trigger), derived from the example.
    conf = state.load_conf(EXAMPLE)
    conf.setdefault("interfaces", {})["wg_vps_iface"] = ""
    conf["interfaces"]["wg_server_iface"] = ""
    conf_path = tmp_path / "machine.conf"
    state.write_conf(conf, conf_path)

    # A templates tree whose edge-watchdog reintroduces the OLD hardcoded empty-instance line.
    broken = tmp_path / "templates"
    shutil.copytree(TEMPLATES, broken)
    wd = broken / "systemd" / "edge-watchdog.service"
    wd.write_text(wd.read_text().replace(
        "After=network.target nftables.service{{ network.watchdog_wg_ordering }}",
        "After=network.target nftables.service wg-quick@{{ interfaces.wg_vps_iface }}.service"))

    rc = cli.main(["generate", "--check", "--conf", str(conf_path), "--templates", str(broken)])
    assert rc == 1                                       # the guard goes RED on the broken unit

    # GREEN: the shipped (fixed) template, same blank conf -> guard passes.
    rc_ok = cli.main(["generate", "--check", "--conf", str(conf_path), "--templates", str(TEMPLATES)])
    assert rc_ok == 0


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


def test_real_nft_edge_scopes_zt_wg_control_ports():
    # M3: ZeroTier(9993)/WireGuard(51820) control-port accepts must be POSITIVELY scoped to the box's
    # non-WAN interfaces (not any-source), and must render valid nft even when the ZT/WG ifaces are
    # blank (a WG/ZT-less edge), where each gated rule VANISHES rather than leaving a bare
    # `iifname { }` (which nft rejects).
    from bastion import state, templates
    cfg = state.load_conf(EXAMPLE)                     # lan=eth0 zt=zt0 wg_server=wg0 wg_vps=wg_vps
    out = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    ifset = "{ eth0, zt0, wg0, wg_vps }"
    assert f"iifname {ifset} tcp dport 9993 accept" in out
    assert f"iifname {ifset} udp dport 9993 accept" in out
    assert f"iifname {ifset} udp dport 51820 accept" in out
    stripped = [ln.strip() for ln in out.splitlines()]
    assert "tcp dport 9993 accept" not in stripped     # the bare any-source form is gone
    assert "udp dport 51820 accept" not in stripped
    assert templates.find_placeholders(out) == set()
    ran, ok, *err = _nft_check(out)
    assert ok, f"scoped edge failed nft -c: {err}"

    # WG/ZT-less edge: the M3 rules must gate off cleanly. Tested at the helper (isolated from the
    # PRE-EXISTING forward-chain blank bug at nftables-edge.nft:126-136, `iifname ""` when zt/wg are
    # blank, which independently breaks the whole ruleset and is tracked as a separate fix).
    from bastion.templates import _nonwan_iface_accepts
    # no ZT, no WG server -> both ports vanish
    r = _nonwan_iface_accepts({"interfaces": {"lan": "eth0", "zt_iface": "", "wg_server_iface": "",
                                              "wg_vps_iface": "wg_vps"}})
    assert r["zt_accept_tcp"] == "" and r["zt_accept_udp"] == "" and r["wg_server_accept"] == ""
    # ZT present, WG server absent -> only the 9993 rules, scoped to the non-blank set, no bare braces
    r = _nonwan_iface_accepts({"interfaces": {"lan": "eth0", "zt_iface": "zt0",
                                              "wg_server_iface": "", "wg_vps_iface": ""}})
    assert r["zt_accept_tcp"] == "iifname { eth0, zt0 } tcp dport 9993 accept"
    assert r["zt_accept_udp"] == "iifname { eth0, zt0 } udp dport 9993 accept"
    assert r["wg_server_accept"] == ""
    for v in r.values():
        assert "{ }" not in v and "{  }" not in v and 'iifname ""' not in v
    # everything blank -> all vanish, never a bare `iifname { }`
    r = _nonwan_iface_accepts({"interfaces": {}})
    assert all(v == "" for v in r.values())


def test_real_nft_edge_m3b_fail_closed_input_drop():
    # M3b: the input-chain WAN drop is fail-CLOSED — `iifname != { <internal set> } drop` instead of
    # the fail-OPEN `iifname "{{wan}}" drop`. A renamed/mis-detected WAN can no longer expose the
    # any-source accepts below it. The WAN iface MUST be excluded from the internal set (else WAN
    # traffic matches `!=` false and is NOT dropped — the exact exposure being closed).
    from bastion import state, templates
    from bastion.templates import _internal_iface_drop
    cfg = state.load_conf(EXAMPLE)                     # lan=eth0 wan=eth1 zt=zt0 wg_server=wg0 wg_vps=wg_vps
    out = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    assert "iifname != { eth0, zt0, wg0, wg_vps } drop" in out
    stripped = [ln.strip() for ln in out.splitlines()]
    assert 'iifname "eth1" drop' not in stripped        # the fail-open literal drop is gone
    # false-green guard: WAN (eth1) must NOT be inside the internal set
    drop = next(ln.strip() for ln in out.splitlines() if ln.strip().startswith("iifname !="))
    assert "eth1" not in drop
    assert templates.find_placeholders(out) == set()
    ran, ok, *err = _nft_check(out)
    assert ok, f"M3b fail-closed drop failed nft -c: {err}"

    # helper edge cases (isolated from the render)
    # normal edge: internal = lan+overlays, wan excluded
    assert _internal_iface_drop({"interfaces": {"lan": "eth0", "wan": "eth1", "zt_iface": "zt0",
        "wg_server_iface": "wg0", "wg_vps_iface": "wg_vps"}}) == "iifname != { eth0, zt0, wg0, wg_vps } drop"
    # WG/ZT-less edge: set collapses to just lan, still fail-closed
    assert _internal_iface_drop({"interfaces": {"lan": "eth0", "wan": "eth1"}}) == "iifname != { eth0 } drop"
    # WAN name collision: wan excluded even when it appears among the internal names
    assert _internal_iface_drop({"interfaces": {"lan": "eth1", "wan": "eth1",
        "zt_iface": "zt0"}}) == "iifname != { zt0 } drop"
    # broken config with NO internal iface -> FALL BACK to the literal wan drop (never `!= { }`, nft-fatal)
    assert _internal_iface_drop({"interfaces": {"wan": "eth1"}}) == 'iifname "eth1" drop'
    for ifs in ({"interfaces": {"lan": "eth0", "wan": "eth1"}}, {"interfaces": {"wan": "eth1"}}):
        d = _internal_iface_drop(ifs)
        assert "!= { }" not in d and "!= {  }" not in d


def test_real_nft_edge_m2b_anti_spoof_gated():
    # M2b: forward-chain anti-spoof teeth gated by [network] anti_spoof (off|on|strict).
    #   off    -> no rules (no forwarding change)
    #   on     -> BCP38 v4 egress drop over the UNION of declared CIDRs (not lan_cidr alone — F3)
    #   strict -> on + a v6 reverse-path fib drop (v6-only on purpose)
    from bastion import state, templates
    from bastion.templates import _anti_spoof_rules

    def render(mode):
        cfg = state.load_conf(EXAMPLE)                 # lan_cidr 10.0.1.0/24, zt 10.147.17.0/24, wg 10.8.0.0/24, wan eth1
        cfg["network"] = dict(cfg["network"]); cfg["network"]["anti_spoof"] = mode
        return templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)

    off, on, strict = render("off"), render("on"), render("strict")
    for out in (off, on, strict):
        assert templates.find_placeholders(out) == set()
        ran, ok, *err = _nft_check(out)
        assert ok, f"anti_spoof render failed nft -c: {err}"
    # off: nothing
    assert "saddr !=" not in off and "fib saddr" not in off
    # on: BCP38 present, keyed on the UNION (false-green guard: all three CIDRs, not lan_cidr alone), no fib
    assert 'oifname "eth1" ip saddr != { 10.0.1.0/24, 10.147.17.0/24, 10.8.0.0/24 } drop' in on
    assert "fib saddr" not in on
    # strict: BCP38 + v6-only fib reverse-path
    assert "meta nfproto ipv6 fib saddr . iif oif missing drop" in strict
    assert 'oifname "eth1" ip saddr' in strict

    # helper edge cases
    assert _anti_spoof_rules({"network": {"anti_spoof": "off"}}) == ""
    assert _anti_spoof_rules({"network": {}}) == ""                      # absent key => off
    # union dedups and drops blanks; no zt/wg -> just lan_cidr, never a bare `!= { }`
    r = _anti_spoof_rules({"interfaces": {"wan": "eth1"}, "network": {"anti_spoof": "on",
        "lan_cidr": "10.0.1.0/24", "zt_cidr": "", "wg_server_cidr": ""}})
    assert r == 'oifname "eth1" ip saddr != { 10.0.1.0/24 } drop'
    # blank wan or no CIDRs -> BCP38 line vanishes (never a bare set); strict still adds v6 fib
    r = _anti_spoof_rules({"interfaces": {"wan": ""}, "network": {"anti_spoof": "strict"}})
    assert "saddr !=" not in r and "fib saddr" in r


def test_real_nft_edge_forward_nat_blank_iface_safe():
    # M13: the forward-chain LAN<->tunnel / tunnel->WAN accepts and the postrouting masquerade rules
    # must render only for CONFIGURED overlay ifaces/CIDRs. With an optional iface (or its CIDR) blank
    # they must VANISH, not render `iifname ""` / an empty `ip saddr` (both nft-fatal — the whole
    # ruleset would fail to load on a legit WG/ZT-less edge).
    from bastion import state, templates
    cfg = state.load_conf(EXAMPLE)                # all ifaces + cidrs set
    out = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    # behavior-preserving: every rule still present (content, single-spaced from the helper).
    for rule in ('iifname "eth0" oifname "zt0" accept', 'iifname "zt0" oifname "eth0" accept',
                 'iifname "eth0" oifname "wg0" accept', 'iifname "eth0" oifname "wg_vps" accept',
                 'iifname "zt0" oifname "eth1" accept', 'iifname "wg0" oifname "eth1" accept',
                 'ip saddr 10.147.17.0/24 oifname "eth0" masquerade',
                 'ip saddr 10.8.0.0/24 oifname "eth0" masquerade',
                 'ip saddr 10.0.1.0/24 oifname "wg_vps" masquerade'):
        assert rule in out, rule
    assert templates.find_placeholders(out) == set()
    ran, ok, *err = _nft_check(out)
    assert ok, f"all-set edge failed nft -c: {err}"

    def _no_empty_fragments(text):
        # check RULE lines only — the template comments mention `iifname ""` / empty `ip saddr` by name.
        rules = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
        for ln in rules:
            assert 'iifname ""' not in ln and 'oifname ""' not in ln, ln
            assert "ip saddr  oifname" not in ln and "ip saddr oifname" not in ln, ln

    # ZeroTier-less edge: removing ZT blanks BOTH zt_iface and zt_cidr. The zt forward pair AND the
    # zt_cidr masquerade (nat :157) must vanish — no `iifname ""`, no empty `ip saddr`, still valid.
    cfg["interfaces"]["zt_iface"] = ""
    cfg["network"]["zt_cidr"] = ""
    out = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    assert 'oifname "zt0"' not in out and 'iifname "zt0"' not in out
    _no_empty_fragments(out)
    assert 'iifname "wg0" oifname "eth0" accept' in out                       # WG pair still there
    assert templates.find_placeholders(out) == set()
    ran, ok, *err = _nft_check(out)
    assert ok, f"ZT-less edge failed nft -c: {err}"

    # All overlays gone (VPN-less edge): only the mandatory lan<->wan forward + wan masquerade survive.
    for k in ("zt_iface", "wg_server_iface", "wg_vps_iface"):
        cfg["interfaces"][k] = ""
    for k in ("zt_cidr", "wg_server_cidr"):
        cfg["network"][k] = ""
    out = templates.render_file(TEMPLATES / "nftables-edge.nft", cfg)
    _no_empty_fragments(out)
    assert 'iifname "eth0"          oifname "eth1" accept' in out             # lan->wan kept
    assert 'oifname "eth1" masquerade' in out                                 # wan masq kept
    assert templates.find_placeholders(out) == set()
    ran, ok, *err = _nft_check(out)
    assert ok, f"VPN-less edge failed nft -c: {err}"

    # Helper unit: a ZT-less config emits no zt rules and no empty fragments.
    from bastion.templates import _forward_iface_rules
    r = _forward_iface_rules({"interfaces": {"lan": "eth0", "wan": "eth1", "zt_iface": "",
                                             "wg_server_iface": "wg0", "wg_vps_iface": ""},
                              "network": {"lan_cidr": "10.0.1.0/24", "zt_cidr": "",
                                          "wg_server_cidr": "10.8.0.0/24"}})
    assert "zt" not in r["forward_tunnel_rules"] and "zt" not in r["forward_overlay_egress"]
    assert r["forward_tunnel_rules"] == 'iifname "eth0" oifname "wg0" accept\n        iifname "wg0" oifname "eth0" accept'
    assert r["forward_overlay_egress"] == 'iifname "wg0" oifname "eth1" accept'
    assert r["nat_masq_rules"] == 'ip saddr 10.8.0.0/24 oifname "eth0" masquerade'   # zt_cidr + wg_vps gone


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


def test_endpoint_wg_server_listen_accept_renders_and_is_gated():
    """M-A: an ENDPOINT that hosts a WireGuard server (wg_server_iface set) opens its listen port as
    an any-source `udp dport <port> accept`; a client endpoint (no wg_server_iface) renders NO such
    accept. False-green guarded — the assertions FAIL if the accept were always-on or absent-when-set,
    or if a blank port ever rendered `udp dport  accept`. Endpoint-only: empty in edge mode."""
    from bastion import state, templates
    tmpl = TEMPLATES / "nftables-endpoint.nft"

    # (1) endpoint + wg_server_iface + explicit port -> any-source accept on that port; valid nft
    cfg = state.load_conf(EXAMPLE)
    cfg["machine"]["mode"] = "endpoint"
    cfg["interfaces"]["wg_server_iface"] = "wg0"
    cfg["network"]["wg_server_listen_port"] = "51900"
    out = templates.render_file(tmpl, cfg)
    assert "udp dport 51900 accept" in out
    assert templates.find_placeholders(out) == set()
    ran, ok, *err = _nft_check(out)
    assert ok, f"endpoint wg accept failed nft -c: {err}"

    # (2) blank port + iface set -> defaults to WireGuard's 51820 (closes L28 for endpoint)
    cfg["network"]["wg_server_listen_port"] = ""
    out = templates.render_file(tmpl, cfg)
    assert "udp dport 51820 accept" in out
    assert "dport  accept" not in out and "dport { } accept" not in out

    # (3) FALSE-GREEN GUARD: a client endpoint (no wg_server_iface) renders NO WG listen accept
    cfg["interfaces"]["wg_server_iface"] = ""
    out = templates.render_file(tmpl, cfg)
    assert "udp dport 51820 accept" not in out and "udp dport 51900 accept" not in out
    ran, ok, *err = _nft_check(out)
    assert ok, f"client endpoint (no wg server) failed nft -c: {err}"

    # (4) ENDPOINT-ONLY: the producer is empty in edge mode, so the edge template never gains an
    # any-source opener (it keeps its M3 iface-scoped wg_server_accept).
    cfg["machine"]["mode"] = "edge"
    cfg["interfaces"]["wg_server_iface"] = "wg0"
    assert templates._endpoint_wg_server_accept(cfg) == ""


def test_validate_conf_endpoint_wg_server_warn_and_port_range():
    """M-A: an endpoint with a WG server gets a reachability CAUTION (not an 'ignored' scold), and the
    new listen-port field is range-checked. Edge / client-endpoint configs get no such warning."""
    from bastion import state

    def _mk(mode, wg_iface="", wg_port=""):
        cfg = state.load_conf(EXAMPLE)
        cfg["machine"]["mode"] = mode
        cfg["interfaces"]["wg_server_iface"] = wg_iface
        if wg_port:
            cfg["network"]["wg_server_listen_port"] = wg_port
        return cfg

    # endpoint + wg server -> a caution warning naming the opened port; NOT an "ignored" warn
    errs, warns = state.validate_conf(_mk("endpoint", "wg0"))
    assert errs == []
    wg_warn = [w for w in warns if "wg_server_iface is set on an endpoint" in w]
    assert wg_warn and "udp/51820" in wg_warn[0] and "ignored" not in wg_warn[0].lower()

    # honours a custom port in the warning text
    _, warns = state.validate_conf(_mk("endpoint", "wg0", "51900"))
    assert any("udp/51900" in w for w in warns)

    # edge with wg server -> no endpoint-WG caution (edge keeps its scoped accept)
    _, warns = state.validate_conf(_mk("edge", "wg0"))
    assert not any("wg_server_iface is set on an endpoint" in w for w in warns)

    # client endpoint (no wg server) -> no caution
    _, warns = state.validate_conf(_mk("endpoint", ""))
    assert not any("wg_server_iface is set on an endpoint" in w for w in warns)

    # out-of-range listen port -> hard error
    errs, _ = state.validate_conf(_mk("endpoint", "wg0", "70000"))
    assert any("wg_server_listen_port" in e for e in errs)


def test_should_daemon_reload_gate():
    # W2 gate predicate: daemon-reload fires ONLY on a live root run (out is /) as euid 0 that actually
    # wrote a unit file. Every other combination must be False so generate stays side-effect-free.
    from bastion.cli import _should_daemon_reload
    root = Path("/")
    assert _should_daemon_reload(root, True, 0) is True            # live root + unit written -> reload
    assert _should_daemon_reload(Path("/tmp/stage"), True, 0) is False   # staged --root tree -> never
    assert _should_daemon_reload(root, True, 1000) is False        # non-root live run -> never
    assert _should_daemon_reload(root, False, 0) is False          # config-only generate -> never


def test_generate_to_staged_root_never_daemon_reloads(tmp_path, monkeypatch):
    # A staged --root generate (out != /) writes unit files under the staged tree but must NEVER touch
    # systemd. Guards the side-effect-free contract cmd_switch + the test suite rely on.
    import argparse, types
    calls = []

    def fake_run(*a, **k):
        calls.append(a)
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    ns = argparse.Namespace(conf=str(EXAMPLE), templates=None, out=str(tmp_path), check=False)
    assert cli.cmd_generate(ns) == 0
    assert (tmp_path / "etc/systemd/system").exists()             # unit files WERE written under stage
    assert not any("daemon-reload" in a[0] for a in calls if a)   # ...but systemd was never reloaded
