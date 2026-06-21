import pytest

from bastion import templates


CONFIG = {
    "interfaces": {"lan": "eth0", "wan": "eth1"},
    "network": {"lan_cidr": "10.0.1.0/24", "zt_cidr": ""},
    "ports": {"ssh": "22"},
}


def test_find_placeholders():
    text = "a {{ interfaces.lan }} b {{network.lan_cidr}} c"
    assert templates.find_placeholders(text) == {("interfaces", "lan"), ("network", "lan_cidr")}


def test_render_resolves():
    out = templates.render('iif "{{ interfaces.lan }}" dport {{ ports.ssh }}', CONFIG)
    assert out == 'iif "eth0" dport 22'


def test_blank_value_resolves_to_empty():
    # zt_cidr is present but empty -> resolves to "" (NOT an error).
    out = templates.render("set { {{ network.zt_cidr }} }", CONFIG)
    assert out == "set {  }"


def test_render_raises_on_missing_and_lists_all():
    with pytest.raises(templates.UnresolvedPlaceholderError) as exc:
        templates.render("{{ network.nope }} {{ ai.model }}", CONFIG)
    msg = str(exc.value)
    assert "network.nope" in msg and "ai.model" in msg


def test_secrets_are_not_resolvable():
    # A template referencing secrets must fail — the engine is only handed machine.conf,
    # never secrets, so {{ secrets.* }} is unresolved by construction.
    with pytest.raises(templates.UnresolvedPlaceholderError):
        templates.render("key={{ secrets.anthropic_api_key }}", CONFIG)


def test_missing_placeholders_helper():
    assert templates.missing_placeholders("{{ ports.ssh }}", CONFIG) == []
    assert templates.missing_placeholders("{{ ports.https }}", CONFIG) == ["ports.https"]


# --- derived trusted_hosts_elements (empty `elements = { }` is invalid nft) -----------------

TMPL = "set trusted_hosts {\n    type ipv4_addr\n    {{ network.trusted_hosts_elements }}\n}"


def test_trusted_hosts_elements_blank_omits_line():
    # Blank trusted_hosts -> the elements line VANISHES (never `elements = {  }`, which nft rejects).
    cfg = {"network": {"trusted_hosts": ""}}
    out = templates.render(TMPL, cfg)
    assert "elements" not in out
    assert "{  }" not in out
    assert templates.find_placeholders(out) == set()


def test_trusted_hosts_elements_populated():
    cfg = {"network": {"trusted_hosts": "10.0.1.50, 10.0.1.55"}}
    out = templates.render(TMPL, cfg)
    assert "elements = { 10.0.1.50, 10.0.1.55 }" in out


def test_trusted_hosts_elements_is_a_resolved_placeholder():
    # The derived key counts as present for the check (so generate --check passes either way).
    assert templates.missing_placeholders(TMPL, {"network": {"trusted_hosts": ""}}) == []
    assert templates.missing_placeholders(TMPL, {"network": {"trusted_hosts": "10.0.0.9"}}) == []


def test_derived_keys_not_written_back():
    # _derived augments a COPY — the caller's config is never mutated (so write_conf round-trips
    # never persist trusted_hosts_elements into machine.conf).
    cfg = {"network": {"trusted_hosts": "10.0.0.9"}}
    templates.render(TMPL, cfg)
    assert "trusted_hosts_elements" not in cfg["network"]


# --- IPv6 parity (D6): trusted_hosts splits by family into v4 + v6 element lines -------------

def test_trusted_hosts_split_by_family():
    # A v6 literal must NOT land in the ipv4_addr set (nft load error). Mixed input partitions:
    d = templates._derived({"network": {"trusted_hosts": "203.0.113.7, 2001:db8::5, 198.51.100.9"}})
    net = d["network"]
    assert net["trusted_hosts_elements"] == "elements = { 203.0.113.7, 198.51.100.9 }"
    assert net["trusted_hosts6_elements"] == "elements = { 2001:db8::5 }"


def test_trusted_hosts6_blank_when_no_v6():
    # v4-only trusted_hosts -> the v6 elements line vanishes (no empty `elements = { }`).
    net = templates._derived({"network": {"trusted_hosts": "10.0.1.50"}})["network"]
    assert net["trusted_hosts_elements"] == "elements = { 10.0.1.50 }"
    assert net["trusted_hosts6_elements"] == ""


def test_unparseable_host_stays_on_v4_line():
    # Preserve pre-IPv6 behaviour: a bad token isn't silently dropped, it stays on the v4 line
    # (surfacing as the same nft load error it always did).
    net = templates._derived({"network": {"trusted_hosts": "not-an-ip"}})["network"]
    assert net["trusted_hosts_elements"] == "elements = { not-an-ip }"
    assert net["trusted_hosts6_elements"] == ""


# --- service_ports inbound allowlist (a server can run bastion without its services dropped) ----

def test_service_ports_splits_tcp_udp_and_dedupes_order():
    tcp, udp = templates._parse_service_ports("8096, 7878/tcp 53/udp 8096 122/udp")
    assert tcp == [8096, 7878]          # order preserved, dup 8096 dropped, default proto = tcp
    assert udp == [53, 122]


def test_service_ports_skips_out_of_range_and_nonnumeric():
    # validate_conf blocks these first; the parser is belt-and-suspenders and just skips them.
    tcp, udp = templates._parse_service_ports("99999 0 abc 8096")
    assert tcp == [8096]
    assert udp == []


def test_service_ports_derived_renders_accept_lines():
    net = templates._derived({"network": {"service_ports": "8096, 53/udp"}})["network"]
    assert net["service_ports_tcp_accept"] == "tcp dport { 8096 } accept"
    assert net["service_ports_udp_accept"] == "udp dport { 53 } accept"


def test_service_ports_blank_omits_both_lines():
    # Blank (or absent) -> both lines vanish; an empty `dport { }` is an nft syntax error.
    for cfg in ({"network": {"service_ports": ""}}, {"network": {}}):
        net = templates._derived(cfg)["network"]
        assert net["service_ports_tcp_accept"] == ""
        assert net["service_ports_udp_accept"] == ""


# --- zones: the general source->action input-accept primitive (inline rules, no named set) -------

def _zones(entries):
    return templates._derived({"zones": entries})["network"]["zones_input_rules"]


def test_zones_absent_or_empty_renders_empty():
    assert templates._derived({})["network"]["zones_input_rules"] == ""
    assert _zones({}) == ""


def test_zones_cidr_source_single_port():
    # CIDR source -> inline `ip saddr` (no named set, so no `flags interval` needed).
    assert _zones({"lan": "192.168.1.0/24 -> 8096"}) == \
        "ip saddr 192.168.1.0/24 tcp dport { 8096 } accept"


def test_zones_multi_port_and_tcp_udp_split():
    # tcp+udp can't mix in one rule -> two lines; order preserved within a transport.
    out = _zones({"mix": "10.0.0.0/8 -> 8096, 8989, 53/udp"})
    assert out == ("ip saddr 10.0.0.0/8 tcp dport { 8096, 8989 } accept\n"
                   "        ip saddr 10.0.0.0/8 udp dport { 53 } accept")


def test_zones_action_all_emits_source_only_accept():
    assert _zones({"vms": "iface:virbr0 -> all"}) == 'iifname "virbr0" accept'
    assert _zones({"trust": "192.168.5.5 -> all"}) == "ip saddr 192.168.5.5 accept"


def test_zones_any_source_omits_saddr():
    assert _zones({"zt": "any -> 9993"}) == "tcp dport { 9993 } accept"


def test_zones_v6_source_uses_ip6_saddr():
    assert _zones({"v6": "fd00::/8 -> 22"}) == "ip6 saddr fd00::/8 tcp dport { 22 } accept"


def test_zones_destination_pin_emits_daddr():
    # `<source> to <dest>` -> ip saddr ... ip daddr ... (a service bound to one local address).
    assert _zones({"api": "10.0.0.0/24 to 10.0.0.1 -> 8080"}) == \
        "ip saddr 10.0.0.0/24 ip daddr 10.0.0.1 tcp dport { 8080 } accept"


def test_zones_destination_pin_any_source():
    assert _zones({"api": "any to 10.0.0.1 -> 8080"}) == \
        "ip daddr 10.0.0.1 tcp dport { 8080 } accept"


def test_zones_destination_pin_iface_source():
    assert _zones({"api": "iface:wg0 to 10.0.0.1 -> 8080"}) == \
        'iifname "wg0" ip daddr 10.0.0.1 tcp dport { 8080 } accept'


def test_lan_ssh_accept_only_for_private_subnet():
    # F6: auto-trust SSH from a PRIVATE lan_cidr, but NOT a public one (a VPS's datacenter /24).
    assert templates._lan_ssh_accept({"network": {"lan_cidr": "192.168.1.0/24"}, "ports": {"ssh": "1111"}}) \
        == "ip saddr 192.168.1.0/24 tcp dport 1111 accept"
    assert templates._lan_ssh_accept({"network": {"lan_cidr": "8.8.8.0/24"}, "ports": {"ssh": "1111"}}) == ""
    assert templates._lan_ssh_accept({"network": {"lan_cidr": ""}, "ports": {"ssh": "1111"}}) == ""
    assert templates._is_private_cidr("10.0.0.0/24") and not templates._is_private_cidr("8.8.8.0/24")


def test_zones_dedupes_identical_rules():
    out = _zones({"a": "any -> 9993", "b": "any -> 9993"})
    assert out == "tcp dport { 9993 } accept"


def test_zones_multiple_entries_joined_at_chain_indent():
    out = _zones({"lan": "192.168.1.0/24 -> 8096", "zt": "any -> 9993"})
    assert out == ("ip saddr 192.168.1.0/24 tcp dport { 8096 } accept\n"
                   "        tcp dport { 9993 } accept")


def test_zones_malformed_entry_skipped_in_render():
    # No `->` -> skipped by the renderer (validate_conf blocks generate before this runs).
    assert _zones({"bad": "192.168.1.0/24 8096"}) == ""


# --- firewall_preamble: ownership mode (exclusive flush vs cooperative table-scoped reset) --------

def _preamble(machine):
    return templates._derived({"machine": machine})["machine"]["firewall_preamble"]


def test_preamble_default_and_exclusive_is_flush():
    assert _preamble({"mode": "edge"}) == "flush ruleset"          # absent scope -> exclusive
    assert _preamble({"mode": "edge", "firewall_scope": "exclusive"}) == "flush ruleset"
    assert _preamble({"mode": "endpoint", "firewall_scope": "exclusive"}) == "flush ruleset"


def test_preamble_cooperative_edge_resets_both_tables():
    # edge owns the filter table AND ip edge_nat — cooperative reset must cover both, NOT flush.
    out = _preamble({"mode": "edge", "firewall_scope": "cooperative"})
    assert "flush ruleset" not in out
    assert out == ("add table inet edge\ndelete table inet edge\n"
                   "add table ip edge_nat\ndelete table ip edge_nat")


def test_preamble_cooperative_endpoint_resets_one_table():
    out = _preamble({"mode": "endpoint", "firewall_scope": "cooperative"})
    assert out == "add table inet bastion\ndelete table inet bastion"
