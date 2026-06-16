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
