"""Minimal placeholder template engine for bastion. No Jinja2 dependency.

Resolves ``{{ section.key }}`` placeholders from a nested config dict (as produced by
:func:`bastion.state.load_conf`). Contract (founding document §8):

1. Resolve every ``{{ section.key }}`` from machine.conf values.
2. Raise an explicit error for any UNRESOLVED placeholder — never emit a silent empty
   value. (A *present but blank* value is considered resolved and renders as empty.)
3. Never read secrets.conf — secrets reach services via systemd EnvironmentFile, not
   templates. The engine only ever sees the dict it is handed; a ``{{ secrets.* }}``
   reference therefore fails as unresolved unless a secrets section is explicitly passed,
   which the CLI never does.
4. Support a check that validates all placeholders resolve without writing output.
"""
from __future__ import annotations

import re
from pathlib import Path

# section.key — both are identifier-like; whitespace inside the braces is tolerated.
PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\}\}")


class UnresolvedPlaceholderError(Exception):
    """Raised when a template references a placeholder absent from the config."""


def find_placeholders(text: str) -> set[tuple[str, str]]:
    """Return the set of ``(section, key)`` pairs referenced in ``text``."""
    return {(m.group(1), m.group(2)) for m in PLACEHOLDER_RE.finditer(text)}


def missing_placeholders(text: str, config: dict) -> list[str]:
    """Return a sorted list of ``"section.key"`` referenced but not present in ``config``.

    "Present" means the section exists and the key exists in it — even if its value is the
    empty string. Only genuinely absent keys are reported. Derived keys (see :func:`_derived`)
    count as present.
    """
    cfg = _derived(config)
    missing = []
    for section, key in find_placeholders(text):
        if key not in cfg.get(section, {}):
            missing.append(f"{section}.{key}")
    return sorted(set(missing))


def _derived(config: dict) -> dict:
    """Return a copy of ``config`` augmented with computed, template-only keys.

    These are never written back to machine.conf — they exist only at render/check time so a
    template can express something the raw config cannot. Currently:

    * ``network.trusted_hosts_elements`` / ``network.trusted_hosts6_elements`` — the nftables
      ``elements = { ... }`` line for the static ``trusted_hosts`` set, split by address family
      (the v4 set is ``ipv4_addr``, the v6 set ``ipv6_addr``; a v6 literal in an ipv4_addr set is
      a load error). Each is ``""`` when that family has no configured hosts. An empty
      ``elements = { }`` is an nftables *syntax error*, so when a family is blank the whole line
      must vanish, not render empty braces. (Blank ``trusted_hosts`` is a valid operator choice —
      the wizard offers "blank = none".)
    * ``network.ipv6_forward_block`` — the IPv6 forwarding lines for the edge sysctl drop-in
      (``templates/sysctl-forward.conf``): empty when ``[network] ipv6_forward`` is off, else
      ``net.ipv6.conf.all.forwarding = 1`` plus an ``accept_ra = 2`` on the WAN (see
      :func:`_ipv6_forward_block`). Always present so the sysctl template resolves.
    * ``network.service_ports_tcp_accept`` / ``network.service_ports_udp_accept`` — the input-chain
      accept rule for the operator's ``[network] service_ports`` allowlist, one per transport (e.g.
      ``tcp dport { 8096, 7878 } accept``). Each is ``""`` when that transport has no ports (an empty
      ``dport { }`` is an nft syntax error, so the whole line must vanish). Lets a server that runs
      bastion open its service ports without hand-editing the default-drop ruleset. See
      :func:`_parse_service_ports`.
    * ``machine.firewall_preamble`` — the opening reset of the rendered nft ruleset (ownership mode).
      ``exclusive`` (default) => ``flush ruleset`` (bastion owns the whole ruleset). ``cooperative``
      => an idempotent, table-scoped reset of ONLY bastion's own tables (``add table`` then ``delete
      table``, so a re-load is clean) — leaves co-resident tables (libvirt/docker) intact. Edge owns
      two tables (``inet edge`` filter + ``ip edge_nat``), endpoint one (``inet bastion``). See
      :func:`_firewall_preamble`.
    * ``network.zones_input_rules`` — the input-chain accept rules synthesised from the dynamic
      ``[zones]`` section (the general source→action primitive), rendered as one block under a single
      placeholder (the engine has no loops). A zone is ``name = <source> -> <action>`` where source
      is ``any`` / an IP-or-CIDR / ``iface:NAME`` and action is ``all`` or a service-ports-style port
      list. Rendered as INLINE rules (``ip saddr <cidr> tcp dport { ... } accept``), which need no
      ``flags interval`` and so sidestep the ``trusted_hosts`` named-set CIDR bug. ``""`` when no
      ``[zones]`` section is present. See :func:`_render_zones`.
    """
    net = dict(config.get("network") or {})
    if "trusted_hosts" in net:
        hosts = str(net.get("trusted_hosts") or "").strip().strip(",").strip()
        v4, v6 = _split_hosts_by_family(hosts)
        net["trusted_hosts_elements"] = f"elements = {{ {v4} }}" if v4 else ""
        net["trusted_hosts6_elements"] = f"elements = {{ {v6} }}" if v6 else ""
    net["ipv6_forward_block"] = _ipv6_forward_block(config)
    tcp_ports, udp_ports = _parse_service_ports(str(net.get("service_ports") or ""))
    net["service_ports_tcp_accept"] = (
        f"tcp dport {{ {', '.join(str(p) for p in tcp_ports)} }} accept" if tcp_ports else "")
    net["service_ports_udp_accept"] = (
        f"udp dport {{ {', '.join(str(p) for p in udp_ports)} }} accept" if udp_ports else "")
    net["zones_input_rules"] = _render_zones(config)
    mach = dict(config.get("machine") or {})
    mach["firewall_preamble"] = _firewall_preamble(config)
    return {**config, "network": net, "machine": mach}


def _parse_service_ports(raw: str) -> tuple[list[int], list[int]]:
    """Partition a ``[network] service_ports`` string into ``(tcp_ports, udp_ports)``.

    Each token is ``port`` or ``port/proto`` (proto ``tcp``|``udp``, default ``tcp``); tokens are
    comma- and/or whitespace-separated. Order is preserved and duplicates within a transport are
    dropped (keeps the rendered ``dport { }`` set clean). Malformed/out-of-range tokens are skipped
    here — :func:`bastion.state.validate_conf` surfaces them as errors and blocks ``generate`` first,
    so a clean conf never reaches this with a bad token; the skip is just belt-and-suspenders."""
    tcp: list[int] = []
    udp: list[int] = []
    for tok in raw.replace(",", " ").split():
        port, _, proto = tok.partition("/")
        if not port.isdigit():
            continue
        n = int(port)
        if not (1 <= n <= 65535):
            continue
        bucket = udp if proto.lower() == "udp" else tcp
        if n not in bucket:
            bucket.append(n)
    return tcp, udp


def _zone_prefix(source: str) -> str:
    """Map a zone source token to its nft rule prefix (with trailing space, or '' for any).

    ``any`` -> '' (no saddr/iif match — applies to every source); ``iface:NAME`` -> ``iifname
    "NAME" ``; an IP/CIDR -> ``ip saddr <s> `` (v4) or ``ip6 saddr <s> `` (v6). An unparseable
    address falls back to ``ip saddr`` so a genuinely bad token surfaces as an nft load error the
    same way trusted_hosts does, rather than being silently dropped (validate_conf blocks it first)."""
    import ipaddress
    if source == "any":
        return ""
    if source.startswith("iface:"):
        return f'iifname "{source[len("iface:"):].strip()}" '
    try:
        fam = "ip6" if ipaddress.ip_network(source, strict=False).version == 6 else "ip"
    except ValueError:
        fam = "ip"
    return f"{fam} saddr {source} "


def _render_zones(config: dict) -> str:
    """Render the dynamic ``[zones]`` section into inline nft input-chain accept rules.

    Each entry is ``name = <source> -> <action>``. ``action: all`` emits a source-only accept (the
    ``trusted_hosts`` semantic); a port list emits one ``dport { ... } accept`` line per transport
    (tcp/udp can't be mixed in one rule). Identical rendered rules are de-duplicated, order
    preserved. Returns one string (joined at the placeholder's 8-space chain-input indent); ``""``
    for an absent/empty section, so the ``{{ network.zones_input_rules }}`` line vanishes (an empty
    block would otherwise leave a stray indented blank line — harmless, but we keep it clean)."""
    rules: list[str] = []
    for spec in (config.get("zones") or {}).values():
        src_raw, sep, act_raw = str(spec).partition("->")
        source, action = src_raw.strip(), act_raw.strip()
        if not sep or not source or not action:
            continue  # malformed; validate_conf blocks generate before we get here
        prefix = _zone_prefix(source)
        if action == "all":
            rules.append(f"{prefix}accept".strip())
            continue
        tcp_ports, udp_ports = _parse_service_ports(action)
        if tcp_ports:
            rules.append(f"{prefix}tcp dport {{ {', '.join(str(p) for p in tcp_ports)} }} accept")
        if udp_ports:
            rules.append(f"{prefix}udp dport {{ {', '.join(str(p) for p in udp_ports)} }} accept")
    seen: set[str] = set()
    deduped = [r for r in rules if not (r in seen or seen.add(r))]
    return "\n        ".join(deduped)


def _firewall_preamble(config: dict) -> str:
    """The opening reset line(s) of the rendered nft ruleset, per ``[machine] firewall_scope``.

    ``exclusive`` (default) -> ``flush ruleset``: bastion owns the entire ruleset. ``cooperative``
    -> an idempotent table-scoped reset of bastion's OWN tables only, so re-loading is clean while
    co-resident tables (libvirt/docker) survive: ``add table <t>`` (ensures it exists so the delete
    can't error on a first load) then ``delete table <t>`` (drops the old instance; the template's
    own ``table <t> { ... }`` block below recreates it fresh) — all atomic in one ``nft -f``. Edge
    owns two tables (``inet edge`` + ``ip edge_nat``); endpoint one (``inet bastion``)."""
    scope = str(config.get("machine", {}).get("firewall_scope", "exclusive")).strip().lower()
    if scope != "cooperative":
        return "flush ruleset"
    mode = config.get("machine", {}).get("mode", "edge")
    tables = ["inet bastion"] if mode == "endpoint" else ["inet edge", "ip edge_nat"]
    lines = []
    for t in tables:
        lines += [f"add table {t}", f"delete table {t}"]
    return "\n".join(lines)


def _ipv6_forward_block(config: dict) -> str:
    """The IPv6 lines for the edge forwarding sysctl drop-in. ``[network] ipv6_forward`` defaults
    to ON (a real edge box routes the v6 firewall it ships); off => v4-only routing, v6 rules stay
    ready-but-inert. When on, also pin ``accept_ra = 2`` on the WAN: enabling v6 forwarding makes
    Linux stop honoring Router Advertisements by default, which would strip the box's OWN WAN IPv6
    address — ``accept_ra = 2`` keeps SLAAC working on the uplink while forwarding."""
    net = config.get("network", {})
    raw = str(net.get("ipv6_forward", "yes")).strip().lower()
    if raw in ("no", "false", "0", "off"):
        return ""
    lines = ["net.ipv6.conf.all.forwarding = 1"]
    wan = str(config.get("interfaces", {}).get("wan", "")).strip()
    if wan:
        lines.append(f"net.ipv6.conf.{wan}.accept_ra = 2")
    return "\n".join(lines)


def _split_hosts_by_family(hosts: str) -> tuple[str, str]:
    """Partition a comma-separated trusted_hosts string into (v4_csv, v6_csv). A token that
    parses as IPv6 goes to the v6 set; everything else (IPv4 or unparseable) stays on the v4
    line, preserving the pre-IPv6 behaviour for v4 and surfacing a genuinely bad token the same
    way it did before (as an nft load error) rather than silently dropping it."""
    import ipaddress
    v4, v6 = [], []
    for tok in (t.strip() for t in hosts.split(",")):
        if not tok:
            continue
        try:
            net = ipaddress.ip_network(tok, strict=False)
            (v6 if net.version == 6 else v4).append(tok)
        except ValueError:
            v4.append(tok)
    return ", ".join(v4), ", ".join(v6)


def render(text: str, config: dict) -> str:
    """Resolve every placeholder in ``text``. Raise if any cannot be resolved.

    Collects ALL missing placeholders before raising, so the error lists everything wrong
    at once rather than failing one at a time.
    """
    cfg = _derived(config)
    missing = missing_placeholders(text, config)
    if missing:
        raise UnresolvedPlaceholderError("unresolved placeholders: " + ", ".join(missing))
    return PLACEHOLDER_RE.sub(lambda m: str(cfg[m.group(1)][m.group(2)]), text)


def render_file(src: Path, config: dict) -> str:
    """Render the template file at ``src`` and return the resolved text."""
    return render(Path(src).read_text(), config)


def check_file(src: Path, config: dict) -> list[str]:
    """Return the list of unresolved ``section.key`` for the template at ``src`` (no write)."""
    return missing_placeholders(Path(src).read_text(), config)
