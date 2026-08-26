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

# systemd dependency directives whose values are unit names. An EMPTY template instance
# ("foo@.service") in one of these resolves to the REFERENCING unit's own name, so the
# ordering/dependency silently targets a real-but-meaningless unit and orders against nothing
# (the L33 defect class). :func:`empty_instance_deps` scans rendered unit text for it so a
# generate-time guard can go RED, instead of the silent path that shipped it.
_UNIT_DEP_DIRECTIVE_RE = re.compile(
    r"^\s*(?:After|Before|Wants|Requires|Requisite|BindsTo|PartOf|Conflicts|Upholds)\s*=(.*)$",
    re.MULTILINE,
)
# A token with an EMPTY instance: some non-space name, then "@" IMMEDIATELY followed by ".<suffix>".
# The "." must come right after "@", so a NON-empty instance ("foo@bar.service") never matches.
_EMPTY_INSTANCE_TOKEN_RE = re.compile(
    r"\S*@\.(?:service|socket|timer|target|mount|path|slice|device|swap|automount|scope)\b"
)


class UnresolvedPlaceholderError(Exception):
    """Raised when a template references a placeholder absent from the config."""


def empty_instance_deps(rendered_unit_text: str) -> list[str]:
    """Return dependency tokens with an EMPTY systemd template instance (``foo@.service``).

    Scans only the values of unit DEPENDENCY directives (``After=``/``Wants=``/``Requires=``/…),
    across the WHOLE space-separated value (the offender may not be the first token — e.g.
    edge-watchdog's ``After=network.target nftables.service wg-quick@.service``), so a harmless
    ``@.`` elsewhere (an ``ExecStart=`` argument, a comment, or a template unit's own *file name*)
    is never flagged. systemd resolves such an instance-less dependency to the referencing unit's
    own name, silently ordering against nothing (L33). Empty list ⇒ clean.
    """
    offenders: list[str] = []
    for m in _UNIT_DEP_DIRECTIVE_RE.finditer(rendered_unit_text):
        offenders.extend(t.group(0) for t in _EMPTY_INSTANCE_TOKEN_RE.finditer(m.group(1)))
    return offenders


def _watchdog_wg_after(config: dict) -> str:
    """The wg-quick ordering tokens for edge-watchdog's ``After=`` line (L33).

    Emits ``" wg-quick@<iface>.service"`` (LEADING space) for each configured WireGuard interface
    the watchdog should order after — BOTH the inbound server iface (``wg_server_iface``) and the
    upstream relay iface (``wg_vps_iface``), deduped — so the unit orders after whichever WG
    interfaces actually exist. A box may host a WG *server* without an upstream relay (a 1.5.16
    endpoint), or a relay without a server, so both roles are covered. Returns ``""`` when neither
    is set, so the ``After=`` line simply ends after ``nftables.service`` with no trailing token —
    and NEVER renders the empty-instance ``wg-quick@.service`` that the old hardcoded
    ``wg-quick@{{ interfaces.wg_vps_iface }}.service`` produced when ``wg_vps_iface`` was blank.
    """
    ifaces = config.get("interfaces") or {}
    names: list[str] = []
    for key in ("wg_server_iface", "wg_vps_iface"):
        name = str(ifaces.get(key) or "").strip()
        if name and name not in names:
            names.append(name)
    return "".join(f" wg-quick@{name}.service" for name in names)


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
    net["lan_ssh_accept"] = _lan_ssh_accept(config)
    net.update(_nonwan_iface_accepts(config))   # M3: iface-scoped ZT/WG control-port accepts
    net["wg_server_listen_accept"] = _endpoint_wg_server_accept(config)  # M-A: endpoint any-source WG accept
    net["wg_server_wan_accept"] = _edge_wg_wan_accept(config)  # H17: edge opt-in WG-server WAN accept (above drop)
    net["watchdog_wg_ordering"] = _watchdog_wg_after(config)  # L33: blank-safe wg-quick After= tokens
    net["internal_iface_drop"] = _internal_iface_drop(config)  # M3b: fail-closed input WAN drop
    net["anti_spoof_rules"] = _anti_spoof_rules(config)   # M2b: gated forward-chain anti-spoof teeth
    net.update(_forward_iface_rules(config))     # M13: blank-safe forward/nat overlay-iface rules
    mach = dict(config.get("machine") or {})
    mach["firewall_preamble"] = _firewall_preamble(config)
    return {**config, "network": net, "machine": mach}


def _is_private_cidr(cidr: str) -> bool:
    """True if an IP/CIDR is RFC1918 / link-local / ULA — i.e. a real private LAN where trusting the
    whole subnet is reasonable. A PUBLIC subnet (e.g. a VPS's datacenter /24) returns False. F6."""
    import ipaddress
    try:
        return ipaddress.ip_network(str(cidr).strip(), strict=False).is_private
    except ValueError:
        return False


def _lan_ssh_accept(config: dict) -> str:
    """The endpoint 'accept SSH from the local subnet' rule, or '' when it must NOT be emitted.

    Auto-trusting the whole ``lan_cidr`` for SSH is convenient on a private LAN — but a PUBLIC
    ``lan_cidr`` (a VPS whose 'local /24' is full of unknown datacenter tenants) would silently expose
    SSH to all of them the moment bastion is the sole input gate. So for a non-private subnet the rule
    is dropped: the operator pins an explicit admin source via a zone / ``trusted_hosts`` instead (the
    wizard warns loudly). Blank/absent ``lan_cidr`` or ssh port also renders ''. F6."""
    net = config.get("network") or {}
    lan_cidr = str(net.get("lan_cidr") or "").strip()
    ssh = str((config.get("ports") or {}).get("ssh") or "").strip()
    if not lan_cidr or not ssh or not _is_private_cidr(lan_cidr):
        return ""
    return f"ip saddr {lan_cidr} tcp dport {ssh} accept"


def _nonwan_iface_accepts(config: dict) -> dict:
    """M3: the ZeroTier (9993 tcp+udp) and WireGuard-server (51820 udp) control-port accepts,
    POSITIVELY scoped to the box's non-WAN interfaces.

    These were any-source accepts (``tcp dport 9993 accept`` …). They sit AFTER the input chain's
    ``iifname wan drop``, so on a correctly-detected box they only ever match non-WAN sources — but
    that safety rests entirely on ``interfaces.wan`` naming the real uplink. A mis-detected or (more
    realistically) *renamed* WAN makes that drop match nothing, and the any-source accepts then expose
    ZeroTier/WireGuard to the internet. Scoping to a positive allowlist of the box's OWN interfaces
    removes that dependency: an unknown/renamed iface simply isn't in the set.

    Each key renders a COMPLETE rule line or ``""`` — never a bare ``iifname { }`` (nft rejects an
    empty set, the same class as the ``trusted_hosts`` empty-``elements`` trap). The source set is the
    non-blank ``{lan, zt, wg_server, wg_vps}``; a port's rule also vanishes when its owning service
    iface is unconfigured (no ZeroTier => no 9993; no WG server => no 51820). Behavior-preserving on a
    correctly-detected box. (Does NOT touch the any-source ``service_ports``/``zones`` accepts, which
    share the same WAN-dependence — tracked separately.)"""
    ifaces = config.get("interfaces") or {}
    def _name(k): return str(ifaces.get(k) or "").strip()
    lan, zt = _name("lan"), _name("zt_iface")
    wg_server, wg_vps = _name("wg_server_iface"), _name("wg_vps_iface")
    internal = [i for i in (lan, zt, wg_server, wg_vps) if i]
    src = "{ " + ", ".join(internal) + " }" if internal else ""

    def _rule(owner_iface: str, proto: str, port: int) -> str:
        # owner_iface present => it is in `internal`, so `src` is non-empty (never a bare `{ }`).
        return f"iifname {src} {proto} dport {port} accept" if (owner_iface and src) else ""

    return {"zt_accept_tcp": _rule(zt, "tcp", 9993),
            "zt_accept_udp": _rule(zt, "udp", 9993),
            "wg_server_accept": _rule(wg_server, "udp", 51820)}


def _endpoint_wg_server_accept(config: dict) -> str:
    """M-A: the ENDPOINT-only any-source accept for an inbound WireGuard server's listen port, or ''.

    An endpoint that hosts a WireGuard server (a VPS that peers dial into) must reach its listen port
    from arbitrary internet peers — so, unlike the edge's iface-scoped ``wg_server_accept`` (M3, which
    protects a router's WAN), this is an ANY-SOURCE ``udp dport <port> accept``. That is safe for a WG
    listen port: WireGuard's crypto silently drops any packet that isn't a valid handshake/transport
    from a configured peer, so an open UDP port exposes no attack surface beyond the WG protocol.

    Endpoint-only (the edge WG server keeps its non-WAN-scoped form — this key is empty in edge mode).
    Renders '' (the whole line vanishes) when no ``wg_server_iface`` is set, so a *client* endpoint
    stays fully locked down. Port from ``[network] wg_server_listen_port``, defaulting to WireGuard's
    default 51820 when a server iface is set but no explicit port is given (this also closes L28 for
    endpoint: a non-default ListenPort is honoured instead of a hardcoded 51820)."""
    if str((config.get("machine") or {}).get("mode") or "").strip() != "endpoint":
        return ""
    wg_server = str((config.get("interfaces") or {}).get("wg_server_iface") or "").strip()
    if not wg_server:
        return ""
    port = str((config.get("network") or {}).get("wg_server_listen_port") or "").strip() or "51820"
    return f"udp dport {port} accept"


def _edge_wg_wan_accept(config: dict) -> str:
    """H17 facet: the EDGE opt-in that makes an inbound WireGuard server's listen port reachable from
    the WAN — for a single-NIC PUBLIC / host-firewall box where a CGNAT dial-only peer must dial INTO
    this box's WG listener over the public NIC.

    The edge input chain's fail-closed WAN drop (:func:`_internal_iface_drop`, M3b) renders ABOVE the
    normal iface-scoped ``wg_server_accept``, so a WAN dial-in to the WG port is dropped. When
    ``[network] wg_server_wan = yes`` (default no), this renders a WAN-iface-scoped accept the edge
    template places ABOVE that drop (but BELOW the block-set drops, so bans still apply).

    Scoped to ``interfaces.wan`` — the NARROWEST shape that admits the dial-in without opening the port
    on any other iface (a multi-NIC edge that opts in exposes it only on its uplink). Its only failure
    mode under a mis-named WAN is 'peer can't connect' (loud), never silent exposure — so it does NOT
    reintroduce the M3 fail-open hazard. Safe like the endpoint case: WG crypto drops any packet that
    isn't a valid handshake from a configured peer, so an open UDP port exposes no surface beyond the
    WG protocol.

    OFF by default and fail-CLOSED: renders '' unless mode is edge AND ``wg_server_wan`` is explicitly
    truthy AND both a ``wan`` and a ``wg_server_iface`` are set — never a bare fragment. Port from
    ``[network] wg_server_listen_port`` (default 51820). (Endpoint mode keeps its own any-source accept,
    :func:`_endpoint_wg_server_accept`, which needs no opt-in — it has no WAN drop to sit above.)"""
    if str((config.get("machine") or {}).get("mode") or "").strip() != "edge":
        return ""
    net = config.get("network") or {}
    # OFF by default; only an explicit truthy opens the port (NEVER "non-empty == true" — that would
    # fail OPEN on `wg_server_wan = no`). configspec validates it to yes|no; the on-list is belt.
    if str(net.get("wg_server_wan", "no")).strip().lower() not in ("yes", "true", "1", "on"):
        return ""
    ifaces = config.get("interfaces") or {}
    wan = str(ifaces.get("wan") or "").strip()
    wg_server = str(ifaces.get("wg_server_iface") or "").strip()
    if not wan or not wg_server:
        return ""
    port = str(net.get("wg_server_listen_port") or "").strip() or "51820"
    return f'iifname "{wan}" udp dport {port} accept'


def _internal_iface_drop(config: dict) -> str:
    """M3b: the fail-CLOSED input-chain WAN drop (root-cause reframe of M3).

    The input chain's ``iifname "{{wan}}" drop`` drops ONLY packets arriving on the *named* WAN iface,
    so every any-source accept below it (``service_ports``, ``zones``, and — pre-M3 — the ZT/WG control
    ports) is safe *only if* ``interfaces.wan`` names the real uplink. A mis-detected or renamed WAN
    makes that drop match nothing and silently exposes those ports to the internet (fail-OPEN).

    This drops everything NOT arriving on one of the box's OWN internal ifaces:
    ``iifname != { lan, zt, wg_server, wg_vps } drop``. An unknown/renamed iface is now DROPPED, not
    exposed (fail-CLOSED). The trade is *silent-exposure* → *loud-lockout*, and the lockout is
    recoverable: ``bastion-recovery``'s ``ensure_main_accept`` INSERTS its accept at the TOP of the
    input chain (above this drop), and the serial console is out-of-band.

    Renders a COMPLETE rule line. Guards (pressure test A1):
    * WAN is EXCLUDED from the internal set even on a name collision, so WAN is always dropped.
    * Empty internal set (a broken, hand-editable config with no ``lan``) FALLS BACK to the literal
      ``iifname "{wan}" drop`` — never ``!= { }`` (nft rejects an empty set), never a bare vanish
      (which would delete the only WAN drop and re-open fail-open, strictly worse than today). So this
      is strictly-safer-or-equal to the literal drop on every config.

    M3's per-rule ``_nonwan_iface_accepts`` scoping is KEPT alongside this (defense in depth): this rule
    closes the still-any-source ``service_ports``/``zones`` gap that M3 left open."""
    ifaces = config.get("interfaces") or {}
    def _name(k): return str(ifaces.get(k) or "").strip()
    wan = _name("wan")
    internal = [i for i in (_name("lan"), _name("zt_iface"),
                            _name("wg_server_iface"), _name("wg_vps_iface")) if i and i != wan]
    if internal:
        return f'iifname != {{ {", ".join(internal)} }} drop'
    return f'iifname "{wan}" drop'


def _anti_spoof_rules(config: dict) -> str:
    """M2b: the forward-chain anti-spoof teeth, gated by ``[network] anti_spoof`` (off|on|strict).

    ``off`` (default) → ``""`` (today's behavior; no forwarding change on existing installs). This is
    off-by-default because BCP38 keyed on the *declared* CIDRs can blackhole an UNDECLARED downstream/
    cascaded subnet routed behind the LAN — the same class of legit-traffic blackhole the M2 pressure
    test made bastion avoid (strict rp_filter on the asymmetric relay path). The operator opts in once
    they know their source prefixes.

    ``on`` → **BCP38 v4 egress drop**: a packet FORWARDED out the WAN whose source is not one of the
    box's own declared CIDRs (``lan_cidr`` ∪ ``zt_cidr`` ∪ ``wg_server_cidr``) is dropped. Uses the
    UNION (pressure test F3 — keying on ``lan_cidr`` alone would drop legit overlay-sourced egress).
    Only matches ``oifname wan`` FORWARDED traffic, so the router's own output and the ``wg_vps`` relay
    egress (``oifname wg_vps``) are untouched; masquerade is postrouting (after forward), so ``saddr``
    is still the original in-CIDR source here. ct-established (chain top) already accepted return flows,
    so the asymmetric-return path M2 rejected is NOT re-broken (BCP38 checks egress source, not reverse
    route).

    ``strict`` → BCP38 + a **v6 reverse-path** ``meta nfproto ipv6 fib saddr . iif oif missing drop``.
    v6-only ON PURPOSE: there is no v6 rp_filter sysctl, but a v4 ``fib`` reverse-path reproduces the
    exact policy-routing/asymmetry blackhole M2 rejected — so v4 stays BCP38-only, and even v6 fib is
    behind this explicit ``strict`` opt-in.

    Renders a complete block (one rule per line, forward-chain body indent) or ``""``. Each rule vanishes
    if it would be empty (blank ``wan`` or no declared CIDRs → no BCP38 line; never a bare ``!= { }``)."""
    net = config.get("network") or {}
    ifaces = config.get("interfaces") or {}
    mode = str(net.get("anti_spoof") or "off").strip().lower()
    if mode not in ("on", "strict"):
        return ""
    wan = str(ifaces.get("wan") or "").strip()
    cidrs: list[str] = []
    for k in ("lan_cidr", "zt_cidr", "wg_server_cidr"):
        c = str(net.get(k) or "").strip()
        if c and c not in cidrs:
            cidrs.append(c)
    rules: list[str] = []
    if wan and cidrs:
        rules.append(f'oifname "{wan}" ip saddr != {{ {", ".join(cidrs)} }} drop')
    if mode == "strict":
        rules.append("meta nfproto ipv6 fib saddr . iif oif missing drop")
    return "\n        ".join(rules)


def _forward_iface_rules(config: dict) -> dict:
    """M13: the edge forward-chain LAN<->tunnel + tunnel->WAN accepts and the postrouting masquerade
    rules, rendered only for the interfaces / CIDRs actually configured.

    These interpolated the OPTIONAL overlay ifaces (zt/wg_server/wg_vps) inside ``iifname "..."`` /
    ``oifname "..."`` and the optional overlay CIDRs inside ``ip saddr ...``. A blank value rendered
    ``iifname ""`` or an empty ``ip saddr`` — both of which nft REJECTS — so a legit WG/ZT-less edge
    (a valid, hand-editable config; ``validate_conf`` doesn't require these) could not load its ruleset
    at ALL. Each rule now renders as a complete line or vanishes (never ``iifname ""``). ``lan``/``wan``/
    ``lan_cidr`` are mandatory on an edge (a blank one is a broken uplink, not a supported config) and
    stay literal in the template. Fails closed: a blank ``lan`` drops the forward rules to ``policy
    drop`` while the input-chain protection still loads — strictly safer than the whole-ruleset failure."""
    ifaces = config.get("interfaces") or {}
    net = config.get("network") or {}
    def _if(k): return str(ifaces.get(k) or "").strip()
    def _cidr(k): return str(net.get(k) or "").strip()
    lan, wan = _if("lan"), _if("wan")

    tunnel: list[str] = []
    for ov in (_if("zt_iface"), _if("wg_server_iface"), _if("wg_vps_iface")):
        if lan and ov:
            tunnel += [f'iifname "{lan}" oifname "{ov}" accept',
                       f'iifname "{ov}" oifname "{lan}" accept']
    egress = [f'iifname "{ov}" oifname "{wan}" accept'
              for ov in (_if("zt_iface"), _if("wg_server_iface")) if ov and wan]
    nat: list[str] = []
    for cidr_k, oif in (("zt_cidr", lan), ("wg_server_cidr", lan), ("lan_cidr", _if("wg_vps_iface"))):
        c = _cidr(cidr_k)
        if c and oif:
            nat.append(f'ip saddr {c} oifname "{oif}" masquerade')
    join = "\n        ".join            # subsequent lines carry the 8-space forward/nat body indent
    return {"forward_tunnel_rules": join(tunnel),
            "forward_overlay_egress": join(egress),
            "nat_masq_rules": join(nat)}


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


def _zone_prefix(match: str) -> str:
    """Map a zone match token to its nft rule prefix (with trailing space, or '' for any).

    ``match`` is ``<source>`` or ``<source> to <dest>``. The source: ``any`` -> '' (no saddr/iif —
    every source); ``iface:NAME`` -> ``iifname "NAME"``; an IP/CIDR -> ``ip saddr <s>`` (v4) /
    ``ip6 saddr <s>`` (v6); ``iface:NAME+<CIDR>`` -> BOTH ``iifname "NAME" ip[6] saddr <CIDR>`` (B9 —
    lets a zone restrict a source network to arrivals on one interface). An optional ``to <dest>``
    (IP/CIDR) appends ``ip[6] daddr <dest>`` — so a zone can pin the DESTINATION (e.g. a service
    bound to one of several local addresses, like a UFW ``to 10.0.0.1 port 8080`` rule). Family comes
    from whichever side is an IP (source and dest must agree — validate_conf enforces it). An
    unparseable address falls back to ``ip`` so a genuinely bad token surfaces as an nft load error
    rather than being silently dropped."""
    import ipaddress

    def _fam(addr: str) -> str:
        try:
            return "ip6" if ipaddress.ip_network(addr, strict=False).version == 6 else "ip"
        except ValueError:
            return "ip"

    source, _, dest = match.partition(" to ")
    source, dest = source.strip(), dest.strip()

    is_iface = source.startswith("iface:")
    iface = ""
    src_ip = ""
    if is_iface:
        iface, _, cidr = source[len("iface:"):].partition("+")   # optional +<CIDR> (B9)
        iface, src_ip = iface.strip(), cidr.strip()
    elif source != "any":
        src_ip = source
    fam = _fam(src_ip) if src_ip else (_fam(dest) if dest else "ip")

    parts: list[str] = []
    if is_iface:
        # Always emit the iifname clause for an iface: source — an empty name (malformed; validate_conf
        # blocks it upstream) yields `iifname ""`, which nft REJECTS, so a validation-bypassing caller
        # fails CLOSED rather than rendering a bare accept-all.
        parts.append(f'iifname "{iface}"')
    if src_ip:
        parts.append(f"{fam} saddr {src_ip}")
    if dest:
        parts.append(f"{fam} daddr {dest}")
    prefix = " ".join(parts)
    return prefix + " " if prefix else ""


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
