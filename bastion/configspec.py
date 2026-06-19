"""bastion config registry — the ONE writable-settings contract (the worldstate.py analogue for writes).

`SETTINGS` declares every machine.conf knob raised into the control room: its validator, its risk
tier (EVERYDAY vs ADVANCED), its scope (which mode/layer it applies to), and — critically — the
*apply action* (which regen + reload must run after a change, and ONLY that one). `apply_change()` is
the engine the CLI (`bastion config set`, the domain/E7 verbs) and the TUI (Configure palette group)
both call; a future GUI consumes the same registry. Writes flow through the existing safety
machinery: field validate -> whole-conf `state.validate_conf` on a staged copy -> atomic
`state.write_conf` -> the scoped apply. A bad value can never land; a DNS-only change never reloads
the firewall.

The script-side knobs that are still hardcoded in templates/scripts (nft rate limits, watchdog/
reconciler thresholds, feed URLs, policy.allowlist) are intentionally NOT here yet — each must first
be promoted into machine.conf + a template (a later pass). The apply taxonomy already anticipates them.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import state
from .system import System
# Reuse the wizard's typo-catching validators + the systemd time-span normalizer (single source).
from .setup.wizard import (_v_port, _v_ip, _v_cidr, _v_hosts, _v_iface,  # noqa: F401
                           normalize_timer_interval)

EVERYDAY = "everyday"
ADVANCED = "advanced"

# Apply-action tags — what runs (live) after a validated write. Staged --root trees regen only.
APPLY_NONE = "none"                       # write only (reserved/inert keys)
APPLY_GENERATE = "generate"               # re-render machine.env / a config file; no daemon touch
APPLY_GENERATE_FIREWALL = "generate+firewall"   # + `firewall reload` (nft)
APPLY_GENERATE_DNSMASQ = "generate+dns"   # + reload dnsmasq/unbound (L4)
APPLY_GENERATE_AI = "generate+ai"         # + `ai enable` (re-render edge-ai.timer + daemon-reload + re-arm)
APPLY_GENERATE_SYSCTL = "generate+sysctl" # + `sysctl --system` (re-apply the forwarding drop-in)

_APPLY_TAGS = {APPLY_NONE, APPLY_GENERATE, APPLY_GENERATE_FIREWALL, APPLY_GENERATE_DNSMASQ,
               APPLY_GENERATE_AI, APPLY_GENERATE_SYSCTL}

_APPLY_DESC = {
    APPLY_NONE: "stored only (reserved / inert — nothing re-renders)",
    APPLY_GENERATE: "re-renders configs (`bastion generate`)",
    APPLY_GENERATE_FIREWALL: "re-renders configs, then reloads the firewall (`bastion firewall reload`)",
    APPLY_GENERATE_DNSMASQ: "re-renders configs, then reloads DNS/DHCP (dnsmasq + unbound)",
    APPLY_GENERATE_AI: "re-renders configs, then re-arms the AI timer (`bastion ai enable`)",
    APPLY_GENERATE_SYSCTL: "re-renders configs, then re-applies kernel sysctls (`sysctl --system`)",
}


# --- new validators (the existing _v_* don't cover these; kept local to avoid touching wizard) ---
def _v_posint(v: str) -> bool:
    return not v or (v.isdigit() and int(v) > 0)


def _v_url(v: str) -> bool:
    """An http(s)/scheme URL (egress probe, blocklist sources). Lenient — the fetch is authoritative."""
    return not v or bool(re.fullmatch(r"[a-z][a-z0-9+.-]*://\S+", v))


def _v_url_list(v: str) -> bool:
    return all(_v_url(p) for p in v.split())


def _v_domains(v: str) -> bool:
    """Space/comma-separated bare domains (the DNS never-sink allowlist)."""
    return all(re.fullmatch(r"[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+", p)
               for p in v.replace(",", " ").split())


def _v_dns_upstream(v: str) -> bool:
    """`host[#port]` (e.g. 127.0.0.1#5335) or a bare IP/hostname. Typo-catching only."""
    if not v:
        return True
    host = v.split("#", 1)[0]
    if _v_ip(host):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9.-]+", host))


def _v_service_ports(v: str) -> bool:
    """Space/comma-separated `port` or `port/proto` (proto tcp|udp). Blank = none (a locked endpoint)."""
    for tok in v.replace(",", " ").split():
        port, sep, proto = tok.partition("/")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            return False
        if sep and proto.lower() not in ("tcp", "udp"):
            return False
    return True


def _v_choice(*choices):
    return lambda v: (not v) or v in choices


def _v_layers(v: str) -> bool:
    ids = {f"l{i}" for i in range(7)}
    return all(p.strip() in ids for p in v.split(",") if p.strip())


@dataclass(frozen=True)
class Setting:
    key: str                       # "ports.ssh" — dotted section.option (the public id)
    section: str
    option: str
    label: str
    help: str
    tier: str                      # EVERYDAY | ADVANCED
    validator: Callable[[str], bool]
    hint: str                      # expected-format string for error messages
    apply: str = APPLY_GENERATE_FIREWALL
    choices: tuple = ()
    scope: str = "both"            # both | edge | endpoint
    layer_gate: str = ""           # e.g. "l4" — value is inert until that layer is active
    normalize: Callable[[str], str | None] | None = None
    list_sep: str = ""             # "," / " " for list-valued keys (add/remove helpers use it)


def _S(key, label, help, tier, validator, hint, apply=APPLY_GENERATE_FIREWALL, **kw):
    section, option = key.split(".", 1)
    return Setting(key=key, section=section, option=option, label=label, help=help, tier=tier,
                   validator=validator, hint=hint, apply=apply, **kw)


SETTINGS: tuple[Setting, ...] = (
    # ---- EVERYDAY -------------------------------------------------------------------------------
    _S("ports.ssh", "SSH port", "Port the firewall accepts SSH on.", EVERYDAY, _v_port,
       "a port 1–65535", APPLY_GENERATE_FIREWALL),
    _S("network.trusted_hosts", "Trusted hosts", "IPs/CIDRs always allowed full inbound access.",
       EVERYDAY, _v_hosts, "comma-separated IPs/CIDRs", APPLY_GENERATE_FIREWALL, list_sep=","),
    _S("network.service_ports", "Service ports",
       "Inbound ports to open to LAN/overlay so a server can run bastion (blank = locked endpoint).",
       EVERYDAY, _v_service_ports, "ports like 8096, 53/udp (port or port/proto)",
       APPLY_GENERATE_FIREWALL, list_sep=" "),
    _S("network.dns_upstream", "DNS upstream", "Upstream resolver dnsmasq forwards to (host#port).",
       EVERYDAY, _v_dns_upstream, "host#port (e.g. 127.0.0.1#5335) or an IP/hostname",
       APPLY_GENERATE_DNSMASQ, scope="edge", layer_gate="l4"),
    _S("network.dhcp_range_start", "DHCP pool start", "First IP in the DHCP pool.", EVERYDAY, _v_ip,
       "an IP like 10.0.1.100", APPLY_GENERATE_DNSMASQ, scope="edge", layer_gate="l4"),
    _S("network.dhcp_range_end", "DHCP pool end", "Last IP in the DHCP pool.", EVERYDAY, _v_ip,
       "an IP like 10.0.1.249", APPLY_GENERATE_DNSMASQ, scope="edge", layer_gate="l4"),
    _S("network.dhcp_lease", "DHCP lease", "DHCP lease time (systemd time span).", EVERYDAY,
       lambda v: normalize_timer_interval(v) is not None, "a time span like 12h / 30min",
       APPLY_GENERATE_DNSMASQ, scope="edge", layer_gate="l4", normalize=normalize_timer_interval),
    _S("ai.timer_interval", "AI cadence", "How often the AI analysis runs.", EVERYDAY,
       lambda v: normalize_timer_interval(v) is not None, "a time span like 4h / 30min / 90s",
       APPLY_GENERATE_AI, layer_gate="l3", normalize=normalize_timer_interval),
    _S("ai.depth", "AI depth", "How much config the AI is SHOWN (not what it may apply).", EVERYDAY,
       _v_choice("regular", "advanced", "expert"), "regular | advanced | expert", APPLY_GENERATE,
       choices=("regular", "advanced", "expert"), layer_gate="l3"),
    _S("recovery.window_seconds", "Recovery window", "Seconds before recovery auto-stops.", EVERYDAY,
       _v_posint, "a positive integer (seconds)", APPLY_GENERATE),
    _S("recovery.dedicated_port", "Recovery port", "Fixed recovery SSH port (blank = auto-pick).",
       EVERYDAY, _v_port, "a port 1–65535 (or blank for auto)", APPLY_GENERATE),
    _S("recovery.try_port_22", "Recovery tries :22", "Also bind port 22 for recovery when free.",
       EVERYDAY, _v_choice("yes", "no"), "yes | no", APPLY_GENERATE, choices=("yes", "no")),
    _S("monitoring.egress_probe", "Egress probe", "URL the watchdog/flowcheck use as the ISP-up canary.",
       EVERYDAY, _v_url, "an http(s) URL", APPLY_GENERATE),
    _S("monitoring.relay_endpoint", "Relay public endpoint",
       "Public IP of the upstream relay/tunnel far end; folded into the never-block allowlist.",
       EVERYDAY, _v_ip, "an IP like 198.51.100.1", APPLY_GENERATE, scope="edge"),
    _S("monitoring.feed_sources", "IP blocklist feeds",
       "Public IP-blocklist feed URLs edge-feed-fetch pulls (space-separated; blank = built-in defaults).",
       EVERYDAY, _v_url_list, "space-separated http(s) URLs", APPLY_GENERATE, layer_gate="l1",
       list_sep=" "),
    _S("monitoring.dnsblock_sources", "DNS blocklist sources", "Blocklist feed URLs (space-separated).",
       EVERYDAY, _v_url_list, "space-separated http(s) URLs", APPLY_GENERATE, scope="edge",
       layer_gate="l4", list_sep=" "),
    _S("monitoring.dns_allowlist", "DNS never-sink allowlist",
       "Domains the sinkhole must NEVER block (covers subdomains); on top of the shipped defaults.",
       EVERYDAY, _v_domains, "space-separated domains", APPLY_GENERATE, scope="edge",
       layer_gate="l4", list_sep=" "),

    # ---- ADVANCED (gated) -----------------------------------------------------------------------
    _S("machine.firewall_scope", "Firewall ownership",
       "exclusive = bastion owns the whole ruleset (flush ruleset); cooperative = manage only "
       "bastion's own nft table, leaving co-resident firewalls (libvirt/docker) intact.",
       ADVANCED, _v_choice("exclusive", "cooperative"), "exclusive | cooperative",
       APPLY_GENERATE_FIREWALL, choices=("exclusive", "cooperative")),
    _S("network.lan_cidr", "LAN subnet", "The LAN CIDR. Changing it reshapes DHCP + firewall scope.",
       ADVANCED, _v_cidr, "a CIDR like 10.0.1.0/24", APPLY_GENERATE_FIREWALL, scope="edge"),
    _S("network.lan_ip", "LAN IP", "This node's LAN address.", ADVANCED, _v_ip,
       "an IP like 10.0.1.1", APPLY_GENERATE_FIREWALL, scope="edge"),
    _S("network.gateway", "Gateway", "Upstream router IP (watchdog ISP-up probe).", ADVANCED, _v_ip,
       "an IP like 10.0.1.254", APPLY_GENERATE_FIREWALL, scope="edge"),
    _S("network.ipv6_forward", "IPv6 forwarding",
       "Route IPv6 (make the edge box a real v6 router). no = v4-only routing, v6 rules stay inert.",
       ADVANCED, _v_choice("yes", "no"), "yes | no", APPLY_GENERATE_SYSCTL, choices=("yes", "no"),
       scope="edge"),
    _S("interfaces.lan", "LAN interface", "LAN NIC name.", ADVANCED, _v_iface, "an interface name",
       APPLY_GENERATE_FIREWALL),
    _S("interfaces.wan", "WAN interface", "Uplink NIC name.", ADVANCED, _v_iface, "an interface name",
       APPLY_GENERATE_FIREWALL, scope="edge"),
    _S("interfaces.zt_iface", "ZeroTier interface", "ZeroTier NIC name.", ADVANCED, _v_iface,
       "an interface name", APPLY_GENERATE_FIREWALL),
    _S("interfaces.wg_vps_iface", "WG relay interface", "Upstream WireGuard/relay NIC.", ADVANCED,
       _v_iface, "an interface name", APPLY_GENERATE_FIREWALL),
    _S("interfaces.wg_server_iface", "WG server interface", "Inbound WireGuard server NIC.", ADVANCED,
       _v_iface, "an interface name", APPLY_GENERATE_FIREWALL),
    _S("ai.backend_cmd", "AI backend command", "Executable the analyzer shells out to.", ADVANCED,
       lambda v: bool(v.strip()), "a path to an executable", APPLY_GENERATE, layer_gate="l3"),
    _S("ai.model", "AI model", "Model id passed to the backend.", ADVANCED,
       lambda v: bool(v.strip()), "a model id", APPLY_GENERATE, layer_gate="l3"),
    _S("ai.max_intents", "AI max intents", "Max intents applied per run.", ADVANCED, _v_posint,
       "a positive integer", APPLY_GENERATE, layer_gate="l3"),
    _S("ai.expert_canary_seconds", "Expert canary (reserved)", "Reserved/inert (future auto-apply).",
       ADVANCED, _v_posint, "a positive integer", APPLY_NONE, layer_gate="l3"),
    _S("ai.expert_confidence_floor", "Expert confidence floor (reserved)", "Reserved/inert.",
       ADVANCED, lambda v: not v or _is_float(v), "a number 0–1", APPLY_NONE, layer_gate="l3"),
)


def _is_float(v: str) -> bool:
    try:
        float(v); return True
    except ValueError:
        return False


_BY_KEY = {s.key: s for s in SETTINGS}


def get(key: str) -> Setting | None:
    return _BY_KEY.get(key)


def by_group() -> dict[str, list[Setting]]:
    """Settings grouped by section (preserving registry order) for a menu/list."""
    groups: dict[str, list[Setting]] = {}
    for s in SETTINGS:
        groups.setdefault(s.section, []).append(s)
    return groups


def current_value(config: dict, setting: Setting) -> str:
    return (config.get(setting.section, {}).get(setting.option) or "")


def applies_to(setting: Setting, config: dict) -> tuple[bool, str]:
    """(applies, note). False = hard scope mismatch (wrong mode) — refuse. True+note = the value is
    valid but inert because its gating layer isn't active (warn-but-proceed)."""
    mode = config.get("machine", {}).get("mode", "edge")
    if setting.scope != "both" and setting.scope != mode:
        return False, f"{setting.key} applies only to {setting.scope} mode (this node is {mode})"
    if setting.layer_gate:
        layers = [l.strip() for l in config.get("machine", {}).get("layers", "").split(",")]
        if setting.layer_gate not in layers:
            return True, f"layer {setting.layer_gate} is not active — the value is stored but inert until it is"
    return True, ""


def validate_value(setting: Setting, value: str) -> tuple[str | None, str | None]:
    """Returns (normalized_value, error). Applies the setting's normalizer (if any) then its
    validator / choices. error is a human string when the value is rejected."""
    val = value
    if setting.normalize is not None:
        val = setting.normalize(value)
        if val is None:
            return None, f"{setting.key}: {value!r} is invalid — expected {setting.hint}"
    if setting.choices and val and val not in setting.choices:
        return None, f"{setting.key}: must be one of {', '.join(setting.choices)}"
    if not setting.validator(val):
        return None, f"{setting.key}: {value!r} is invalid — expected {setting.hint}"
    return val, None


# --- list-valued helpers (trusted_hosts, dnsblock_sources) -----------------------------------------
def list_items(value: str, sep: str) -> list[str]:
    raw = value.replace(",", " ").split() if sep == "," else value.split()
    return [p for p in raw if p]


def list_add(value: str, item: str, sep: str) -> str:
    items = list_items(value, sep)
    if item not in items:
        items.append(item)
    return _join(items, sep)


def list_remove(value: str, item: str, sep: str) -> str:
    return _join([i for i in list_items(value, sep) if i != item], sep)


def _join(items: list[str], sep: str) -> str:
    return (", " if sep == "," else " ").join(items)


@dataclass
class ConfigChangeResult:
    key: str
    old: str
    new: str
    rc: int = 0
    wrote: bool = False
    steps: list[str] = field(default_factory=list)


def resolve_conf_path(conf: str | None, root: str | None) -> Path:
    """Where config get/set reads + writes machine.conf: explicit --conf, else under --root, else
    the default search path."""
    if conf:
        return Path(conf)
    if root:
        return System(root=Path(root)).path("/etc/bastion/machine.conf")
    return state.find_conf(None)


def apply_change(key: str, value: str, *, conf: str | None = None, root: str | None = None,
                 dry_run: bool = False, advanced: bool = False, assume_yes: bool = False,
                 out=print) -> ConfigChangeResult:
    """Validate, write, and apply a single config change. Returns a ConfigChangeResult; prints
    progress via `out`. The ONE write path shared by `bastion config set`, the domain verbs, the
    E7 verbs, and (through the CLI) the TUI."""
    from . import cli   # lazy: cli imports configspec

    setting = get(key)
    if setting is None:
        out(f"unknown setting {key!r} (see `bastion config list`)")
        return ConfigChangeResult(key, "", "", rc=1)

    conf_path = resolve_conf_path(conf, root)
    sys_ = System(root=Path(root) if root else Path("/"))
    try:
        config = state.load_conf(conf_path)
    except FileNotFoundError:
        out(f"no machine.conf at {conf_path} — run `bastion setup` first")
        return ConfigChangeResult(key, "", "", rc=1)

    ok_scope, note = applies_to(setting, config)
    if not ok_scope:
        out(f"refused: {note}")
        return ConfigChangeResult(key, current_value(config, setting), value, rc=1)

    norm, err = validate_value(setting, value)
    if err:
        out(err)
        return ConfigChangeResult(key, current_value(config, setting), value, rc=1)

    old = current_value(config, setting)
    new = norm
    staged = copy.deepcopy(config)
    staged.setdefault(setting.section, {})[setting.option] = new

    # whole-conf gate — a bad value never lands, and cross-field warnings surface.
    errs, warns = state.validate_conf(staged)
    if errs:
        out(f"refused — the change would make machine.conf invalid:")
        for e in errs:
            out(f"  {e}")
        return ConfigChangeResult(key, old, new, rc=1)

    out(f"config set {key}: {old or '(unset)'} -> {new or '(unset)'}   [{setting.tier}]")
    if note:
        out(f"  note: {note}")
    for w in warns:
        out(f"  WARNING: {w}")
    out(f"  apply: {_APPLY_DESC[setting.apply]}")

    if old == new:
        out("  unchanged — nothing to do")
        return ConfigChangeResult(key, old, new, rc=0)

    if dry_run:
        out("  --dry-run: not written")
        return ConfigChangeResult(key, old, new, rc=0)

    if setting.tier == ADVANCED and not advanced:
        out("  REFUSED: this is an ADVANCED setting (dangerous waters). Re-run with --advanced "
            "to acknowledge, e.g.:")
        out(f"    bastion config set {key} {value} --advanced")
        return ConfigChangeResult(key, old, new, rc=1)

    state.write_conf(staged, conf_path)
    out(f"  wrote {conf_path}")
    res = ConfigChangeResult(key, old, new, rc=0, wrote=True)

    rc = _run_apply(cli, setting, sys_, conf_path, root, res, out)
    res.rc = rc
    out("  done" if rc == 0 else f"  apply step returned rc={rc}")
    return res


def apply_firewall_change(conf_path: Path, root: str | None, *, out=print) -> int:
    """Regenerate templates from machine.conf and (live only) reload the firewall.

    The generate→nft-reload tail shared by domain verbs that edit a whole *section* (e.g. `bastion
    zones`) rather than a single registry `Setting`, so they reuse `apply_change`'s apply behaviour
    without a `Setting`. The caller is responsible for validating + writing the conf first. On a
    staged `--root` tree the live reload is skipped (regen still runs into the staged tree)."""
    from . import cli  # lazy: cli imports configspec
    sys_ = System(root=Path(root) if root else Path("/"))
    out_base = None if sys_.root == Path("/") else str(sys_.root)
    rc = cli.cmd_generate(argparse.Namespace(conf=str(conf_path), templates=None, out=out_base, check=False))
    if rc != 0:
        return rc
    if not sys_.is_live:
        out("  (staged --root: live reload skipped)")
        return 0
    return cli.cmd_firewall(argparse.Namespace(action="reload", conf=str(conf_path), root=root))


def _run_apply(cli, setting: Setting, sys_: System, conf_path: Path, root: str | None,
               res: ConfigChangeResult, out) -> int:
    """Run only the regen+reload the setting's apply tag calls for. Live reloads are skipped on a
    staged --root tree (regen still runs into the staged tree)."""
    tag = setting.apply
    if tag == APPLY_NONE:
        return 0
    out_base = None if sys_.root == Path("/") else str(sys_.root)
    rc = cli.cmd_generate(argparse.Namespace(conf=str(conf_path), templates=None, out=out_base, check=False))
    res.steps.append("generate")
    if rc != 0:
        return rc
    if not sys_.is_live:
        out("  (staged --root: live reload skipped)")
        return 0
    if tag == APPLY_GENERATE_FIREWALL:
        rc = cli.cmd_firewall(argparse.Namespace(action="reload", conf=str(conf_path), root=root))
        res.steps.append("firewall reload")
    elif tag == APPLY_GENERATE_DNSMASQ:
        for unit in ("dnsmasq", "unbound"):
            sys_.run("systemctl", "reload", unit)
        res.steps.append("dnsmasq/unbound reload")
    elif tag == APPLY_GENERATE_AI:
        rc = cli.cmd_ai(argparse.Namespace(action="enable", id=None, conf=str(conf_path), root=root))
        res.steps.append("ai re-arm")
    elif tag == APPLY_GENERATE_SYSCTL:
        sys_.run("sysctl", "--system")
        res.steps.append("sysctl --system")
    return rc
