"""Setup wizard — the §10 flow, rule-based (Phase 5).

No AI here: the AI-assisted layer recommendation (§10 step 3) is Phase 6 (`ai_assistant.py`),
and nothing in this module makes a network/API call. The wizard DETECTS, PROPOSES, and asks the
user to confirm or correct; the confirmed value is what writes machine.conf (§10 universal
heuristics principle).

Structure (testability): `build_machine_conf()` is pure — detection + profile + user answers in,
the nested machine.conf dict out. It overlays onto the shipped `machine.conf.example` skeleton so
every template placeholder is guaranteed to resolve (the Phase-2 generate-check invariant). The
interactive `Wizard` drives prompts and the dry-run preview around that pure core.
"""
from __future__ import annotations

import getpass
import ipaddress
import re
import sys as _sys
from dataclasses import dataclass, field
from pathlib import Path

from .. import state, templates
from ..system import System
from . import ai_backend
from . import alerts as alertsmod
from . import detect as detectmod
from . import pkg as pkgmod
from . import vpn_setup

# Profile -> active layers (§4). "custom" is resolved from user selection, not here.
PROFILE_LAYERS: dict[str, str] = {
    "full-edge": "l0,l1,l2,l3,l4,l5,l6",
    "basic-edge": "l0,l1,l2,l4,l6",
    "full-endpoint": "l0,l1,l2,l3,l6",
    "minimal-endpoint": "l0,l1,l6",
}
EDGE_PROFILES = ("full-edge", "basic-edge")
ENDPOINT_PROFILES = ("full-endpoint", "minimal-endpoint")
DEFAULT_PROFILE = {"edge": "full-edge", "endpoint": "full-endpoint"}

# Answer keys settable non-interactively via `bastion setup --set key=value`. These are the
# same flat keys build_machine_conf() consumes, so a --set value overrides BOTH detection and
# any prompt default — the supported way to script/reproduce a setup (e.g. trusted_hosts, which
# detection cannot know). An unknown key is a hard error, never silently ignored.
SETTABLE_KEYS: tuple[str, ...] = (
    "mode", "profile", "layers",
    "lan_iface", "wan_iface", "lan_cidr", "lan_ip", "gateway",
    "dhcp_range_start", "dhcp_range_end", "trusted_hosts", "dns_upstream",
    "ssh_port", "ai_depth", "timer_interval", "ai_backend_cmd", "ai_model", "secrets_file",
)


# AI analysis cadence — the per-operator control knob for how often edge-ai runs (rendered into
# edge-ai.timer's OnUnitActiveSec). Skeleton default; the wizard prompts for it and validates.
DEFAULT_TIMER_INTERVAL = "4h"

# systemd.time(7) span units. CASE-SENSITIVE on purpose: lowercase `m`/`min` = minutes, uppercase
# `M` = months — so this regex must not be compiled with IGNORECASE or the two would collapse.
_TS_UNITS = (r"(?:usec|us|msec|ms|seconds?|secs?|s|minutes?|min|m|"
             r"hours?|hr|h|days?|d|weeks?|w|months?|M|years?|y)")
_TS_PART = re.compile(r"(\d+(?:\.\d+)?)\s*" + _TS_UNITS)


def normalize_timer_interval(raw: str) -> str | None:
    """Validate an AI-cadence value the way systemd would parse OnUnitActiveSec. Accepts a bare
    integer (= seconds) or one-or-more ``<number><unit>`` spans — e.g. ``4h``, ``30min``, ``90s``,
    ``2h30m``, ``1d 12h``. Returns the cleaned string, or ``None`` if systemd would reject it, so a
    bad knob is caught at setup/generate time instead of failing the timer load. Case matters:
    ``m`` = minutes, ``M`` = months (mirrors systemd.time(7))."""
    s = (raw or "").strip()
    if not s:
        return None
    if re.fullmatch(r"\d+", s):
        return s                      # bare integer => seconds
    pos = 0
    saw = False
    for m in _TS_PART.finditer(s):
        if s[pos:m.start()].strip():  # non-whitespace junk before/between tokens
            return None
        saw = True
        pos = m.end()
    if not saw or s[pos:].strip():    # nothing matched, or trailing junk
        return None
    return s


# --- answer validators (B8: typo-catching at the wizard boundary, NOT a security control —
#     the real gate is `nft -c` + reconciler re-validation; this just stops a fat-fingered CIDR
#     surfacing three steps later as an opaque dnsmasq/nft failure). Each accepts blank (the
#     caller decides whether blank is allowed); only a *non-blank, malformed* value is rejected. ---
def _v_port(v: str) -> bool:
    return not v or (v.isdigit() and 1 <= int(v) <= 65535)


def _v_ip(v: str) -> bool:
    if not v:
        return True
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _v_cidr(v: str) -> bool:
    if not v:
        return True
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


def _v_hosts(v: str) -> bool:
    """Comma-separated single IPs and/or CIDRs (the nft trusted_hosts element list)."""
    if not v:
        return True
    for part in (p.strip() for p in v.split(",") if p.strip()):
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            return False
    return True


def _v_iface(v: str) -> bool:
    """A plausible Linux interface name (IFNAMSIZ caps the kernel name at 15 chars)."""
    return not v or (len(v) <= 15 and re.fullmatch(r"[A-Za-z0-9._@:-]+", v) is not None)


# --set keys whose values carry a typed format — validated at parse time so a scripted/repeatable
# setup fails loud on a typo instead of writing a broken machine.conf (mirrors the interactive
# re-prompt). timer_interval is validated separately (systemd time-span grammar).
_SET_VALIDATORS = {
    "lan_cidr": (_v_cidr, "a CIDR like 192.168.1.0/24"),
    "lan_ip": (_v_ip, "an IP like 192.168.1.1"),
    "gateway": (_v_ip, "an IP like 192.168.1.1"),
    "ssh_port": (_v_port, "a port in 1–65535"),
    "trusted_hosts": (_v_hosts, "comma-separated IPs/CIDRs"),
}


def parse_overrides(pairs) -> dict[str, str]:
    """Parse `--set key=value` strings into an answers-override dict. Raises ValueError on a
    malformed pair, an unknown key (listing the valid keys), or a typed value that fails its
    validator — fail loud, never silently drop."""
    out: dict[str, str] = {}
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        key = key.strip()
        if not sep:
            raise ValueError(f"--set must be key=value (got {pair!r})")
        if key not in SETTABLE_KEYS:
            raise ValueError(f"--set: unknown key {key!r}; valid keys: {', '.join(SETTABLE_KEYS)}")
        value = value.strip()
        if key == "timer_interval" and normalize_timer_interval(value) is None:
            raise ValueError(f"--set timer_interval {value!r} is not a valid systemd time span "
                             "(e.g. 4h, 30min, 90s, 2h30m)")
        if key in _SET_VALIDATORS and value:
            fn, hint = _SET_VALIDATORS[key]
            if not fn(value):
                raise ValueError(f"--set {key} {value!r} is invalid — expected {hint}.")
        out[key] = value
    return out


def profile_mode(profile: str) -> str | None:
    if profile in EDGE_PROFILES:
        return "edge"
    if profile in ENDPOINT_PROFILES:
        return "endpoint"
    return None   # custom — mode-agnostic


def find_example_conf(explicit: str | None = None) -> Path:
    """Locate machine.conf.example (the default-skeleton source)."""
    if explicit:
        return Path(explicit)
    # Packaged location (ships with the wheel) first, then a cwd fallback for dev checkouts.
    for c in (Path(__file__).resolve().parent.parent / "machine.conf.example",
              Path.cwd() / "machine.conf.example"):
        if c.is_file():
            return c
    raise FileNotFoundError("machine.conf.example not found; pass example_conf")


def derive_dhcp_pool(lan_cidr: str | None) -> tuple[str, str] | tuple[None, None]:
    """Derive a default DHCP pool that actually lies inside ``lan_cidr``.

    The skeleton ships a generic ``10.0.1.100–249`` pool; left as-is it lands OUTSIDE an
    operator-supplied LAN subnet (so dnsmasq would hand out unroutable leases). Prefer the
    familiar ``.100–.249`` window when it fits (e.g. any /24); otherwise fall back to the upper
    half of the usable range. Returns ``(None, None)`` for an unparseable/too-small subnet, so
    the caller keeps the skeleton default rather than inventing a broken one.
    """
    try:
        net = ipaddress.ip_network(str(lan_cidr), strict=False)
    except (ValueError, TypeError):
        return None, None
    hosts = list(net.hosts())
    if len(hosts) < 2:
        return None, None
    lo, hi = net.network_address + 100, net.network_address + 249
    if lo in net and hi in net and lo != net.network_address:
        return str(lo), str(hi)
    # Small subnet: upper half of the usable range, last host reserved as the top.
    return str(hosts[len(hosts) // 2]), str(hosts[-1])


def build_machine_conf(detection: detectmod.Detection, profile: str,
                       answers: dict | None, base: dict) -> dict[str, dict[str, str]]:
    """Pure: assemble a complete machine.conf dict.

    Precedence (low -> high): `base` skeleton (the shipped example, guarantees all keys exist)
    < detected values < explicit user `answers`. A complete conf means `bastion generate` resolves
    every template against it.
    """
    answers = answers or {}
    # Deep-copy the skeleton so we never mutate the caller's dict.
    conf = {sec: dict(items) for sec, items in base.items()}

    def put(section: str, key: str, value) -> None:
        if value is None or value == "":
            return
        conf.setdefault(section, {})[key] = str(value)

    mode = answers.get("mode") or detection.proposed_mode
    layers = answers.get("layers") or PROFILE_LAYERS.get(profile) or base["machine"].get("layers", "")

    put("machine", "mode", mode)
    put("machine", "profile", profile)
    put("machine", "layers", layers)
    put("machine", "distro", detection.distro)
    put("machine", "schema_version", str(state.CONF_SCHEMA_VERSION))

    put("interfaces", "lan", answers.get("lan_iface") or detection.lan_iface)
    if mode == "edge":
        put("interfaces", "wan", answers.get("wan_iface") or detection.wan_iface)
    else:
        # endpoint has no WAN; keep the key (template-safe) but blank it.
        conf.setdefault("interfaces", {})["wan"] = answers.get("wan_iface", "")

    eff_lan_cidr = answers.get("lan_cidr") or detection.lan_cidr
    put("network", "lan_cidr", eff_lan_cidr)
    put("network", "lan_ip", answers.get("lan_ip") or detection.lan_ip)
    put("network", "gateway", answers.get("gateway") or detection.gateway)
    if mode == "edge":
        # Keep the DHCP pool inside the LAN: explicit answers win, else derive from lan_cidr,
        # else leave the skeleton default (only reached when lan_cidr is unparseable).
        d_start, d_end = derive_dhcp_pool(eff_lan_cidr)
        put("network", "dhcp_range_start", answers.get("dhcp_range_start") or d_start)
        put("network", "dhcp_range_end", answers.get("dhcp_range_end") or d_end)
    if "trusted_hosts" in answers:
        conf.setdefault("network", {})["trusted_hosts"] = answers["trusted_hosts"]
    if "dns_upstream" in answers:
        put("network", "dns_upstream", answers["dns_upstream"])

    put("ports", "ssh", answers.get("ssh_port") or detection.ssh_port)

    if "ai_depth" in answers:
        put("ai", "depth", answers["ai_depth"])
    if "timer_interval" in answers:
        iv = normalize_timer_interval(answers["timer_interval"])
        if iv is None:
            raise ValueError(
                f"ai.timer_interval {answers['timer_interval']!r} is not a valid systemd time "
                "span (e.g. 4h, 30min, 90s, 2h30m)")
        put("ai", "timer_interval", iv)
    if "ai_backend_cmd" in answers:
        put("ai", "backend_cmd", answers["ai_backend_cmd"])
    if "ai_model" in answers:
        put("ai", "model", answers["ai_model"])

    if "secrets_file" in answers:
        put("machine", "secrets_file", answers["secrets_file"])

    if mode == "endpoint":
        # An endpoint doesn't route, tunnel, or serve DNS/DHCP, so blank the edge-only fields the
        # (edge-shaped) skeleton carries — otherwise the generated machine.env hands stale edge
        # values to flowcheck/edge-watchdog, which then false-fail or run edge recovery on a node
        # that has no edge config. Kept: lan / lan_cidr / trusted_hosts / ssh (the endpoint ruleset
        # uses these); wan is already blanked above.
        for sec, key in (
            ("interfaces", "zt_iface"), ("interfaces", "wg_vps_iface"),
            ("interfaces", "wg_server_iface"),
            ("network", "lan_ip"), ("network", "gateway"), ("network", "zt_cidr"),
            ("network", "wg_server_cidr"), ("network", "dns_upstream"),
            ("network", "dhcp_range_start"), ("network", "dhcp_range_end"),
            ("network", "dhcp_lease"),
            ("monitoring", "relay_dst"), ("monitoring", "relay_endpoint"),
            ("monitoring", "dnsblock_sources"),
        ):
            conf.setdefault(sec, {})[key] = ""
    return conf


# --- interactive wizard ----------------------------------------------------

@dataclass
class WizardResult:
    config: dict[str, dict[str, str]]
    mode: str
    profile: str
    dry_run: bool
    written: list[str] = field(default_factory=list)
    install_plan: list[str] = field(default_factory=list)   # packages that would be installed
    notes: list[str] = field(default_factory=list)


class Wizard:
    def __init__(self, sys: System, *, dry_run: bool = False, profile: str | None = None,
                 no_ai: bool = True, inp=input, out=print, assume_defaults: bool | None = None,
                 example_conf: str | None = None, secret_inp=getpass.getpass,
                 overrides: dict[str, str] | None = None, bootstrap: bool = False):
        self.sys = sys
        self.dry_run = dry_run
        self.profile_arg = profile
        self.no_ai = no_ai
        # D5: soft-recovery. Distrust the existing machine.conf (don't overlay it as the base) and
        # surface where detection disagrees with it — the "changed SSH port, locked myself out" fix.
        self.bootstrap = bootstrap
        self.inp = inp
        self.out = out
        self.secret_inp = secret_inp   # hidden input for secrets (getpass); injectable for tests
        # `--set key=value` answers: override detection AND prompt defaults, in either mode.
        self.overrides = overrides or {}
        # Non-interactive (no tty / piped) -> accept every detected/proposed default.
        self.assume_defaults = (not _sys.stdin.isatty()) if assume_defaults is None else assume_defaults
        # Was non-interactive auto-detected (vs. explicitly requested, e.g. by tests)? Used to
        # surface a discoverable hint that --set is how you override defaults without a TTY.
        self._auto_noninteractive = assume_defaults is None and self.assume_defaults
        self.example_path = find_example_conf(example_conf)

    # --- prompt helpers ---
    def _ask(self, prompt: str, default: str) -> str:
        if self.assume_defaults:
            self.out(f"  {prompt} [{default}]")
            return default
        raw = self.inp(f"  {prompt} [{default}]: ").strip()
        return raw or default

    def _confirm(self, prompt: str, default: bool = True) -> bool:
        if self.assume_defaults:
            return default
        raw = self.inp(f"  {prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        return default if not raw else raw.startswith("y")

    def _choose(self, prompt: str, options: list[str], default: str) -> str:
        if self.assume_defaults:
            self.out(f"  {prompt}: {default}")
            return default
        self.out(f"  {prompt}")
        for i, o in enumerate(options, 1):
            self.out(f"    {i}) {o}" + ("  (default)" if o == default else ""))
        raw = self.inp("  choice: ").strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        return raw if raw in options else default

    def _ask_validated(self, prompt: str, default: str, validator, hint: str) -> str:
        """Like _ask, but re-prompts until the answer passes `validator` (B8). Blank is always
        accepted (the validators treat blank as 'unset' — the caller/skeleton decides if that's
        OK). Non-interactive: never loop on a bad detected default — take it and move on (the
        detected value should already be valid; a bad one is surfaced later by generate)."""
        while True:
            v = self._ask(prompt, default)
            if validator(v):
                return v
            self.out(f"  '{v}' isn't valid — expected {hint}.")
            if self.assume_defaults:
                return default

    def _current_timer_interval(self) -> str:
        """Default for the AI-cadence prompt: an existing live machine.conf value (preserve it on
        reinstall), else the shipped skeleton default — never lose a deliberate operator setting."""
        for p in (self.sys.path("etc/bastion/machine.conf"), self.example_path):
            try:
                v = state.load_conf(p).get("ai", {}).get("timer_interval", "").strip()
                if normalize_timer_interval(v):
                    return v
            except Exception:
                continue
        return DEFAULT_TIMER_INTERVAL

    def _ask_timer_interval(self, default: str) -> str:
        """Prompt for the AI run cadence, re-asking until the value is a systemd time span."""
        while True:
            raw = self._ask("AI analysis interval — how often edge-ai runs (systemd time span)",
                            default)
            iv = normalize_timer_interval(raw)
            if iv:
                return iv
            self.out(f"  '{raw}' isn't a valid time span — try e.g. 4h, 30min, 90s, 2h30m.")
            if self.assume_defaults:   # non-interactive: never loop on a bad default
                return default

    # --- flow ---
    def run(self) -> WizardResult:
        out = self.out
        out("== bastion setup " + ("(DRY RUN — nothing will be written/installed) ==" if self.dry_run
                                    else "==") )
        if self._auto_noninteractive:
            out("  (non-interactive: no TTY detected — accepting detected defaults; "
                "override any value with --set KEY=VALUE)")

        # 1. DETECT
        out("\n[1/8] Detecting topology...")
        d = detectmod.detect(self.sys)
        self._show_detection(d)

        # 2. CONFIRM MODE
        out("\n[2/8] Deployment mode")
        # An explicit --profile carries a definite mode (e.g. minimal-endpoint -> endpoint); that
        # user intent seeds the default over the raw detection proposal. The user still confirms.
        mode_default = profile_mode(self.profile_arg or "") or d.proposed_mode
        if mode_default != d.proposed_mode:
            out(f"  (detection proposed {d.proposed_mode}; --profile {self.profile_arg} "
                f"implies {mode_default})")
        mode = self.overrides.get("mode") or self._choose("Confirm mode", ["edge", "endpoint"],
                                                          mode_default)
        self._conflict_warn(d, mode)

        # 3. PROFILE
        out("\n[3/8] Profile")
        profile = self.overrides.get("profile") or self._select_profile(mode)
        self._prereq_warn(profile, d)

        # 4. LAYER CONFIGURATION (essential machine.conf values; user confirms detected ones)
        out("\n[4/8] Layer configuration")
        answers = self._layer_questions(d, mode, profile)
        # Thread the CONFIRMED mode through so the written conf honours the operator's choice
        # (and --profile), instead of build_machine_conf silently falling back to detection's
        # proposed_mode when the two disagree.
        answers["mode"] = mode
        # `--set key=value` wins over both detection and prompt answers — the scriptable path
        # for values a prompt would otherwise own (e.g. trusted_hosts).
        if self.overrides:
            answers.update(self.overrides)
            out("  applied --set: " + ", ".join(f"{k}={v}" for k, v in self.overrides.items()))

        # 5. SECRETS — the L3 API key and the L6 alert sinks: both are operator/secret config written
        #    out-of-band (chmod 600), never into machine.conf.
        out("\n[5/8] Secrets")
        notes = self._secrets_step(profile, answers)
        notes += self._alerts_step(profile)

        # build the conf now that all answers are gathered. A4: if a machine.conf already exists,
        # overlay the skeleton with it FIRST so operator hand-edits the wizard never prompts for
        # (e.g. ai.depth, a custom layer list) survive a re-run — detection + the answers above
        # still take precedence (they flow in as the high-priority layer of build_machine_conf).
        base = state.load_conf(self.example_path)
        existing = self._load_existing_conf()
        if self.bootstrap:
            # D5: re-detect from zero; do NOT overlay the (possibly broken) conf, and show the diff
            # so the operator sees what the current conf got wrong before the fresh one is written.
            self.out("  soft-recovery (--bootstrap): re-detecting from scratch; the existing "
                     "machine.conf is NOT trusted for detected values.")
            if existing:
                self._show_bootstrap_diff(d, existing)
        elif existing:
            base = self._merge_conf(base, existing)
            self.out("  found an existing machine.conf — preserving settings you didn't change "
                     "(your answers + detection still take precedence).")
        config = build_machine_conf(d, profile, answers, base)

        # C1: final review/confirm before ANYTHING is written or installed.
        if not self._confirm_step(config, mode, profile):
            self.out("  aborted at confirmation — nothing was written or installed.")
            return WizardResult(config=config, mode=mode, profile=profile, dry_run=self.dry_run,
                                notes=["setup aborted at the confirmation step; "
                                       "nothing written or installed."])

        # 6. GENERATE — preview in dry-run; live, write machine.conf + render templates/env.
        out("\n[6/8] Generate" + (" (preview)" if self.dry_run else ""))
        if self.dry_run:
            written, gen_notes = self._generate_preview(config, mode)
        else:
            written, gen_notes = self._generate_apply(config, mode)
        notes += gen_notes

        # 7. INSTALL — on a live root install: batch-install all active-layer packages up front,
        #    then run each layer's install() (loads nft, enables units). Dry-run / --root staging
        #    keep the non-mutating preview of the package plan.
        out("\n[7/8] Install")
        install_plan, install_notes = self._install_step(config, mode)
        notes += install_notes

        # 8. VERIFY — live: run `bastion check` (flowcheck) and offer rollback on failure;
        #    otherwise print the operator's next steps.
        out("\n[8/8] Verify")
        notes += self._verify_step(config, mode)

        return WizardResult(config=config, mode=mode, profile=profile, dry_run=self.dry_run,
                            written=written, install_plan=install_plan, notes=notes)

    # --- step helpers ---
    def _show_detection(self, d: detectmod.Detection) -> None:
        o = self.out
        o(f"  distro: {d.distro}  package-manager: {d.pkg_manager}")
        o(f"  proposed mode: {d.proposed_mode}")
        for i in d.physical_ifaces():
            o(f"  iface {i.name}: {i.kind}, {'up' if i.up else 'down'}, {i.addrs or 'no-addr'}")
        o(f"  default route: {d.default_iface or '-'} via {d.gateway or '-'}")
        o(f"  ssh port: {d.ssh_port}")
        active = sorted(k for k, v in d.services.items() if v.active)
        o(f"  active services: {', '.join(active) or 'none'}")

    def _conflict_warn(self, d: detectmod.Detection, mode: str) -> None:
        # §5/119 conflict detection: endpoint installs must not fight an existing edge/router.
        if mode == "endpoint" and d.gateway:
            self.out(f"  NOTE: endpoint mode — default gateway {d.gateway} stays untouched "
                     "(no DHCP/DNS/NAT, no default-route changes).")

    def _select_profile(self, mode: str) -> str:
        opts = list(EDGE_PROFILES if mode == "edge" else ENDPOINT_PROFILES) + ["custom"]
        default = self.profile_arg or DEFAULT_PROFILE[mode]
        if self.profile_arg and profile_mode(self.profile_arg) not in (mode, None):
            self.out(f"  WARNING: --profile {self.profile_arg} is a "
                     f"{profile_mode(self.profile_arg)} profile but mode is {mode}; ignoring.")
            default = DEFAULT_PROFILE[mode]
        chosen = default if self.assume_defaults else self._choose("Select profile", opts, default)
        self.out(f"  layers: {PROFILE_LAYERS.get(chosen, '(custom — select in machine.conf)')}")
        return chosen

    def _prereq_warn(self, profile: str, d: detectmod.Detection) -> None:
        """C5: surface packages the host's package manager cannot resolve from its repos (e.g.
        crowdsec is AUR-only on Arch, pulled in by L2) at PROFILE-selection time — before the
        operator invests the rest of the wizard — rather than only as an `unavailable` package
        at the install step. bastion never builds such packages itself (Commandment #5)."""
        layers_str = PROFILE_LAYERS.get(profile)
        if not layers_str:
            return   # custom: active layers aren't known yet; the install step still surfaces this
        layer_ids = [l.strip() for l in layers_str.split(",") if l.strip()]
        mgr = pkgmod.detect_manager(self.sys, d.pkg_manager)
        if mgr is None:
            return
        blocked = [p for p in self._packages_for_layers(layer_ids)
                   if p in getattr(mgr, "repo_unavailable", ())]
        if blocked:
            self.out(f"  NOTE: {mgr.unavailable_hint(blocked)}")
            self.out("  The rest of the firewall installs and runs without them; install the "
                     "above, then enable the affected layer.")

    def _load_existing_conf(self) -> dict | None:
        """The machine.conf already on the box (root-prefixed for --root staging), or None. Used by
        A4 to carry an operator's prior hand-edits into a re-run instead of clobbering them."""
        p = self.sys.path("/etc/bastion/machine.conf")
        if not p.exists():
            return None
        try:
            return state.load_conf(p)
        except Exception:
            return None   # an unreadable/garbled conf must not wedge setup — fall back to skeleton

    @staticmethod
    def _merge_conf(base: dict, overlay: dict) -> dict:
        """Section-wise overlay: overlay's keys win over base's, base supplies any the overlay omits
        (so every skeleton key still exists — the generate-resolves-everything invariant holds)."""
        out = {sec: dict(items) for sec, items in base.items()}
        for sec, items in overlay.items():
            dst = out.setdefault(sec, {})
            for k, v in items.items():
                dst[k] = v
        return out

    def _show_bootstrap_diff(self, d: detectmod.Detection, existing: dict) -> None:
        """D5: print the fields where the current machine.conf disagrees with fresh detection —
        the lockout culprit (often ssh port) shows up here. Only flags fields where BOTH a detected
        and a current value exist and they differ (a blank either side isn't a 'wrong' value)."""
        rows = [
            ("ssh port", str(d.ssh_port), existing.get("ports", {}).get("ssh", "")),
            ("lan iface", d.lan_iface or "", existing.get("interfaces", {}).get("lan", "")),
            ("wan iface", d.wan_iface or "", existing.get("interfaces", {}).get("wan", "")),
            ("lan cidr", d.lan_cidr or "", existing.get("network", {}).get("lan_cidr", "")),
            ("lan ip", d.lan_ip or "", existing.get("network", {}).get("lan_ip", "")),
            ("gateway", d.gateway or "", existing.get("network", {}).get("gateway", "")),
        ]
        mismatch = [(lbl, det, cur) for lbl, det, cur in rows if cur and det and cur != det]
        if not mismatch:
            self.out("  bootstrap diff: detection agrees with the current machine.conf on key fields.")
            return
        self.out("  bootstrap diff — current machine.conf DISAGREES with the live system:")
        for lbl, det, cur in mismatch:
            self.out(f"    {lbl}: conf={cur}  detected={det}")
        self.out("  (a wrong ssh port is the usual lockout cause; the wizard will write the "
                 "detected values.)")

    def _confirm_step(self, config: dict, mode: str, profile: str) -> bool:
        """C1: show what will be written/installed and ask to proceed. Returns True to go ahead.
        Dry-run writes nothing (just preview the summary → True); non-interactive can't answer a
        prompt, so it proceeds (the operator opted into unattended). Interactive default is N —
        an explicit yes is required before the live write+install."""
        m = config.get("machine", {})
        net = config.get("network", {})
        ifc = config.get("interfaces", {})
        self.out("\n[review] About to apply this configuration:")
        self.out(f"  mode: {mode}    profile: {profile}")
        self.out(f"  layers: {m.get('layers', '')}")
        self.out(f"  ssh port: {config.get('ports', {}).get('ssh', '')}")
        if mode == "edge":
            self.out(f"  interfaces: LAN {ifc.get('lan', '') or '-'} / WAN {ifc.get('wan', '') or '-'}")
            self.out(f"  LAN: {net.get('lan_cidr', '') or '-'} "
                     f"(this box {net.get('lan_ip', '') or '-'}), gateway {net.get('gateway', '') or '-'}")
        else:
            self.out(f"  interface: {ifc.get('lan', '') or '-'}")
        self.out(f"  trusted hosts (full inbound): {net.get('trusted_hosts', '') or 'none'}")
        self.out(f"  packages: {', '.join(self._active_packages(config)) or 'none'}")
        if self.dry_run:
            self.out("  (dry-run — nothing will be written or installed.)")
            return True
        if self.assume_defaults:
            self.out("  (non-interactive — proceeding.)")
            return True
        return self._confirm("Proceed — write machine.conf and install the above?", default=False)

    def _layer_questions(self, d: detectmod.Detection, mode: str, profile: str) -> dict:
        a: dict = {}
        known_ifaces = {i.name for i in d.physical_ifaces()}

        def iface_answer(prompt: str, default: str) -> str:
            name = self._ask_validated(prompt, default, _v_iface, "a NIC name like eth0/wlan0")
            if name and known_ifaces and name not in known_ifaces and not self.assume_defaults:
                self.out(f"  note: '{name}' isn't among the detected interfaces "
                         f"({', '.join(sorted(known_ifaces)) or 'none'}) — continuing in case it "
                         "comes up later.")
            return name

        a["ssh_port"] = self._ask_validated("SSH port (the port sshd already listens on)",
                                             str(d.ssh_port), _v_port, "a port in 1–65535")
        a["trusted_hosts"] = self._ask_validated(
            "IPs allowed FULL inbound access (e.g. a desktop you admin this box from) — "
            "comma-separated, blank = none (typical)", "", _v_hosts, "comma-separated IPs/CIDRs")
        if mode == "edge":
            a["lan_iface"] = iface_answer("LAN interface (NIC facing your local network, e.g. eth0)",
                                          d.lan_iface or "")
            a["wan_iface"] = iface_answer("WAN interface (NIC facing the internet/modem, e.g. eth1)",
                                          d.wan_iface or "")
            a["lan_cidr"] = self._ask_validated("LAN subnet in CIDR (e.g. 192.168.1.0/24)",
                                                d.lan_cidr or "", _v_cidr, "a CIDR like 192.168.1.0/24")
            a["lan_ip"] = self._ask_validated("This box's LAN IP (e.g. 192.168.1.1)",
                                              d.lan_ip or "", _v_ip, "an IP like 192.168.1.1")
            a["gateway"] = self._ask_validated(
                "Upstream gateway IP — your modem/router (e.g. 192.168.1.1)",
                d.gateway or "", _v_ip, "an IP like 192.168.1.1")
        else:
            a["lan_iface"] = iface_answer(
                "Network interface this box uses (e.g. eth0 / wlan0)", d.lan_iface or "")
            if not self.assume_defaults:
                self.out("  endpoint mode — DNS/DHCP, WireGuard-server, relay and gateway "
                         "settings don't apply here and are skipped.")
        return a

    def _secrets_step(self, profile: str, answers: dict) -> list[str]:
        """Configure the L3 AI backend (provider-agnostic) + its key. Reuses an existing key on
        reinstall; requests one only on a fresh install when the chosen backend needs it. Sets
        ai.backend_cmd / ai.model into ``answers`` (-> backend.conf); writes the secret separately
        into secrets.conf + the edge-ai EnvironmentFile, NEVER into machine.conf."""
        layers = PROFILE_LAYERS.get(profile, "")
        if "l3" not in layers.split(","):
            self.out("  no AI layer selected — no API key needed.")
            return []

        # AI run cadence (the per-operator control knob, rendered into edge-ai.timer). Applies to
        # every backend incl. mock, so ask before the backend/key handling. Respect an explicit
        # --set timer_interval (already in answers); only prompt interactively.
        if "timer_interval" not in answers and not self.assume_defaults:
            answers["timer_interval"] = self._ask_timer_interval(self._current_timer_interval())

        detected = ai_backend.detect_backend(self.sys)

        # Provider menu — a reinstall pre-selects the backend already configured.
        labels = [p.label for p in ai_backend.PROVIDERS]
        default_label = (ai_backend.provider_for_cmd(detected.backend_cmd)
                         or ai_backend.PROVIDERS[0]).label
        chosen = default_label if self.assume_defaults else self._choose("AI backend", labels,
                                                                          default_label)
        provider = ai_backend.provider_by_label(chosen)

        # Resolve backend_cmd / model / key_env, and thread cmd+model into the conf.
        if provider.key == "custom":
            backend_cmd = self._ask("BACKEND_CMD (path to your analyzer / local-model executable)",
                                    detected.backend_cmd or "")
            model = self._ask("Model id (optional; blank = backend's own default)",
                              detected.model or "")
            key_env = None
            if backend_cmd and not self.assume_defaults and \
                    self._confirm("Does this backend need an API key/secret?", default=False):
                key_env = (self._ask(
                    "Env var the backend reads the secret from (e.g. ANTHROPIC_API_KEY)", "API_KEY")
                    or "API_KEY").strip()
        else:
            backend_cmd, model, key_env = provider.backend_cmd, provider.default_model, provider.key_env

        if backend_cmd:
            answers["ai_backend_cmd"] = backend_cmd
        if model:
            answers["ai_model"] = model

        # Local model / mock — no secret to handle.
        if not key_env:
            self.out(f"  backend '{provider.label}' needs no API key.")
            return []

        # Reuse on reinstall — do not re-prompt.
        if detected.key_present and detected.key_env == key_env:
            self.out(f"  reusing existing {key_env} from {detected.key_source} — not re-prompting.")
            return []

        # A key is needed and none was detected.
        if self.dry_run:
            self.out(f"  dry-run: would prompt for {key_env}, then write secrets.conf + "
                     f"{ai_backend.EDGE_AI_ENV} (chmod 600).")
            return [f"L3 selected: setup would capture {key_env} into secrets.conf and render the "
                    "edge-ai EnvironmentFile."]
        if self.assume_defaults:
            self.out(f"  non-interactive: {key_env} not supplied — add it to secrets.conf before "
                     "enabling L3.")
            return [f"{key_env} not captured (non-interactive); set it in secrets.conf manually."]

        key = self.secret_inp(f"  {key_env} (input hidden, blank = skip): ").strip()
        if not key:
            self.out("  no key entered — set it in secrets.conf before enabling L3.")
            return [f"{key_env} left unset; add it to secrets.conf manually."]

        written = ai_backend.apply_secret(self.sys, secrets_path=ai_backend.DEFAULT_SECRETS_FILE,
                                          key_env=key_env, key_value=key)
        for w in written:
            self.out(f"  wrote {w} (chmod 600)")
        return []

    def _alerts_step(self, profile: str) -> list[str]:
        """Configure the L6 notify-alert sinks (operator/secret: ntfy topic, email, internal URL) into
        /etc/bastion/notify-alert.conf (chmod 600) — the same out-of-machine.conf pattern as the AI
        key. Reuses an existing conf on reinstall; skips writing when no real sink is supplied
        (notify-alert already no-ops on an absent conf)."""
        if "l6" not in PROFILE_LAYERS.get(profile, "").split(","):
            return []
        if alertsmod.conf_present(self.sys):
            self.out(f"  reusing existing {alertsmod.ALERT_CONF} — not re-prompting.")
            return []
        if self.dry_run:
            self.out(f"  dry-run: would prompt for alert sinks, then write {alertsmod.ALERT_CONF} "
                     "(chmod 600).")
            return [f"L6 selected: setup would capture alert sinks into {alertsmod.ALERT_CONF}."]
        if self.assume_defaults:
            self.out(f"  non-interactive: no alert sinks captured — edit {alertsmod.ALERT_CONF} to "
                     "enable alerts.")
            return [f"alert sinks not configured (non-interactive); edit {alertsmod.ALERT_CONF}."]

        self.out("  alert destinations (all optional — external sinks get a degraded-only template):")
        values: dict[str, str] = {}
        for f in alertsmod.FIELDS:
            # Only ask for the dependent fields once their primary value is set.
            if f.key == "NTFY_SERVER" and not values.get("NTFY_TOPIC"):
                continue
            if f.key == "INTERNAL_NTFY_AUTH" and not values.get("INTERNAL_NTFY_URL"):
                continue
            if f.secret:
                values[f.key] = self.secret_inp(f"  {f.prompt} (input hidden): ").strip()
            else:
                values[f.key] = self._ask(f.prompt, f.default)

        if not alertsmod.has_any_sink(values):
            self.out(f"  no alert sinks entered — leaving {alertsmod.ALERT_CONF} absent (alerts "
                     "no-op; configure later by editing it).")
            return []
        path = alertsmod.apply_alerts(self.sys, values)
        self.out(f"  wrote {path} (chmod 600)")
        return []

    def _install_surface(self, config: dict, mode: str) -> list[str]:
        """The files the SELECTED layers actually install (so an endpoint preview never lists
        edge-only configs like dnsmasq). Derived from the SAME active-layer ownership that
        `bastion generate` now uses (cli.active_template_rels + manifest_dest), so the preview and
        the real write agree exactly."""
        from .. import cli
        active_rels = cli.active_template_rels(config, mode)
        dests: list[str] = []
        for rel in sorted(active_rels):
            dest = cli.manifest_dest(Path(rel), mode, Path("/"))
            if dest is not None:
                dests.append(str(dest))
        dests += ["/etc/bastion/machine.env", "/etc/bastion/machine.conf"]
        # de-dup, preserve order
        seen, out = set(), []
        for d in dests:
            if d not in seen:
                seen.add(d); out.append(d)
        return out

    def _generate_preview(self, config: dict, mode: str) -> tuple[list[str], list[str]]:
        from .. import cli   # lazy: cli imports this module (setup), avoid an import cycle
        # Validation: EVERY template must resolve against the built conf (the gate's "correct
        # template diffs" — an unresolved placeholder means machine.conf is incomplete).
        templates_dir = cli.find_templates_dir(None)
        problems = {}
        for rel, abs_path in cli.iter_templates(templates_dir):
            missing = templates.check_file(abs_path, config)
            if missing:
                problems[rel.as_posix()] = missing
        notes = []
        if problems:
            self.out("  UNRESOLVED placeholders (machine.conf incomplete):")
            for name, miss in sorted(problems.items()):
                self.out(f"    {name}: {', '.join(miss)}")
            notes.append(f"{len(problems)} template(s) had unresolved placeholders.")
        else:
            self.out("  all templates resolve against the proposed machine.conf.")

        would_write = self._install_surface(config, mode)
        self.out(f"  would write {len(would_write)} file(s) for layers "
                 f"[{config['machine'].get('layers', '')}] (mode={mode}):")
        for w in would_write:
            self.out(f"    {w}")
        return would_write, notes

    def _generate_apply(self, config: dict, mode: str) -> tuple[list[str], list[str]]:
        """Live step 6 (§10): persist the built machine.conf, then render the active-layer
        templates + machine.env. The conf round-trips through state.write_conf -> generate's
        load_conf, so a written conf that fails to resolve is caught here, before any install."""
        from .. import cli
        import argparse
        notes: list[str] = []

        # Validate in-memory before touching disk — an unresolved placeholder means the answers
        # were incomplete; abort rather than write a half-resolved conf.
        templates_dir = cli.find_templates_dir(None)
        problems = {rel.as_posix(): miss for rel, abs_path in cli.iter_templates(templates_dir)
                    if (miss := templates.check_file(abs_path, config))}
        if problems:
            self.out("  ABORT — unresolved placeholders (machine.conf incomplete):")
            for name, miss in sorted(problems.items()):
                self.out(f"    {name}: {', '.join(miss)}")
            return [], [f"generate aborted: {len(problems)} template(s) unresolved; nothing written."]

        # Persist machine.conf (root-prefixed so --root staging stays contained).
        conf_path = self.sys.path("/etc/bastion/machine.conf")
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        state.write_conf(config, conf_path)
        self.out(f"  wrote {conf_path}")

        # Render templates + machine.env via the same code path as `bastion generate` (reads the
        # conf we just wrote — so the write is exercised end-to-end). out_base = root for staging.
        out_base = None if self.sys.root == Path("/") else str(self.sys.root)
        ns = argparse.Namespace(conf=str(conf_path), templates=None, out=out_base, check=False)
        rc = cli.cmd_generate(ns)
        if rc != 0:
            notes.append("generate reported unresolved templates against the written conf.")

        written = self._install_surface(config, mode)
        return written, notes

    def _active_layer_ids(self, config: dict) -> list[str]:
        """Active layer ids in install/registry order (l0 first)."""
        from .. import layers as layermod
        declared = [l.strip() for l in config.get("machine", {}).get("layers", "").split(",")
                    if l.strip()]
        order = list(layermod.REGISTRY)
        return [lid for lid in order if lid in declared] if declared else order

    def _active_packages(self, config: dict) -> list[str]:
        """De-duplicated package set required by the active layers, in layer order."""
        return self._packages_for_layers(self._active_layer_ids(config))

    @staticmethod
    def _packages_for_layers(layer_ids) -> list[str]:
        """De-duplicated package set declared by the given layer ids, in the given order."""
        from .. import layers as layermod
        wanted: list[str] = []
        for lid in layer_ids:
            layer = layermod.get(lid)
            if layer:
                wanted += list(getattr(layer, "packages", ()))
        seen, pkgs = set(), []
        for p in wanted:
            if p not in seen:
                seen.add(p); pkgs.append(p)
        return pkgs

    def _install_step(self, config: dict, mode: str) -> tuple[list[str], list[str]]:
        """§10 step 7. Live root install → batch-install packages, then run each active layer's
        install(); dry-run / --root staging → preview the package plan only (non-mutating)."""
        from ..layers import base as layerbase
        # A6: probe the LIVE host's firewall even for a staged/dry preview — a ufw/firewalld
        # conflict is a property of the host the ruleset eventually loads on, not of the staging
        # root. is_live is False under --root, but `systemctl is-active` still queries the real
        # host, so the preview now warns instead of looking clean and aborting only at the real apply.
        fw = layerbase.blocking_conflicting_firewall(self.sys)

        if self.dry_run or not self.sys.is_live:
            notes = []
            if fw:
                self.out(f"  NOTE: {fw} is active on this host — bastion's ruleset would flush it. "
                         f"Disable it (`sudo systemctl disable --now {fw}`) before a live install.")
                notes.append(f"{fw} active — disable before a live install (its rules would be flushed).")
            return self._package_plan(config, mode), notes

        # SAFETY: refuse the live install while another OS firewall governs — bastion's L0 ruleset
        # begins with `flush ruleset` and would wipe it. Abort step 7 with the fix; nothing live runs.
        if fw:
            self.out(f"  ABORT — {layerbase.firewall_conflict_message(fw)}")
            return [], [f"install skipped: {fw} is active and would be flushed by bastion's ruleset "
                        f"— disable it (`sudo systemctl disable --now {fw}`) and re-run `sudo bastion setup`."]

        from .. import cli
        from .. import layers as layermod
        notes: list[str] = []
        ctx = layerbase.Context(system=self.sys, config=config,
                                templates_dir=cli.find_templates_dir(None),
                                scripts_dir=cli.find_scripts_dir(None))

        # 7a. All active-layer packages up front (idempotent --needed); unresolvable AUR-only deps
        #     are surfaced as a prerequisite, non-fatal — the layer's own install() then warns.
        pkgs = self._batch_install_packages(config)

        # 7b. WireGuard configs must exist BEFORE L5.install() brings the tunnels up (it enables
        #     wg-quick@<iface> only when the conf is present). Needs `wg`, just installed in 7a.
        notes += self._wg_configure(config)

        # 7c. B1 — install as a transaction. Snapshot BEFORE touching the firewall so a failed
        #     core (L0) install can auto-roll-back. L0 is the drop-policy ruleset — the one layer
        #     whose half-applied state can lock the box out — so its failure ABORTS the whole
        #     install (and rolls back if we snapped). A LATER layer's failure leaves the firewall
        #     core up and is reported as retryable, not fatal.
        snapped = self._pre_install_snapshot(ctx)
        for lid in self._active_layer_ids(config):
            layer = layermod.get(lid)
            if layer is None:
                continue
            self.out(f"  installing {lid} ({layer.name})...")
            try:
                layer.install(ctx)
            except Exception as exc:                       # noqa: BLE001
                if lid == "l0":
                    self.out(f"  ! l0 (firewall core) install FAILED: {exc}")
                    notes.append(f"l0 install failed: {exc}; aborted before later layers.")
                    if snapped:
                        notes += self._auto_rollback(ctx, "setup-l0-failure")
                    else:
                        notes.append("no pre-install snapshot was captured — restore the network "
                                     "manually if egress is broken.")
                    return pkgs, notes
                self.out(f"  ! {lid} install error: {exc} — firewall core is up; retry with "
                         f"`sudo bastion layer install {lid}`")
                notes.append(f"{lid} install raised: {exc} (retryable — core firewall is up).")

        # 7d. ZeroTier join AFTER L5 started zerotier-one (the cli needs the daemon running).
        notes += self._zt_join_step(config)
        return pkgs, notes

    def _pre_install_snapshot(self, ctx) -> bool:
        """B1 rollback point: capture a pre-install network snapshot with the net-snapshot script
        from scripts_dir (it isn't in sbin yet). Best-effort; True only if it actually ran. Needs
        machine.env, which step 6 already wrote."""
        script = ctx.scripts_dir / "net-snapshot"
        if not script.exists():
            return False
        try:
            if self.sys.run("bash", str(script), capture=False).returncode == 0:
                self.out("  captured a pre-install snapshot (rollback point).")
                return True
        except Exception as exc:                           # noqa: BLE001
            self.out(f"  pre-install snapshot skipped ({exc}).")
        return False

    def _auto_rollback(self, ctx, reason: str) -> list[str]:
        """Restore the pre-install snapshot via the net-rollback script (also from scripts_dir)."""
        script = ctx.scripts_dir / "net-rollback"
        if not script.exists():
            return ["auto-rollback unavailable (net-rollback script missing) — restore manually."]
        self.out("  auto-rolling back to the pre-install snapshot...")
        rc = self.sys.run("bash", str(script), reason, capture=False).returncode
        if rc == 0:
            return ["auto-rolled back to the pre-install network snapshot after the l0 failure."]
        return ["auto-rollback reported errors — verify network state manually."]

    def _wg_configure(self, config: dict) -> list[str]:
        """Generate WireGuard keypairs + write complete /etc/wireguard/<iface>.conf from operator-
        supplied peer details, for the wg interfaces declared in machine.conf. Runs before
        L5.install() so the tunnels it brings up have configs. Reuses an existing config (NEVER
        clobbers a key); requires an interactive session (peer key/endpoint can't be auto-supplied).
        """
        if "l5" not in self._active_layer_ids(config):
            return []
        ifaces = config.get("interfaces", {})
        # (iface, role): a server LISTENS (peers dial in); a client/vps DIALS OUT to a relay.
        specs = [(ifaces.get("wg_server_iface", ""), "server"),
                 (ifaces.get("wg_vps_iface", ""), "client")]
        specs = [(name, role) for name, role in specs if name]
        if not specs:
            return []
        if self.assume_defaults:
            self.out("  WireGuard: non-interactive — peer details can't be auto-supplied; configure "
                     "/etc/wireguard/*.conf manually before enabling the tunnels.")
            return ["WireGuard configs not generated (non-interactive)."]

        notes: list[str] = []
        for iface, role in specs:
            if vpn_setup.wg_conf_present(self.sys, iface):
                self.out(f"  WireGuard {iface}: config already present — reusing (key untouched).")
                continue
            kp = vpn_setup.wg_keypair(self.sys)
            if kp is None:
                self.out(f"  WireGuard {iface}: `wg` unavailable — skipping (install "
                         "wireguard-tools, then re-run `bastion setup`).")
                notes.append(f"wg keypair for {iface} not generated (wg tool unavailable).")
                continue
            private, public = kp
            self.out(f"  WireGuard {iface} ({role}) — your public key (share with the peer):")
            self.out(f"    {public}")

            if role == "server":
                addr_default = vpn_setup.default_server_address(
                    config.get("network", {}).get("wg_server_cidr", ""))
                port_default, allowed_default = "51820", ""
            else:
                addr_default, port_default, allowed_default = "", "", "0.0.0.0/0"

            address = self._ask(f"{iface} Address (this node's tunnel IP/CIDR)", addr_default)
            listen_port = self._ask(
                f"{iface} ListenPort — UDP port this end listens on (blank = none, for a dial-out client)",
                port_default)
            mtu = self._ask(f"{iface} MTU (blank = auto; lower e.g. 1340 for CGNAT/PPPoE/nested tunnels)", "")
            peer_pub = self._ask(f"{iface} peer public key (the OTHER end's WireGuard public key)", "")
            if not peer_pub:
                self.out(f"  no peer key entered — skipping {iface} (complete its conf manually).")
                notes.append(f"{iface} left unconfigured (no peer public key).")
                continue
            peer_endpoint = self._ask(f"{iface} peer Endpoint host:port (blank = peer dials in)", "")
            allowed_ips = self._ask(
                f"{iface} AllowedIPs — subnets routed through this tunnel", allowed_default)
            if not address or not allowed_ips:
                self.out(f"  {iface}: Address and AllowedIPs are required — skipping.")
                notes.append(f"{iface} left unconfigured (missing Address/AllowedIPs).")
                continue
            conf = vpn_setup.WgConf(private_key=private, address=address, peer_public_key=peer_pub,
                                    allowed_ips=allowed_ips, listen_port=listen_port,
                                    mtu=mtu, peer_endpoint=peer_endpoint)
            path = vpn_setup.write_wg_conf(self.sys, iface, conf)
            self.out(f"  wrote {path} (chmod 600)")
        return notes

    def _zt_join_step(self, config: dict) -> list[str]:
        """Join the ZeroTier network after L5 started zerotier-one. The network ID is operator secret —
        prompted, never committed; ZeroTier persists the membership in its own state."""
        if "l5" not in self._active_layer_ids(config):
            return []
        if not config.get("interfaces", {}).get("zt_iface", ""):
            return []
        if self.assume_defaults:
            self.out("  ZeroTier: non-interactive — join with `zerotier-cli join <network-id>` "
                     "after setup.")
            return []
        net = self._ask(
            "ZeroTier network ID to join — 16-char ID from my.zerotier.com (blank = skip)", "").strip()
        if not net:
            self.out("  no ZeroTier network ID — skipping join.")
            return []
        res = vpn_setup.zt_join(self.sys, net)
        if res.returncode == 0:
            self.out(f"  joined ZeroTier network {net} (authorize this node in your ZeroTier "
                     "console).")
            return []
        self.out("  `zerotier-cli join` failed — ensure zerotier-one is running, then join "
                 "manually.")
        return ["ZeroTier join failed; run `zerotier-cli join <network-id>` manually."]

    def _no_manager_msg(self, pkgs: list[str]) -> str:
        """Message when no supported package manager resolved. Names a detected-but-unsupported
        manager (e.g. openSUSE's zypper) explicitly so the operator knows it's unimplemented, not
        absent. Supported managers today: pacman (Arch), apt (Debian/Ubuntu), dnf (Fedora/RHEL)."""
        unsupported = pkgmod.unsupported_present(self.sys)
        if unsupported:
            return (f"{unsupported} is detected but not yet supported by bastion "
                    "(supported: Arch/pacman, Debian-Ubuntu/apt, Fedora-RHEL/dnf) — install these "
                    f"manually, then re-run: {', '.join(pkgs)}")
        return f"no supported package manager — ensure installed: {', '.join(pkgs)}"

    def _batch_install_packages(self, config: dict) -> list[str]:
        mgr = pkgmod.detect_manager(self.sys, config.get("machine", {}).get("distro"))
        pkgs = self._active_packages(config)
        if not pkgs:
            self.out("  no packages required by the selected layers.")
            return pkgs
        if mgr is None:
            self.out("  " + self._no_manager_msg(pkgs))
            return pkgs
        mgr.refresh(self.sys)        # sync the package DB once before the batch (fresh apt cache)
        res = mgr.install(self.sys, pkgs)
        if not res.command and not res.unavailable:
            self.out(f"  packages already present ({len(pkgs)}).")
        elif res.ran:
            ok = "OK" if res.returncode == 0 else f"FAILED (rc={res.returncode})"
            self.out(f"  installed via {mgr.name} [{ok}]: {' '.join(res.command)}")
        elif res.command:
            self.out(f"  would install via {mgr.name}: {' '.join(res.command)}")
        if res.unavailable:
            self.out(f"  ! {mgr.unavailable_hint(res.unavailable)}")
        return pkgs

    def _verify_step(self, config: dict, mode: str) -> list[str]:
        """§10 step 8. Live → run `bastion check` (read-only flowcheck) and, on failure, point at
        the rollback path. Dry-run / staged → print the operator's next steps."""
        if self.dry_run:
            self.out("  dry-run: skipping live install + `bastion check`.")
            return []
        if not self.sys.is_live:
            self.out("  staged (--root): configs written; run the layer installs + `bastion check` "
                     "on the live host.")
            return []
        sbin = "/usr/local/sbin"
        if not self.sys.exists(f"{sbin}/flowcheck"):
            self.out("  flowcheck (L6) not installed — skipping automatic check.")
            return ["bastion check skipped: flowcheck (L6) not installed."]
        self.out("  running bastion check...")
        rc = self.sys.run(str(self.sys.path(f"{sbin}/flowcheck")), capture=False).returncode
        if rc == 0:
            self.out("  bastion check: all flows pass.")
            return []
        self.out("  bastion check: one or more flows FAILED.")
        if self.sys.exists(f"{sbin}/net-rollback"):
            self.out("  to restore the pre-change network state: sudo net-rollback")
        return ["bastion check reported failures; verify egress/DNS before relying on the firewall."]

    def _package_plan(self, config: dict, mode: str) -> list[str]:
        """Preview the package set for dry-run / --root staging (a live root install installs them
        for real via `_install_step`/`_batch_install_packages`, so this path never mutates)."""
        mgr = pkgmod.detect_manager(self.sys, config.get("machine", {}).get("distro"))
        pkgs = self._active_packages(config)
        if mgr is None:
            self.out("  " + self._no_manager_msg(pkgs))
            return pkgs
        self.out(f"  package manager: {mgr.name}")
        self.out(f"  needed by selected layers: {', '.join(pkgs) or 'none'}")
        self.out(f"  install command (preview): "
                 f"{' '.join(mgr.install_command(pkgs)) if pkgs else '(nothing to install)'}")
        return pkgs
