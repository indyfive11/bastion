"""Layer base class — the uniform unit every bastion layer implements.

Each layer declares what it owns (packages, scripts, templates→destinations, systemd units)
and implements install / uninstall / status / health_check. The CLI drives layers through
this interface; nothing layer-specific leaks into the CLI.
"""
from __future__ import annotations

import abc
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


def atomic_write_text(out: Path, text: str) -> None:
    """Write ``text`` to ``out`` atomically: render to a temp file in the same directory,
    fsync it, then ``os.replace`` into place. A crash or power-loss mid-write can then never
    leave a truncated file on disk — the destination is either the old contents or the complete
    new contents. Critical for /etc/nftables.conf, which the pinned nftables.service loads
    verbatim at boot: a half-written ruleset is a fail-open firewall. Mirrors state.write_conf."""
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    try:
        with open(tmp, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, out)
    finally:
        if tmp.exists():
            tmp.unlink()

from ..system import System
from .. import templates as tmpl


# Firewalls that manage the same kernel netfilter hooks bastion does. bastion's nft ruleset begins
# with `flush ruleset`, so loading it while one of these is ACTIVE would wipe that firewall's rules
# and the two would then fight — the live ruleset load (L0) must gate on this.
CONFLICTING_FIREWALLS = ("ufw", "firewalld")
FIREWALL_TAKEOVER_ENV = "BASTION_ALLOW_FIREWALL_TAKEOVER"
NFTABLES_LOADER_UNIT = "nftables.service"


def firewall_conflict_message(fw: str) -> str:
    return (f"{fw} is active. bastion's ruleset begins with `flush ruleset`, which would wipe "
            f"{fw}'s rules — the two firewalls would then fight. Disable it first:\n"
            f"    sudo systemctl disable --now {fw}\n"
            f"  then re-run. To let bastion take over anyway, set {FIREWALL_TAKEOVER_ENV}=1.")


def firewall_coexist_message(fw: str) -> str:
    return (f"l0: WARNING — {fw} is active. bastion is in COOPERATIVE scope, so it manages only "
            f"its own nft table and will NOT flush {fw}'s rules — but two active input-hook filters "
            f"at the same priority is ambiguous. Consider `sudo systemctl disable --now {fw}`.")


class FirewallConflict(Exception):
    """A conflicting OS firewall (ufw/firewalld) is active and bastion would otherwise flush it.
    The active firewall's name is in ``.firewall``."""
    def __init__(self, firewall: str):
        self.firewall = firewall
        super().__init__(firewall_conflict_message(firewall))


def _firewall_enforcing(system: System, fw: str) -> bool:
    """Whether ``fw`` is actually ENFORCING rules, not merely loaded. ufw's systemd unit is a
    RemainAfterExit oneshot that stays ``active`` even after ``ufw disable`` — so ``unit_active``
    alone over-reports a conflict: an inactive ufw owns no table, and flushing it removes nothing.
    Ask the tool itself (``ufw status`` / ``firewall-cmd --state``). Fail-soft: if status can't be
    read (tool absent, or non-root in a staged preview) assume enforcing, so we never silently skip
    a real conflict — the conservative side is to keep warning/blocking, not to proceed blind."""
    if fw == "ufw":
        res = system.run("ufw", "status")
        if res.returncode == 0:
            return "Status: active" in (res.stdout or "")
        return True
    if fw == "firewalld":
        res = system.run("firewall-cmd", "--state")
        if res.returncode == 0:
            return "running" in (res.stdout or "").lower()
        return True
    return True


def active_conflicting_firewall(system: System) -> str | None:
    """Name of a conflicting OS firewall (ufw/firewalld) currently ENFORCING, else None. Meaningful
    only on a live host — a staged ``--root`` install loads no ruleset. A firewall whose unit is
    loaded but which enforces nothing (e.g. ``ufw disable`` left the oneshot unit ``active``) is not
    a conflict: it owns no table, so bastion's ruleset has nothing of its to flush."""
    for fw in CONFLICTING_FIREWALLS:
        if system.unit_active(fw) and _firewall_enforcing(system, fw):
            return fw
    return None


# nft tables bastion itself owns. Anything else live in `nft list tables` belongs to a co-resident
# manager (libvirt/Docker/Kubernetes-CNI/Tailscale/...) that an `exclusive` `flush ruleset` would wipe.
BASTION_NFT_TABLES = {("inet", "edge"), ("inet", "bastion"), ("ip", "edge_nat"),
                      ("inet", "bastion_recovery")}


def live_foreign_nft_tables(system: System) -> list[tuple[str, str]]:
    """Live `nft list tables` minus bastion's own — the co-resident tables an `exclusive`
    `flush ruleset` would delete. Empty when nft can't be read (e.g. non-root) or nothing is foreign;
    fail-soft, never raises (a detection failure must not block an install)."""
    try:
        res = system.run("nft", "list", "tables")
    except Exception:
        return []
    if getattr(res, "returncode", 1) != 0:
        return []
    foreign = []
    for line in (res.stdout or "").splitlines():
        m = re.match(r"\s*table\s+(\S+)\s+(\S+)", line)
        if m and (m.group(1), m.group(2)) not in BASTION_NFT_TABLES:
            foreign.append((m.group(1), m.group(2)))
    return foreign


def warn_if_exclusive_flush(system: System, scope: str, out=print) -> list[tuple[str, str]]:
    """Hard-warn before an `exclusive`-scope apply runs `flush ruleset` and wipes co-resident nft
    tables (the general safety net — fires for ANY foreign table, whatever owns it). Returns the
    foreign tables found (so callers/tests can act on them). No-op in `cooperative` scope (it never
    flushes) or when nothing foreign is present."""
    if scope == "cooperative":
        return []
    foreign = live_foreign_nft_tables(system)
    if not foreign:
        return []
    names = ", ".join(f"{fam} {n}" for fam, n in foreign)
    out("  !!! WARNING — exclusive firewall_scope runs `flush ruleset`, which DELETES every")
    out(f"  !!! nftables table on this host, including these co-resident tables: {names}")
    out("  !!! If a hypervisor / container engine / mesh VPN (libvirt, Docker, Kubernetes/CNI,")
    out("  !!! Tailscale, ...) owns them, this can take the machine's networking DOWN.")
    out("  !!! To coexist instead, set cooperative scope BEFORE applying:")
    out("  !!!     bastion config set machine.firewall_scope cooperative --advanced")
    return foreign


def warn_if_foreign_nftables_conf(system: System, mode: str, out=print) -> str | None:
    """If an existing ``/etc/nftables.conf`` is loaded by an enabled/active ``nftables.service`` but
    is NOT a bastion ruleset, save a recovery copy to ``/etc/nftables.conf.pre-bastion`` and warn
    loudly before L0 overwrites it — so a hand-rolled nft firewall the operator relies on is never
    silently replaced with no way back. Returns the backup path, or None when there's nothing foreign
    to guard: the file is absent, the loader unit is inert (e.g. ufw-via-iptables boxes that don't use
    it), bastion already owns the file (a reinstall), or this is a staged ``--root``/non-live run.
    Fail-soft — a probe failure must never block an install."""
    if not getattr(system, "is_live", False) or not system.exists("/etc/nftables.conf"):
        return None
    if not (system.unit_enabled(NFTABLES_LOADER_UNIT) or system.unit_active(NFTABLES_LOADER_UNIT)):
        return None
    try:
        body = system.path("/etc/nftables.conf").read_text(errors="replace")
    except OSError:
        return None
    if "table inet edge" in body or "table inet bastion" in body:
        return None   # already bastion's ruleset -> reinstall, safe to overwrite
    bak = system.path("/etc/nftables.conf.pre-bastion")
    try:
        if not bak.exists():
            bak.write_text(body)
    except OSError:
        pass
    out("  !!! WARNING — /etc/nftables.conf already exists, is loaded by an enabled/active")
    out("  !!! nftables.service, and is NOT a bastion ruleset. L0 is about to overwrite it.")
    out("  !!! A recovery copy was saved to /etc/nftables.conf.pre-bastion — if a hand-rolled")
    out("  !!! nftables firewall owns this file, restore from that copy before re-running L0.")
    return "/etc/nftables.conf.pre-bastion"


def blocking_conflicting_firewall(system: System, scope: str = "exclusive") -> str | None:
    """The active conflicting firewall that should BLOCK a live ruleset load, or None.

    None when: none is active; the operator set ``BASTION_ALLOW_FIREWALL_TAKEOVER=1``; OR the
    firewall_scope is ``cooperative`` — in which case bastion no longer flushes the ruleset (the
    rendered preamble is a table-scoped reset, see ``templates._firewall_preamble``), so it won't
    wipe the other firewall's tables and need not block. Cooperative still PRINTS a coexist warning
    (two active input filters at the same priority is ambiguous); it just stops aborting."""
    if os.environ.get(FIREWALL_TAKEOVER_ENV):
        return None
    fw = active_conflicting_firewall(system)
    if fw and scope == "cooperative":
        print(firewall_coexist_message(fw))
        return None
    return fw


@dataclass
class Context:
    """Execution context handed to every layer method."""
    system: System
    config: dict
    templates_dir: Path
    scripts_dir: Path
    sbin_dir: str = "/usr/local/sbin"

    @property
    def mode(self) -> str:
        # "unset" when no machine.conf has been written yet (a fresh box) — never silently claim
        # "edge", which misleads `status`/`doctor` into reporting a mode the operator never chose.
        return self.config.get("machine", {}).get("mode", "unset")


@dataclass
class HealthCheck:
    name: str
    ok: bool
    detail: str = ""
    unknown: bool = False   # could not be determined (e.g. nft query needs root) — not a failure


def nft_table_health(sys: System, name: str, family: str, table: str) -> HealthCheck:
    """Health check for a loaded nft table, honest about non-root: on a live host without
    root, `nft list` is denied and would read as a false FAIL — report it as unknown instead."""
    if sys.is_live and not sys.is_root:
        return HealthCheck(name, False, "needs root to verify", unknown=True)
    return HealthCheck(name, sys.nft_table_exists(family, table))


def nft_set_health(sys: System, name: str, family: str, table: str, set_name: str) -> HealthCheck:
    """Like nft_table_health for an nft set within a table (see its note on non-root)."""
    if sys.is_live and not sys.is_root:
        return HealthCheck(name, False, "needs root to verify", unknown=True)
    return HealthCheck(name, sys.nft_set_exists(family, table, set_name))


@dataclass
class LayerStatus:
    name: str          # short id, e.g. "l0"
    title: str         # display name, e.g. "core"
    installed: bool
    active: bool
    detail: str = ""
    checks: list[HealthCheck] = field(default_factory=list)


class Layer(abc.ABC):
    # Declarative metadata — subclasses override.
    name: str = ""
    title: str = ""
    description: str = ""
    prerequisites: tuple[str, ...] = ()
    packages: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()          # script basenames installed to sbin
    template_dests: tuple[tuple[str, str], ...] = ()   # (template relpath, dest path)
    units: tuple[str, ...] = ()            # systemd unit filenames

    def owned_templates(self, mode: str) -> set[str]:
        """Template relpaths this layer is responsible for (config files + its systemd units).

        The single source of truth for `bastion generate` (which writes only active-layer
        templates) and the setup-wizard preview. Defaults to the declared template_dests + units;
        layers that render mode-dependent configs in install() (L0's nft ruleset) override to add
        them so generate and install never disagree.
        """
        rels = {t for t, _dest in self.template_dests}
        rels |= {f"systemd/{u}" for u in self.units}
        return rels

    # --- helpers usable by subclasses -------------------------------------
    def render_to(self, ctx: Context, template_rel: str, dest: str) -> None:
        """Render a template against machine.conf and write it under the system root."""
        src = ctx.templates_dir / template_rel
        out = ctx.system.path(dest)
        atomic_write_text(out, tmpl.render_file(src, ctx.config))

    def install_script(self, ctx: Context, name: str) -> None:
        src = ctx.scripts_dir / name
        out = ctx.system.path(f"{ctx.sbin_dir}/{name}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(src.read_text())
        out.chmod(0o755)

    def install_unit(self, ctx: Context, name: str) -> None:
        src = ctx.templates_dir / "systemd" / name
        out = ctx.system.path(f"/etc/systemd/system/{name}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(tmpl.render_file(src, ctx.config))

    def install_logrotate(self, ctx: Context, name: str) -> None:
        """Install a static logrotate drop-in from templates/logrotate/<name> to
        /etc/logrotate.d/<name> — caps bastion's append-only state (B5). Idempotent overwrite;
        these are plain config (no placeholders), so a verbatim copy, not a render."""
        src = ctx.templates_dir / "logrotate" / name
        out = ctx.system.path(f"/etc/logrotate.d/{name}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(src.read_text())

    # --- the interface every layer implements -----------------------------
    @abc.abstractmethod
    def install(self, ctx: Context) -> None: ...

    @abc.abstractmethod
    def uninstall(self, ctx: Context) -> None: ...

    @abc.abstractmethod
    def status(self, ctx: Context) -> LayerStatus: ...

    @abc.abstractmethod
    def health_check(self, ctx: Context) -> list[HealthCheck]: ...
