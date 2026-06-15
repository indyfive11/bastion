"""Layer base class — the uniform unit every bastion layer implements.

Each layer declares what it owns (packages, scripts, templates→destinations, systemd units)
and implements install / uninstall / status / health_check. The CLI drives layers through
this interface; nothing layer-specific leaks into the CLI.
"""
from __future__ import annotations

import abc
import os
from dataclasses import dataclass, field
from pathlib import Path

from ..system import System
from .. import templates as tmpl


# Firewalls that manage the same kernel netfilter hooks bastion does. bastion's nft ruleset begins
# with `flush ruleset`, so loading it while one of these is ACTIVE would wipe that firewall's rules
# and the two would then fight — the live ruleset load (L0) must gate on this.
CONFLICTING_FIREWALLS = ("ufw", "firewalld")
FIREWALL_TAKEOVER_ENV = "BASTION_ALLOW_FIREWALL_TAKEOVER"


def firewall_conflict_message(fw: str) -> str:
    return (f"{fw} is active. bastion's ruleset begins with `flush ruleset`, which would wipe "
            f"{fw}'s rules — the two firewalls would then fight. Disable it first:\n"
            f"    sudo systemctl disable --now {fw}\n"
            f"  then re-run. To let bastion take over anyway, set {FIREWALL_TAKEOVER_ENV}=1.")


class FirewallConflict(Exception):
    """A conflicting OS firewall (ufw/firewalld) is active and bastion would otherwise flush it.
    The active firewall's name is in ``.firewall``."""
    def __init__(self, firewall: str):
        self.firewall = firewall
        super().__init__(firewall_conflict_message(firewall))


def active_conflicting_firewall(system: System) -> str | None:
    """Name of a conflicting OS firewall (ufw/firewalld) currently active, else None. Meaningful
    only on a live host — a staged ``--root`` install loads no ruleset."""
    for fw in CONFLICTING_FIREWALLS:
        if system.unit_active(fw):
            return fw
    return None


def blocking_conflicting_firewall(system: System) -> str | None:
    """The active conflicting firewall that should BLOCK a live ruleset load, or None — None when
    none is active OR the operator set ``BASTION_ALLOW_FIREWALL_TAKEOVER=1`` to override the guard."""
    if os.environ.get(FIREWALL_TAKEOVER_ENV):
        return None
    return active_conflicting_firewall(system)


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
        return self.config.get("machine", {}).get("mode", "edge")


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
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(tmpl.render_file(src, ctx.config))

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
