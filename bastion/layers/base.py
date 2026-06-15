"""Layer base class — the uniform unit every bastion layer implements.

Each layer declares what it owns (packages, scripts, templates→destinations, systemd units)
and implements install / uninstall / status / health_check. The CLI drives layers through
this interface; nothing layer-specific leaks into the CLI.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path

from ..system import System
from .. import templates as tmpl


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

    # --- the interface every layer implements -----------------------------
    @abc.abstractmethod
    def install(self, ctx: Context) -> None: ...

    @abc.abstractmethod
    def uninstall(self, ctx: Context) -> None: ...

    @abc.abstractmethod
    def status(self, ctx: Context) -> LayerStatus: ...

    @abc.abstractmethod
    def health_check(self, ctx: Context) -> list[HealthCheck]: ...
