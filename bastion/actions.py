"""UI-agnostic action layer — the command surface shared by `bastion tui` and (later) the GUI.

Every operation the CLI exposes is declared here as an :class:`Action` with a **risk tier** that
drives confirmation gating, so a front-end never has to hard-code which operations are dangerous.
Actions execute by invoking the real ``bastion`` CLI as a subprocess: that keeps a single source
of truth for all guard logic (prerequisite blocks, firewall-conflict refusal, root checks, the AI
kill-switch semantics) instead of re-implementing it per front-end, and gives a future GUI the same
clean "build argv → run → (rc, output)" contract.

Risk tiers:
  * ``READ``        — no mutation; run and show output, no confirmation.
  * ``CAUTION``     — mutates state; a single yes/no confirmation.
  * ``DESTRUCTIVE`` — can disrupt networking / tear down structure; requires a TYPED confirmation
                      (the front-end makes the operator type a phrase) plus a warning.
"""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field

from .layers.base import Context

READ = "read"
CAUTION = "caution"
DESTRUCTIVE = "destructive"

LAYER_IDS = ("l0", "l1", "l2", "l3", "l4", "l5", "l6")


class ActionError(ValueError):
    """Invalid action invocation (missing/bad parameter, or an interactive action run headless)."""


@dataclass(frozen=True)
class Param:
    name: str
    label: str
    required: bool = True
    flag: str = ""              # if set, emitted as [flag, value]; otherwise a positional value
    choices: tuple = ()
    placeholder: str = ""


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    group: str
    risk: str
    argv: tuple                 # fixed subcommand tokens, e.g. ("layer", "install")
    params: tuple = ()
    root_flag: str | None = "--root"   # how this subcommand accepts a staged root (generate: --out)
    interactive: bool = False   # needs a real TTY (the wizard) — front-end must suspend and exec
    warn: str = ""

    @property
    def needs_confirm(self) -> bool:
        return self.risk in (CAUTION, DESTRUCTIVE)

    @property
    def needs_typed_confirm(self) -> bool:
        return self.risk == DESTRUCTIVE

    def confirm_phrase(self, values: dict) -> str:
        """The phrase a DESTRUCTIVE action asks the operator to type: the primary positional target
        (e.g. the layer id ``l3``) when there is one, else ``yes``."""
        for p in self.params:
            if not p.flag and values.get(p.name):
                return str(values[p.name])
        return "yes"

    def build_subargv(self, values: dict | None = None) -> list[str]:
        """Resolve this action + parameter values to the CLI sub-arguments (no entrypoint, no root).
        Raises ActionError on a missing required param or an out-of-set choice."""
        values = values or {}
        out = list(self.argv)
        for p in self.params:
            raw = values.get(p.name)
            val = "" if raw is None else str(raw).strip()
            if not val:
                if p.required:
                    raise ActionError(f"{self.id}: missing required '{p.name}'")
                continue
            if p.choices and val not in p.choices:
                raise ActionError(f"{self.id}: '{p.name}' must be one of {', '.join(p.choices)}")
            out.extend([p.flag, val] if p.flag else [val])
        return out


@dataclass
class ActionResult:
    id: str
    returncode: int
    output: str
    argv: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


# --- the registry: the FULL CLI surface (tui itself excluded) -------------------------------
_ID = (Param("id", "audit/proposal id"),)
_LAYER = (Param("layer", "layer", choices=LAYER_IDS, placeholder="l0..l6"),)

ACTIONS: tuple[Action, ...] = (
    # Status / diagnostics (read-only)
    Action("status", "Status (+health)", "Status", READ, ("status", "--health")),
    Action("verify", "Verify (config drift)", "Status", READ, ("verify",)),
    Action("doctor", "Doctor (triage)", "Status", READ, ("doctor",)),
    Action("check", "Connectivity check", "Status", READ, ("check", "--full")),
    Action("firewall.status", "Firewall status", "Firewall", READ, ("firewall", "status")),
    Action("ai.status", "AI status", "AI", READ, ("ai", "status")),
    Action("ai.proposals", "AI proposals (pending)", "AI", READ, ("ai", "proposals")),
    Action("snapshots", "List snapshots", "Snapshots", READ, ("snapshots",)),
    Action("recovery.status", "Recovery status", "Recovery", READ, ("recovery", "status")),

    # Maintenance (caution)
    Action("generate", "Regenerate configs", "Maintenance", CAUTION, ("generate",), root_flag="--out"),
    Action("update.feeds", "Refresh threat feeds", "Maintenance", CAUTION, ("update", "feeds")),
    Action("update.dnsblock", "Refresh DNS blocklist", "Maintenance", CAUTION, ("update", "dnsblock")),

    # AI control (caution; panic is the kill switch)
    Action("ai.enable", "AI: enable analysis", "AI", CAUTION, ("ai", "enable")),
    Action("ai.disable", "AI: disable analysis", "AI", CAUTION, ("ai", "disable")),
    Action("ai.panic", "AI: PANIC (flush ai_* sets)", "AI", CAUTION, ("ai", "panic"),
           warn="Immediately flushes every AI-imposed block/ratelimit/tarpit element."),
    Action("ai.accept", "AI: accept a proposal", "AI", CAUTION, ("ai", "accept"), params=_ID),
    Action("ai.reject", "AI: reject a proposal", "AI", CAUTION, ("ai", "reject"), params=_ID),
    Action("ai.rollback", "AI: roll back an audit id", "AI", CAUTION, ("ai", "rollback"), params=_ID),

    # Snapshots / watchdog (caution)
    Action("snapshot", "Take a snapshot", "Snapshots", CAUTION, ("snapshot",),
           params=(Param("name", "name (optional)", required=False, flag="--name"),)),
    Action("confirm", "Confirm egress + disarm watchdog", "Snapshots", CAUTION, ("confirm",)),

    # Recovery (caution)
    Action("recovery.start", "Recovery: start rescue", "Recovery", CAUTION, ("recovery", "start"),
           warn="Opens the out-of-band rescue service (ephemeral user + OTP)."),
    Action("recovery.stop", "Recovery: stop rescue", "Recovery", CAUTION, ("recovery", "stop")),
    Action("recovery.extend", "Recovery: extend window", "Recovery", CAUTION, ("recovery", "extend")),

    # Destructive — typed confirmation + warning
    Action("layer.install", "Layer: install", "Layers", DESTRUCTIVE, ("layer", "install"),
           params=_LAYER, warn="Installs/changes a layer on the LIVE system (L0 reloads the firewall)."),
    Action("layer.uninstall", "Layer: uninstall", "Layers", DESTRUCTIVE, ("layer", "uninstall"),
           params=_LAYER,
           warn="Can drop the base table + kill switch. Tear down in reverse order (l6→l0)."),
    Action("firewall.reload", "Firewall: reload ruleset", "Firewall", DESTRUCTIVE, ("firewall", "reload"),
           warn="Flushes and re-applies the entire nftables ruleset."),
    Action("rollback", "Rollback network state", "Snapshots", DESTRUCTIVE, ("rollback",),
           params=(Param("name", "snapshot name (optional)", required=False),
                   Param("reason", "reason (optional)", required=False, flag="--reason")),
           warn="Restores a known-good snapshot — disrupts current networking."),
    Action("setup", "Setup wizard", "Setup", DESTRUCTIVE, ("setup",), interactive=True,
           warn="Interactive install/configure wizard (runs on the terminal)."),
)

_CONFIG_ACTIONS: tuple[Action, ...] | None = None


def config_actions() -> tuple[Action, ...]:
    """Bridge the configspec registry into the Action model so the TUI/GUI get a **Configure** group
    for free (one Action per setting). Everyday settings are CAUTION (yes/no); Advanced are
    DESTRUCTIVE (type-to-confirm) and bake ``--advanced`` into the argv so the shelled CLI honours
    the same gate the front-end already enforced. The new value is collected as the one param."""
    global _CONFIG_ACTIONS
    if _CONFIG_ACTIONS is None:
        from . import configspec
        acts: list[Action] = []
        for s in configspec.SETTINGS:
            adv = s.tier == configspec.ADVANCED
            argv = ("config", "set", s.key) + (("--advanced",) if adv else ())
            acts.append(Action(
                f"config.set.{s.key}", s.label, "Configure",
                DESTRUCTIVE if adv else CAUTION, argv,
                params=(Param("value", f"new value ({s.hint})", choices=s.choices),),
                warn=(f"ADVANCED — {s.help} ({configspec._APPLY_DESC[s.apply]})" if adv
                      else configspec._APPLY_DESC[s.apply])))
        _CONFIG_ACTIONS = tuple(acts)
    return _CONFIG_ACTIONS


def all_actions() -> tuple[Action, ...]:
    """The full action surface: the fixed operate/inspect actions + the generated Configure group."""
    return ACTIONS + config_actions()


def get(action_id: str) -> Action | None:
    return {a.id: a for a in all_actions()}.get(action_id)


def by_group() -> dict[str, list[Action]]:
    """Actions grouped (preserving registry order) for a menu/palette."""
    groups: dict[str, list[Action]] = {}
    for a in all_actions():
        groups.setdefault(a.group, []).append(a)
    return groups


def resolve_entrypoint() -> list[str]:
    """How to invoke the bastion CLI: the installed console script if on PATH, else this
    interpreter's ``-m bastion`` (covers running from a source checkout / the dev tree)."""
    exe = shutil.which("bastion")
    return [exe] if exe else [sys.executable, "-m", "bastion"]


def run_action(ctx: Context, action: Action, values: dict | None = None,
               *, entrypoint: list[str] | None = None) -> ActionResult:
    """Execute an action through the bastion CLI and capture (returncode, combined output).
    Never raises on a non-zero command — only on a malformed invocation (ActionError)."""
    if action.interactive:
        raise ActionError(f"{action.id} is interactive — run it on a terminal, not headless")
    sub = action.build_subargv(values)
    base = list(entrypoint) if entrypoint else resolve_entrypoint()
    argv = base + sub
    root = str(getattr(ctx.system, "root", "/"))
    if action.root_flag and root not in ("/", ""):
        argv += [action.root_flag, root]
    p = ctx.system.run(*argv)
    out = (getattr(p, "stdout", "") or "") + (getattr(p, "stderr", "") or "")
    return ActionResult(action.id, getattr(p, "returncode", 1), out.strip(), argv)
