"""`bastion tui` — a read-only terminal dashboard for an installed node.

Design: ALL data-gathering and formatting lives in pure functions (``gather_dashboard`` /
``render_dashboard``) that take a layer ``Context`` and never import Textual — so they are unit
-testable with a ``FakeSystem`` and no terminal. The Textual ``App`` (imported lazily inside
``run_tui``, since ``textual`` is an optional-at-runtime dependency) is a thin view that displays
the rendered text and re-gathers on a timer / keypress. Privileged one-key actions (panic /
snapshot / confirm) shell out to the same operational scripts the CLI wraps; they self-elevate or
fail soft, exactly like ``bastion ai panic`` / ``bastion snapshot``.
"""
from __future__ import annotations

from .layers.base import Context
from . import worldstate
# Re-exported so existing `tui.MANAGED_SETS` / `tui.AI_SETS` imports keep working; the canonical
# definitions and ALL the data-gathering now live in bastion.worldstate.
from .worldstate import (MANAGED_SETS, AI_SETS, AUDIT_LOG, INTENTS, PROPOSALS,  # noqa: F401
                         RESOLVED, AI_TIMER, RECOVERY,
                         _proposal_id, _pending_proposals, _read_lines)  # noqa: F401
from .worldstate import set_count as _set_count  # noqa: F401
from .worldstate import nft_table as _nft_table  # noqa: F401


def gather_dashboard(ctx: Context) -> dict:
    """Read-only snapshot of node state for the dashboard. A thin wrapper over the canonical
    ``worldstate.gather_state`` so the TUI, `bastion state --json`, and the GUI share ONE data path
    / one nft-set parser (the document is a superset; the render reads the keys it needs)."""
    return worldstate.gather_state(ctx)


def _onoff(v) -> str:
    return "on" if v else "off"


def _esc(s) -> str:
    """Escape a dynamic string for Rich/Textual markup — a literal '[' from live data (a detail
    string, backend name, audit field) would otherwise be parsed as a markup tag and raise."""
    return str(s).replace("[", "\\[")


def render_dashboard(data: dict) -> str:
    """Format a gather_dashboard() snapshot into the dashboard body text (Rich markup). All
    interpolated runtime data is escaped via _esc; only the static decoration carries live tags."""
    L = []
    L.append(f"[b]bastion[/b]  mode=[cyan]{_esc(data['mode'])}[/cyan] "
             f"table=[cyan]{_esc(data['table'])}[/cyan]  root={_esc(data['root'])}")
    L.append("")

    L.append("[b]Layers[/b]")
    for ly in data["layers"]:
        inst = "[green]yes[/green]" if ly["installed"] else "[dim]no[/dim]"
        act = "[green]yes[/green]" if ly["active"] else "[dim]no[/dim]"
        L.append(f"  {_esc(ly['name']):<4} {_esc(ly['title']):<10} installed:{inst:<14} active:{act}")
        for c in ly["checks"]:
            if c["unknown"]:
                mark = "[yellow]\\[????][/yellow]"
            elif c["ok"]:
                mark = "[green]\\[OK  ][/green]"
            else:
                mark = "[red]\\[FAIL][/red]"
            L.append(f"       {mark} {_esc(c['name'])}" + (f" — {_esc(c['detail'])}" if c["detail"] else ""))
    L.append("")

    fw = data["firewall"]
    L.append("[b]Firewall[/b]  " + ("[green]loaded[/green]" if fw["loaded"]
                                     else "[red]base table not loaded (or need root)[/red]"))
    for s in fw["sets"]:
        cnt = f"[b]{s['count']}[/b]" if s["count"] else "[dim]0[/dim]"
        L.append(f"  {_esc(s['name']):<16} {cnt}")
    L.append("")

    ai = data["ai"]
    L.append(f"[b]AI layer[/b]  timer enabled=[cyan]{_onoff(ai['timer_enabled'])}[/cyan] "
             f"active=[cyan]{_onoff(ai['timer_active'])}[/cyan]  "
             f"pending proposals=[b]{ai['pending_proposals']}[/b]")
    la = ai["last_analysis"]
    if la:
        L.append(f"  last analysis: backend={_esc(la['backend'])} intents={_esc(la['intents'])}")
    counts = ", ".join(f"{_esc(k)}={_esc(v)}" for k, v in ai["set_counts"].items() if v)
    if counts:
        L.append(f"  active blocks: {counts}")
    L.append("")

    L.append("[b]Recent reconciler audit[/b]")
    if not data["audit_tail"]:
        L.append("  [dim](no audit rows yet)[/dim]")
    for r in data["audit_tail"][-8:]:
        L.append(f"  {_esc(r.get('ts','?')):<26} {_esc(r.get('set','?')):<14} "
                 f"applied={_esc(r.get('desired_count','?'))} rejected={_esc(r.get('rejected_count',0))}")
    L.append("")

    L.append(f"[b]Recovery[/b]  bastion-recovery active=[cyan]{_onoff(data['recovery_active'])}[/cyan]")
    return "\n".join(L)


def run_tui(ctx: Context) -> int:
    """Launch the interactive dashboard + full command surface. Raises RuntimeError if Textual
    isn't installed (the CLI turns that into a friendly hint)."""
    try:
        from . import _tui_app
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
        raise RuntimeError(
            "the TUI needs the 'textual' package (a bastion dependency that appears to be "
            "missing) — reinstall bastion, or run `pip install textual`"
        ) from exc
    return _tui_app.launch(ctx)
