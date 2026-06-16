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

import hashlib
import json

from . import layers as layermod
from .layers.base import Context

# Managed sets shown in the firewall panel — each family (D6 added the `…6` IPv6 siblings).
_BASE_SETS = ["blk_feed", "cs_block", "ai_block", "ai_ratelimit", "ai_tarpit", "trusted_hosts"]
MANAGED_SETS = _BASE_SETS + [s + "6" for s in _BASE_SETS]
AI_SETS = ["ai_block", "ai_ratelimit", "ai_tarpit", "ai_block6", "ai_ratelimit6", "ai_tarpit6"]

AUDIT_LOG = "/var/log/edge-reconciler/audit.jsonl"
INTENTS = "/var/lib/edge-ai/intents.json"
PROPOSALS = "/var/lib/edge-ai/proposals.jsonl"
RESOLVED = "/var/lib/edge-ai/proposals-resolved.jsonl"
AI_TIMER = "edge-ai.timer"
RECOVERY = "bastion-recovery"


def _nft_table(ctx: Context) -> tuple[str, str]:
    return ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")


def _set_count(sys_, family: str, table: str, name: str):
    """Element count of one nft set, or None if it can't be read (absent / needs root)."""
    p = sys_.run("nft", "-j", "list", "set", family, table, name)
    if getattr(p, "returncode", 1) != 0:
        return None
    try:
        data = json.loads(p.stdout)
    except (ValueError, TypeError):
        return None
    for obj in data.get("nftables", []):
        s = obj.get("set")
        if s is not None and s.get("name") == name:
            return len(s.get("elem", []) or [])
    return None


def _read_lines(ctx: Context, path: str) -> list[str]:
    try:
        return ctx.system.read(path).splitlines()
    except OSError:
        return []


def _proposal_id(rec: dict) -> str:
    raw = f"{rec.get('ts','')}\x00{rec.get('description','')}".encode()
    return hashlib.sha1(raw).hexdigest()[:12]


def _pending_proposals(ctx: Context) -> int:
    """Count proposals not yet accepted/rejected — same content-hash identity edge-ctl uses."""
    resolved = set()
    for ln in _read_lines(ctx, RESOLVED):
        try:
            resolved.add(json.loads(ln).get("id"))
        except ValueError:
            continue
    pending = set()
    for ln in _read_lines(ctx, PROPOSALS):
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        pid = _proposal_id(rec)
        if pid not in resolved:
            pending.add(pid)
    return len(pending)


def gather_dashboard(ctx: Context) -> dict:
    """Collect a full read-only snapshot of node state. Every probe fails soft — a dashboard
    must render even on a half-broken box, so nothing here raises."""
    sys_ = ctx.system
    family, table = _nft_table(ctx)

    layers = []
    for layer in layermod.all_layers():
        try:
            st = layer.status(ctx)
            checks = [{"name": c.name, "ok": c.ok, "unknown": getattr(c, "unknown", False),
                       "detail": c.detail} for c in layer.health_check(ctx)]
            layers.append({"name": st.name, "title": st.title, "installed": st.installed,
                           "active": st.active, "detail": st.detail, "checks": checks})
        except Exception as exc:  # one sick layer must not blank the whole board
            layers.append({"name": getattr(layer, "name", "?"), "title": getattr(layer, "title", ""),
                           "installed": False, "active": False, "detail": f"probe error: {exc}",
                           "checks": []})

    loaded = sys_.nft_table_exists(family, table)
    fw_sets = []
    if loaded:
        for name in MANAGED_SETS:
            cnt = _set_count(sys_, family, table, name)
            if cnt is not None:
                fw_sets.append({"name": name, "count": cnt})

    last_analysis = None
    try:
        doc = json.loads(sys_.read(INTENTS))
        last_analysis = {"backend": doc.get("backend"), "intents": len(doc.get("intents", [])),
                         "generated_epoch": doc.get("generated_epoch")}
    except (OSError, ValueError):
        pass

    ai = {
        "timer_enabled": sys_.unit_enabled(AI_TIMER),
        "timer_active": sys_.unit_active(AI_TIMER),
        "set_counts": {s: _set_count(sys_, family, table, s) for s in AI_SETS} if loaded else {},
        "last_analysis": last_analysis,
        "pending_proposals": _pending_proposals(ctx),
    }

    audit_tail = []
    for ln in _read_lines(ctx, AUDIT_LOG)[-12:]:
        try:
            audit_tail.append(json.loads(ln))
        except ValueError:
            continue

    return {
        "mode": ctx.mode,
        "root": str(sys_.root),
        "table": f"{family} {table}",
        "firewall": {"loaded": loaded, "sets": fw_sets},
        "layers": layers,
        "ai": ai,
        "audit_tail": audit_tail,
        "recovery_active": sys_.unit_active(RECOVERY),
    }


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

    # bind each action key to a handler
    for a in ACTIONS:
        setattr(BastionTUI, f"action_action_{a.key}",
                (lambda key: lambda self: self._do(key))(a.key))

    BastionTUI(ctx).run()
    return 0
