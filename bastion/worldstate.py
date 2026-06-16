"""bastion world-state — the ONE canonical, versioned snapshot of an installed node.

`gather_state(ctx)` builds a single JSON-serializable document describing the whole node: per-layer
install/active/health, every managed nft set's element count (both families), AI timer/intents/
proposals, recovery state, optional config drift, and the recent reconciler audit tail. `bastion
state --json` emits it verbatim; the TUI (`tui.gather_dashboard`) and the future GUI render from THIS
document instead of each re-probing the box — one data path, one nft-set parser, one schema.

Everything here is READ-ONLY and fails soft: a dashboard / state query must succeed even on a
half-broken node, so no probe raises. Bump ``STATE_SCHEMA_VERSION`` on any breaking shape change.
"""
from __future__ import annotations

import hashlib
import json
import time

from . import layers as layermod
from .layers.base import Context

STATE_SCHEMA_VERSION = 1

# Managed sets shown in the firewall panel — each family (the `…6` IPv6 siblings).
_BASE_SETS = ["blk_feed", "cs_block", "ai_block", "ai_ratelimit", "ai_tarpit", "trusted_hosts"]
MANAGED_SETS = _BASE_SETS + [s + "6" for s in _BASE_SETS]
AI_SETS = ["ai_block", "ai_ratelimit", "ai_tarpit", "ai_block6", "ai_ratelimit6", "ai_tarpit6"]

AUDIT_LOG = "/var/log/edge-reconciler/audit.jsonl"
INTENTS = "/var/lib/edge-ai/intents.json"
PROPOSALS = "/var/lib/edge-ai/proposals.jsonl"
RESOLVED = "/var/lib/edge-ai/proposals-resolved.jsonl"
AI_TIMER = "edge-ai.timer"
RECOVERY = "bastion-recovery"


def nft_table(ctx: Context) -> tuple[str, str]:
    """The managed base table for the node's mode: edge -> (inet, edge), endpoint -> (inet, bastion)."""
    return ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")


def set_count(sys_, family: str, table: str, name: str):
    """THE canonical nft set element-count reader (was duplicated in tui/edge-ctl). Returns the
    element count, or None if the set can't be read (absent, or `nft` denied without root)."""
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


def _layers(ctx: Context) -> list[dict]:
    out = []
    for layer in layermod.all_layers():
        try:
            st = layer.status(ctx)
            checks = [{"name": c.name, "ok": c.ok, "unknown": getattr(c, "unknown", False),
                       "detail": c.detail} for c in layer.health_check(ctx)]
            out.append({"name": st.name, "title": st.title, "installed": st.installed,
                        "active": st.active, "detail": st.detail, "checks": checks})
        except Exception as exc:  # one sick layer must not blank the whole document
            out.append({"name": getattr(layer, "name", "?"), "title": getattr(layer, "title", ""),
                        "installed": False, "active": False, "detail": f"probe error: {exc}",
                        "checks": []})
    return out


def gather_state(ctx: Context, *, drift: tuple | None = None, audit_tail: int = 12) -> dict:
    """Build the canonical world-state document. ``drift`` is the optional ``(issues, n_ok)`` tuple
    from the CLI drift report (the CLI owns the template helpers, so it passes the result in);
    None means drift was not computed. Read-only; never raises."""
    sys_ = ctx.system
    family, table = nft_table(ctx)

    loaded = sys_.nft_table_exists(family, table)
    fw_sets = []
    if loaded:
        for name in MANAGED_SETS:
            cnt = set_count(sys_, family, table, name)
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
        "set_counts": {s: set_count(sys_, family, table, s) for s in AI_SETS} if loaded else {},
        "last_analysis": last_analysis,
        "pending_proposals": _pending_proposals(ctx),
    }

    audit_rows = []
    for ln in _read_lines(ctx, AUDIT_LOG)[-audit_tail:]:
        try:
            audit_rows.append(json.loads(ln))
        except ValueError:
            continue

    recovery_active = sys_.unit_active(RECOVERY)
    drift_doc = None
    if drift is not None:
        issues, n_ok = drift
        drift_doc = {"ok": n_ok, "issues": [{"dest": d, "status": s} for d, s in issues]}

    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "generated_epoch": int(time.time()),
        "mode": ctx.mode,
        "root": str(sys_.root),
        "table": f"{family} {table}",
        "firewall": {"loaded": loaded, "sets": fw_sets},
        "layers": _layers(ctx),
        "ai": ai,
        "recovery": {"active": recovery_active},
        "recovery_active": recovery_active,     # retained for the TUI render's existing key
        "drift": drift_doc,
        "audit_tail": audit_rows,
    }
