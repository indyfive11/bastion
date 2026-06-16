"""D1 — `bastion tui` read-only dashboard.

All logic under test is the pure data/format layer (gather_dashboard / render_dashboard /
run_action); the Textual App is a thin view imported lazily, so these tests need neither a
terminal nor the `textual` package. A scripted System drives nft/systemctl, and real files under
a temp root drive the audit/intents/proposals reads.
"""
import json
import subprocess
from pathlib import Path

import pytest

from bastion import cli, tui
from bastion.layers.base import Context
from bastion.system import System

TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"


class FakeSystem(System):
    """Real path/read under a temp root; nft + systemctl are scripted."""
    def __init__(self, root: Path, *, loaded=True, set_elems=None, active=(), enabled=()):
        super().__init__(root=root)
        self.loaded = loaded
        self.set_elems = set_elems or {}     # set name -> list of element strings
        self.active = set(active)
        self.enabled = set(enabled)
        self.ran = []

    def run(self, *args, capture=True, input=None):
        self.ran.append(args)
        a = list(args)
        if a[:3] == ["nft", "list", "table"]:
            return subprocess.CompletedProcess(a, 0 if self.loaded else 1, "", "")
        if a[:4] == ["nft", "-j", "list", "set"]:
            name = a[-1]
            if name not in self.set_elems:
                return subprocess.CompletedProcess(a, 1, "", "No such set")
            doc = {"nftables": [{"set": {"name": name,
                    "elem": [{"elem": {"val": e}} for e in self.set_elems[name]]}}]}
            return subprocess.CompletedProcess(a, 0, json.dumps(doc), "")
        if a[:3] == ["systemctl", "is-active", "--quiet"]:
            return subprocess.CompletedProcess(a, 0 if a[-1] in self.active else 3, "", "")
        if a[:3] == ["systemctl", "is-enabled", "--quiet"]:
            return subprocess.CompletedProcess(a, 0 if a[-1] in self.enabled else 1, "", "")
        return subprocess.CompletedProcess(a, 0, "", "")


def _ctx(sys_, mode="edge"):
    return Context(system=sys_, config={"machine": {"mode": mode}},
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def _seed(root: Path, rel: str, text: str):
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# ---------------------------------------------------------------------------
def test_gather_reports_mode_and_table(tmp_path):
    data = tui.gather_dashboard(_ctx(FakeSystem(tmp_path, loaded=False)))
    assert data["mode"] == "edge" and data["table"] == "inet edge"
    assert data["firewall"]["loaded"] is False
    assert len(data["layers"]) == 7


def test_gather_endpoint_table(tmp_path):
    data = tui.gather_dashboard(_ctx(FakeSystem(tmp_path), mode="endpoint"))
    assert data["table"] == "inet bastion"


def test_gather_counts_loaded_sets(tmp_path):
    sys_ = FakeSystem(tmp_path, loaded=True,
                      set_elems={"blk_feed": ["1.2.3.0/24", "5.6.7.8"], "ai_block6": ["2001:db8::/64"]})
    data = tui.gather_dashboard(_ctx(sys_))
    counts = {s["name"]: s["count"] for s in data["firewall"]["sets"]}
    assert counts["blk_feed"] == 2 and counts["ai_block6"] == 1
    # a set the kernel doesn't have is simply omitted, not an error
    assert "cs_block" not in counts


def test_gather_ai_and_recovery_state(tmp_path):
    sys_ = FakeSystem(tmp_path, loaded=True, set_elems={"ai_block": ["9.9.9.9"]},
                      active={"edge-ai.timer", "bastion-recovery"}, enabled={"edge-ai.timer"})
    _seed(tmp_path, "/var/lib/edge-ai/intents.json",
          json.dumps({"backend": "mock:1", "intents": [{"a": 1}], "generated_epoch": 100}))
    data = tui.gather_dashboard(_ctx(sys_))
    assert data["ai"]["timer_enabled"] is True and data["ai"]["timer_active"] is True
    assert data["ai"]["last_analysis"]["backend"] == "mock:1"
    assert data["ai"]["set_counts"]["ai_block"] == 1
    assert data["recovery_active"] is True


def test_pending_proposals_excludes_resolved(tmp_path):
    a = {"ts": "t1", "description": "raise ssh port"}
    b = {"ts": "t2", "description": "open wg"}
    _seed(tmp_path, "/var/lib/edge-ai/proposals.jsonl",
          json.dumps(a) + "\n" + json.dumps(b) + "\n")
    _seed(tmp_path, "/var/lib/edge-ai/proposals-resolved.jsonl",
          json.dumps({"id": tui._proposal_id(a), "disposition": "reject"}) + "\n")
    data = tui.gather_dashboard(_ctx(FakeSystem(tmp_path, loaded=False)))
    assert data["ai"]["pending_proposals"] == 1   # only b remains pending


def test_audit_tail_parsed_and_tailed(tmp_path):
    rows = [json.dumps({"ts": f"t{i}", "set": "blk_feed", "desired_count": i}) for i in range(20)]
    _seed(tmp_path, "/var/log/edge-reconciler/audit.jsonl", "\n".join(rows) + "\n")
    data = tui.gather_dashboard(_ctx(FakeSystem(tmp_path, loaded=False)))
    assert len(data["audit_tail"]) == 12 and data["audit_tail"][-1]["ts"] == "t19"


def test_gather_never_raises_on_garbage(tmp_path):
    _seed(tmp_path, "/var/lib/edge-ai/intents.json", "not json")
    _seed(tmp_path, "/var/log/edge-reconciler/audit.jsonl", "garbage\n{bad}\n")
    data = tui.gather_dashboard(_ctx(FakeSystem(tmp_path, loaded=False)))
    assert data["ai"]["last_analysis"] is None and data["audit_tail"] == []


# ---------------------------------------------------------------------------
def test_render_contains_sections(tmp_path):
    sys_ = FakeSystem(tmp_path, loaded=True, set_elems={"blk_feed": ["1.2.3.0/24"]},
                      enabled={"edge-ai.timer"})
    out = tui.render_dashboard(tui.gather_dashboard(_ctx(sys_)))
    for needle in ("Layers", "Firewall", "AI layer", "Recent reconciler audit", "Recovery",
                   "blk_feed", "inet edge"):
        assert needle in out


# ---------------------------------------------------------------------------
def test_tui_parser_wires_command():
    args = cli.build_parser().parse_args(["tui", "--root", "/x"])
    assert args.func is cli.cmd_tui


def test_cmd_tui_reports_missing_textual(monkeypatch, capsys):
    monkeypatch.setattr(tui, "run_tui", lambda ctx: (_ for _ in ()).throw(RuntimeError("need textual")))
    monkeypatch.setattr(cli, "build_context", lambda args: _ctx(FakeSystem(Path("/x"))))
    assert cli.cmd_tui(cli.build_parser().parse_args(["tui"])) == 1
    assert "need textual" in capsys.readouterr().err


def test_cmd_tui_happy_path(monkeypatch):
    monkeypatch.setattr(tui, "run_tui", lambda ctx: 0)
    monkeypatch.setattr(cli, "build_context", lambda args: _ctx(FakeSystem(Path("/x"))))
    assert cli.cmd_tui(cli.build_parser().parse_args(["tui"])) == 0
