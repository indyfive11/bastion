"""Innovation #1 — the canonical `bastion state --json` world-state document.

worldstate.gather_state is the single data path the TUI (tui.gather_dashboard) and the future GUI
render from. These pin the document's schema, the canonical nft set-count parser, drift embedding,
and that `bastion state` emits valid JSON.
"""
import json
import subprocess
from pathlib import Path

from bastion import cli, tui, worldstate
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


class FakeSystem(System):
    def __init__(self, root: Path, *, loaded=True, set_elems=None, active=(), enabled=()):
        super().__init__(root=root)
        self.loaded = loaded
        self.set_elems = set_elems or {}
        self.active = set(active)
        self.enabled = set(enabled)

    def run(self, *args, capture=True, input=None):
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


def test_document_is_versioned_and_complete(tmp_path):
    doc = worldstate.gather_state(_ctx(FakeSystem(tmp_path, loaded=False)))
    assert doc["schema_version"] == worldstate.STATE_SCHEMA_VERSION == 1
    assert isinstance(doc["generated_epoch"], int) and doc["generated_epoch"] > 0
    for key in ("mode", "root", "table", "firewall", "layers", "ai", "recovery", "drift", "audit_tail"):
        assert key in doc
    assert doc["mode"] == "edge" and doc["table"] == "inet edge"


def test_endpoint_table(tmp_path):
    doc = worldstate.gather_state(_ctx(FakeSystem(tmp_path, loaded=False), mode="endpoint"))
    assert doc["table"] == "inet bastion"


def test_firewall_set_counts_via_canonical_parser(tmp_path):
    sys_ = FakeSystem(tmp_path, loaded=True,
                      set_elems={"blk_feed": ["1.1.1.1", "2.2.2.2"], "ai_block6": ["2001:db8::1"]})
    doc = worldstate.gather_state(_ctx(sys_))
    counts = {s["name"]: s["count"] for s in doc["firewall"]["sets"]}
    assert counts["blk_feed"] == 2 and counts["ai_block6"] == 1
    assert doc["ai"]["set_counts"]["ai_block6"] == 1
    # the canonical reader returns None for an absent set (not 0, not a crash)
    assert worldstate.set_count(sys_, "inet", "edge", "nope") is None


def test_recovery_and_ai_timer_reflect_units(tmp_path):
    sys_ = FakeSystem(tmp_path, loaded=False, active=["bastion-recovery"], enabled=["edge-ai.timer"])
    doc = worldstate.gather_state(_ctx(sys_))
    assert doc["recovery"]["active"] is True and doc["recovery_active"] is True
    assert doc["ai"]["timer_enabled"] is True and doc["ai"]["timer_active"] is False


def test_drift_section_embeds_when_provided(tmp_path):
    drift = ([("/etc/nftables.conf", "DRIFTED"), ("/etc/x", "MISSING")], 7)
    doc = worldstate.gather_state(_ctx(FakeSystem(tmp_path, loaded=False)), drift=drift)
    assert doc["drift"]["ok"] == 7
    assert {"dest": "/etc/nftables.conf", "status": "DRIFTED"} in doc["drift"]["issues"]
    # absent when not computed
    doc2 = worldstate.gather_state(_ctx(FakeSystem(tmp_path, loaded=False)))
    assert doc2["drift"] is None


def test_tui_dashboard_delegates_to_worldstate(tmp_path):
    # the TUI must not re-implement gathering — gather_dashboard is now a thin pass-through
    sys_ = FakeSystem(tmp_path, loaded=True, set_elems={"blk_feed": ["9.9.9.9"]})
    dash = tui.gather_dashboard(_ctx(sys_))
    assert dash["schema_version"] == 1                       # it IS the worldstate document
    assert {s["name"]: s["count"] for s in dash["firewall"]["sets"]}["blk_feed"] == 1
    assert tui.MANAGED_SETS == worldstate.MANAGED_SETS       # re-export still works


def test_cmd_state_emits_valid_json(tmp_path, capsys):
    rc = cli.main(["state", "--root", str(tmp_path)])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)               # must be parseable
    assert doc["schema_version"] == 1 and doc["root"] == str(tmp_path)
    assert isinstance(doc["layers"], list) and len(doc["layers"]) == 7


def test_cmd_state_compact_is_single_line(tmp_path, capsys):
    rc = cli.main(["state", "--compact", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert "\n" not in out and json.loads(out)["schema_version"] == 1
