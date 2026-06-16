"""Regression guard: render_dashboard() output must be valid Textual markup.

The substring-based render test can't catch a malformed tag (a stray '[' from live data, an
unbalanced color tag) — only the real parser can, and that's exactly the bug class that shipped
once. Textual is a declared bastion dependency, so a real install / CI runs this; a bare env
without textual skips it.
"""
import pytest

from bastion import tui

pytest.importorskip("textual")
from textual.content import Content  # noqa: E402


def _parse(data):
    # raises textual.markup.MarkupError on malformed markup
    Content.from_markup(tui.render_dashboard(data))


def _base():
    return {
        "mode": "edge", "root": "/", "table": "inet edge",
        "firewall": {"loaded": True, "sets": [{"name": "blk_feed", "count": 3}]},
        "layers": [{"name": "l0", "title": "core", "installed": True, "active": True,
                    "detail": "", "checks": [{"name": "base table", "ok": True,
                                              "unknown": False, "detail": ""}]}],
        "ai": {"timer_enabled": True, "timer_active": False, "set_counts": {"ai_block": 2},
               "last_analysis": {"backend": "mock:1", "intents": 1}, "pending_proposals": 0},
        "audit_tail": [{"ts": "t1", "set": "blk_feed", "desired_count": 3, "rejected_count": 0}],
        "recovery_active": True,
    }


def test_baseline_renders_valid_markup():
    _parse(_base())


def test_all_health_marks_valid_markup():
    d = _base()
    d["layers"][0]["checks"] = [
        {"name": "ok one", "ok": True, "unknown": False, "detail": ""},
        {"name": "bad one", "ok": False, "unknown": False, "detail": "down"},
        {"name": "unknown one", "ok": False, "unknown": True, "detail": "needs root"},
    ]
    _parse(d)


def test_bracket_in_live_data_is_escaped_not_parsed():
    # a '[' arriving in any runtime field must not blow up the markup parser
    d = _base()
    d["layers"][0]["detail"] = "weird [not-a-tag] detail"
    d["audit_tail"][0]["set"] = "blk[feed]"
    d["ai"]["last_analysis"]["backend"] = "prov[x]:model"
    d["firewall"]["sets"][0]["name"] = "set[1]"
    _parse(d)


def test_empty_board_renders_valid_markup():
    d = _base()
    d["firewall"] = {"loaded": False, "sets": []}
    d["ai"]["last_analysis"] = None
    d["ai"]["set_counts"] = {}
    d["audit_tail"] = []
    _parse(d)
