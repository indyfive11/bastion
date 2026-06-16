"""D3 — the AI proposals review loop in edge-ctl (list with stable ids → accept/reject).

edge-ctl is a standalone root script; we load it as a module (top level is import-safe — it only
reads machine.env, never calls ensure_root) and redirect its file-path globals to a temp dir, so
the pending/resolve logic is exercised without root or /var.
"""
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-ctl"


def _load():
    # edge-ctl has no .py suffix, so give importlib an explicit source loader.
    loader = SourceFileLoader("edge_ctl_mod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("edge_ctl_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture
def ctl(tmp_path):
    m = _load()
    m.PROPOSALS = str(tmp_path / "proposals.jsonl")
    m.RESOLVED = str(tmp_path / "resolved.jsonl")
    m.AUDIT = str(tmp_path / "audit.jsonl")
    return m


def _write_proposals(ctl, *recs):
    with open(ctl.PROPOSALS, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")


def test_no_proposals_is_clean(ctl, capsys):
    assert ctl.cmd_proposals() == 0
    assert "no pending proposals" in capsys.readouterr().out


def test_proposal_id_is_stable_and_content_derived(ctl):
    rec = {"ts": "2026-06-15T10:00:00+0000", "description": "raise ssh port to 2222"}
    assert ctl._proposal_id(rec) == ctl._proposal_id(dict(rec))         # deterministic
    assert ctl._proposal_id(rec) != ctl._proposal_id({**rec, "description": "other"})


def test_list_then_reject_removes_from_pending(ctl, capsys):
    rec = {"ts": "2026-06-15T10:00:00+0000", "backend": "claude",
           "description": "consider moving ssh off 22"}
    _write_proposals(ctl, rec)
    pid = ctl._proposal_id(rec)

    assert ctl.cmd_proposals() == 0
    assert pid in capsys.readouterr().out                                # id shown in the listing

    assert ctl.cmd_proposal_resolve(pid, "reject") == 0
    assert [p for p, _ in ctl._pending_proposals()] == []               # gone from pending
    # the decision is recorded in the resolved sidecar
    resolved = [json.loads(l) for l in open(ctl.RESOLVED)]
    assert resolved[0]["id"] == pid and resolved[0]["disposition"] == "reject"


def test_accept_records_decision_and_reminder(ctl, capsys):
    rec = {"ts": "2026-06-15T11:00:00+0000", "description": "open wireguard port"}
    _write_proposals(ctl, rec)
    pid = ctl._proposal_id(rec)
    assert ctl.cmd_proposal_resolve(pid, "accept") == 0
    out = capsys.readouterr().out
    assert "accept" in out and "manually" in out                        # never auto-applies
    assert pid not in [p for p, _ in ctl._pending_proposals()]


def test_resolve_unknown_id_errors(ctl, capsys):
    assert ctl.cmd_proposal_resolve("deadbeef0000", "reject") == 1
    assert "no pending proposal" in capsys.readouterr().out


def test_already_resolved_not_listed(ctl):
    a = {"ts": "t1", "description": "one"}
    b = {"ts": "t2", "description": "two"}
    _write_proposals(ctl, a, b)
    ctl.cmd_proposal_resolve(ctl._proposal_id(a), "reject")
    pending_ids = [p for p, _ in ctl._pending_proposals()]
    assert pending_ids == [ctl._proposal_id(b)]
