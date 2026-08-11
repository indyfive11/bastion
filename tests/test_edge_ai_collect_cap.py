"""H5 — cap the emitted observations list to a deterministic top-N by threat rank.

edge-ai-collect's signals.json is piped verbatim to a PAID AI backend every analyzer cycle, so an
unbounded observations list (one row per distinct public attacker over 24h) is a cost/latency blowup
on a scanned box. The cap must keep the RIGHT rows (crowdsec-active first, then event volume) and keep
them DETERMINISTICALLY (a stable ip tiebreak), report the honest pre-cap count, and never weaken the
no-arch-leak tripwire. Loaded via the standard standalone-script idiom (import-safe top level) with the
external commands stubbed through the module's single run() seam.
"""
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-ai-collect"


def _load():
    loader = SourceFileLoader("edge_ai_collect_cap_mod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("edge_ai_collect_cap_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def _ip(i):
    # 45/8 is allocated PUBLIC space -> every address is is_global (unlike TEST-NET 203.0.113/24,
    # 198.51.100/24, 192.0.2/24, which is_global REJECTS and which would silently drop from the doc).
    return f"45.33.{i // 256}.{i % 256}"


def _run_stub(journal_lines=None, decisions=None):
    """A run() stub dispatching on the command. journal_lines feed sshd observations (repeat an IP to
    raise its total_events); decisions feed crowdsec active-decision-only observations (0 events)."""
    jl = journal_lines or []
    dec = json.dumps([{"decisions": [{"value": v} for v in (decisions or [])]}])

    def run(cmd, timeout=20):
        if cmd[0] == "cscli" and cmd[1] == "decisions":
            return dec
        if cmd[0] == "cscli" and cmd[1] == "alerts":
            return "null"
        if cmd[0] == "journalctl":
            return "\n".join(jl) + "\n"
        if cmd[0] == "nft":
            return json.dumps({"nftables": [{"set": {"elem": []}}]})
        return None
    return run


@pytest.fixture
def collect(tmp_path, monkeypatch):
    m = _load()
    out = tmp_path / "signals.json"
    monkeypatch.setattr(m, "OUT", str(out))
    monkeypatch.setattr(m, "load_allowlist", lambda: [])
    return m, out


def _emit(m, out, journal_lines=None, decisions=None):
    m.run = _run_stub(journal_lines, decisions)  # rebind the module-level seam callers close over
    m.main()
    return json.loads(out.read_text())


def test_constant_ships_at_200(collect):
    m, _ = collect
    assert m.MAX_OBSERVATIONS == 200   # a fully-monkeypatched suite must still prove the real cap value


def test_cap_truncates_and_reports_honest_total(collect, monkeypatch):
    m, out = collect
    monkeypatch.setattr(m, "MAX_OBSERVATIONS", 3)
    # 10 distinct public scanners, one failed-password each -> 10 emittable observations
    lines = [f"Failed password for root from {_ip(i)} port 22 ssh2" for i in range(10)]
    doc = _emit(m, out, journal_lines=lines)
    assert len(doc["observations"]) == 3          # truncated to the cap
    assert doc["observations_total"] == 10        # honest PRE-cap emittable count, not 3
    assert doc["capped"] is True


def test_no_cap_below_threshold(collect, monkeypatch):
    m, out = collect
    monkeypatch.setattr(m, "MAX_OBSERVATIONS", 100)
    lines = [f"Failed password for root from {_ip(i)} port 22 ssh2" for i in range(5)]
    doc = _emit(m, out, journal_lines=lines)
    assert len(doc["observations"]) == 5
    assert doc["observations_total"] == 5
    assert doc["capped"] is False


def test_cap_keeps_highest_event_rows(collect, monkeypatch):
    m, out = collect
    monkeypatch.setattr(m, "MAX_OBSERVATIONS", 3)
    lines = []
    # IPs 0..1 get many events (loud); IPs 2..9 get one each. The loud ones MUST survive the cap.
    for _ in range(5):
        lines.append(f"Failed password for root from {_ip(0)} port 22 ssh2")
        lines.append(f"Failed password for root from {_ip(1)} port 22 ssh2")
    for i in range(2, 10):
        lines.append(f"Failed password for root from {_ip(i)} port 22 ssh2")
    doc = _emit(m, out, journal_lines=lines)
    kept = {o["ip"] for o in doc["observations"]}
    assert _ip(0) in kept and _ip(1) in kept          # the two loudest survived
    # emitted list is sorted by descending event volume (kept the wrong ones? this catches it)
    evs = [o["total_events"] for o in doc["observations"]]
    assert evs == sorted(evs, reverse=True)
    assert evs[0] == 5 and evs[1] == 5


def test_crowdsec_active_outranks_zero_event_noise(collect, monkeypatch):
    """F1: an active-decision-only IP has an empty events dict (total_events=0). A naive
    sort-by-events would truncate it FIRST; the composite rank must keep it OVER 1-event scanners."""
    m, out = collect
    monkeypatch.setattr(m, "MAX_OBSERVATIONS", 2)
    banned = _ip(200)                                  # confirmed-malicious, 0 in-window events
    scanners = [f"Failed password for root from {_ip(i)} port 22 ssh2" for i in range(3)]
    doc = _emit(m, out, journal_lines=scanners, decisions=[banned])
    kept = {o["ip"] for o in doc["observations"]}
    assert banned in kept                              # crowdsec-confirmed survived the cap
    assert doc["observations"][0]["ip"] == banned      # and ranks at the very top


def test_top_n_is_deterministic_under_ties(collect, monkeypatch):
    """All-equal event counts: survivors must be a STABLE ip-ordered top set across runs (this is only
    pinnable because of the x['ip'] tiebreak; without it, set-iteration/hash order decides the cut)."""
    m, out = collect
    monkeypatch.setattr(m, "MAX_OBSERVATIONS", 3)
    lines = [f"Failed password for root from {_ip(i)} port 22 ssh2" for i in range(20)]  # all 1 event
    first = _emit(m, out, journal_lines=lines)
    second = _emit(m, out, journal_lines=lines)
    kept1 = [o["ip"] for o in first["observations"]]
    kept2 = [o["ip"] for o in second["observations"]]
    assert kept1 == kept2                              # deterministic run to run
    # ip descending within the tie -> the 3 highest-sorting ips of the 20
    expected = sorted((_ip(i) for i in range(20)), reverse=True)[:3]
    assert kept1 == expected


def test_cap_preserves_no_arch_leak_property(collect, monkeypatch):
    """Truncation is removal-only: the emitted bytes must still carry zero non-public IP literals."""
    m, out = collect
    monkeypatch.setattr(m, "MAX_OBSERVATIONS", 3)
    lines = [f"Failed password for root from {_ip(i)} port 22 ssh2" for i in range(10)]
    doc = _emit(m, out, journal_lines=lines)
    serialized = out.read_text()
    assert m.find_ip_leaks(serialized, []) == []       # no private/leaky literal survived the cap
    assert isinstance(doc["observations_total"], int)  # count is a bare int, never an ip-shaped string
