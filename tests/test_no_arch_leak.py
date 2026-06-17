"""F4 — end-to-end no-arch-leak assertion for edge-ai-collect (the data-egress sanitization
boundary). The collector hands signals.json to a possibly-remote AI backend, so it must emit ONLY
public source IPs + event counts — never RFC1918 / CGNAT / ULA / link-local / loopback / hostnames.

is_emittable gates at ingest; this pins the belt-and-suspenders SCRUB + the serialized-bytes TRIPWIRE
that fails CLOSED. Loaded via the standard standalone-script idiom (top level is import-safe), with
the external commands (cscli/journalctl/nft) stubbed through the module's single `run()` seam.
"""
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-ai-collect"

PUB4 = "45.33.32.156"             # genuinely global -> MUST be emitted
PUB6 = "2606:4700:4700::1111"     # global (Cloudflare) -> emittable
PRIV = ["192.168.1.10", "10.5.5.5", "172.16.0.9", "100.64.0.7",   # RFC1918 + CGNAT
        "127.0.0.1", "fd00::1", "fe80::abcd", "::1"]               # loopback + ULA + link-local
HOSTNAME = "gateway.internal.lan"


def _load():
    loader = SourceFileLoader("edge_ai_collect_mod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("edge_ai_collect_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def _fake_run(decisions_extra="", journal_lines=None, ai_members=None):
    """Build a run() stub dispatching on the command, injecting poison."""
    journal = journal_lines if journal_lines is not None else [
        f"Failed password for root from {PUB4} port 22 ssh2",
        f"Failed password for root from {PRIV[0]} port 22 ssh2",     # RFC1918 -> dropped
        f"Failed password for invalid user x from {PRIV[5]} port 9 ssh2",  # ULA -> dropped
        f"Failed password for root from {HOSTNAME} port 22 ssh2",    # hostname -> no IP match
        f"Invalid user admin from {PUB6} port 22",
    ]
    decisions = json.dumps([{"decisions": [
        {"value": PUB4}, {"value": PRIV[1] + "/32"}, {"value": PRIV[6]},  # one public, two private
    ]}])
    alerts = json.dumps([
        {"source": {"value": PUB4}, "scenario": "crowdsecurity/ssh-bf"},
        {"source": {"value": PUB4}, "scenario": f"custom/{PRIV[2]}-probe"},  # unsafe label (has IP/dots)
    ])
    nft_members = ai_members if ai_members is not None else [PUB4, PRIV[1]]   # a private snuck into a set
    nft_json = json.dumps({"nftables": [{"set": {"elem": nft_members}}]})

    def run(cmd, timeout=20):
        if cmd[0] == "cscli" and cmd[1] == "decisions":
            return decisions
        if cmd[0] == "cscli" and cmd[1] == "alerts":
            return alerts
        if cmd[0] == "journalctl":
            return "\n".join(journal) + "\n"
        if cmd[0] == "nft":
            return nft_json
        return None
    return run


@pytest.fixture
def collect(tmp_path, monkeypatch):
    m = _load()
    out = tmp_path / "signals.json"
    monkeypatch.setattr(m, "OUT", str(out))
    monkeypatch.setattr(m, "load_allowlist", lambda: [])   # empty allowlist: is_global is the gate
    monkeypatch.setattr(m, "run", _fake_run())
    return m, out


def test_signals_json_has_no_private_or_hostname(collect, capsys):
    m, out = collect
    assert m.main() == 0
    text = out.read_text()
    # the public sources survive
    assert PUB4 in text
    # the PROPERTY: not one non-public IP literal anywhere in the emitted bytes (robust where a naive
    # substring check is not — e.g. "::1" is a substring of the legitimate public 2606:4700:...::1111).
    assert m.find_ip_leaks(text, []) == [], "non-public IP reached signals.json"
    # hostnames have no IP form, so assert them directly
    assert HOSTNAME not in text and "internal.lan" not in text
    doc = json.loads(text)
    # scrub dropped the private already_acted member and the unsafe scenario label
    for members in doc["already_acted"].values():
        assert all("192.168" not in mm and "10.5.5" not in mm for mm in members)
    labels = [s for o in doc["observations"] for s in o.get("scenarios", [])]
    assert "ssh-bf" in labels                                   # safe slug kept
    assert all("." not in s for s in labels)                    # nothing dotted (no FQDN/IP) survived


def test_find_ip_leaks_detects_private(collect):
    m, _ = collect
    serialized = json.dumps({"x": "8.8.8.8 is fine", "y": "but 10.0.0.1 is not"})
    leaks = m.find_ip_leaks(serialized, [])
    assert leaks == ["10.0.0.1"]                                # public ignored, private flagged


def test_scrub_doc_drops_non_public(collect):
    m, _ = collect
    doc = {"observations": [{"ip": PUB4, "scenarios": ["ssh-bf", "bad.dotted"]},
                            {"ip": "10.0.0.9", "scenarios": []}],
           "already_acted": {"ai_block": [PUB4, "192.168.0.1/32"]}}
    out = m.scrub_doc(doc, [])
    assert [o["ip"] for o in out["observations"]] == [PUB4]      # private observation dropped
    assert out["observations"][0]["scenarios"] == ["ssh-bf"]     # dotted label dropped
    assert out["already_acted"]["ai_block"] == [PUB4]            # private member dropped


def test_tripwire_fails_closed(tmp_path, monkeypatch):
    # If a private IP survives scrub (here: scrub neutered), the serialized-bytes tripwire must
    # refuse to emit it — dropping to empty observations + scrubbed=True rather than leaking.
    m = _load()
    out = tmp_path / "signals.json"
    monkeypatch.setattr(m, "OUT", str(out))
    monkeypatch.setattr(m, "load_allowlist", lambda: [])
    monkeypatch.setattr(m, "run", _fake_run())
    monkeypatch.setattr(m, "scrub_doc", lambda doc, allow: doc)   # defeat the scrub -> force the tripwire
    assert m.main() == 0
    doc = json.loads(out.read_text())
    assert doc["observations"] == [] and doc["already_acted"]["ai_block"] == []
    assert doc.get("scrubbed") is True
    for bad in PRIV:
        assert bad not in out.read_text()
