"""Sprint-1 remainder (foundation audit): A1, A3, A7, C1-C5, D5, D6.

Python-side fixes are tested directly; the operational shell-script fixes use the project's
bash idiom — extract a function with sed, source it in a child `bash`, redefine externals as
recording shell functions, drive via env seams.
"""
import importlib.util
import json
import os
import subprocess
import textwrap
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from bastion import state

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "bastion" / "scripts"
TEMPLATES = REPO / "bastion" / "templates"
EXAMPLE = REPO / "bastion" / "machine.conf.example"


def _load(path: Path, name: str):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


# --------------------------------------------------------------------------- A1
def _conf():
    return state.load_conf(EXAMPLE)


def test_validate_conf_clean_example():
    errs, warns = state.validate_conf(_conf())
    assert errs == []


def test_validate_conf_rejects_bad_values():
    c = _conf()
    c["machine"]["mode"] = "bridge"
    c["ports"]["ssh"] = "70000"
    c["network"]["lan_cidr"] = "not-a-cidr"
    c["network"]["lan_ip"] = "999.1.1.1"
    c["interfaces"]["lan"] = "this-name-is-way-too-long-for-an-iface"
    errs, _ = state.validate_conf(c)
    blob = " ".join(errs)
    assert "mode" in blob and "ssh" in blob and "lan_cidr" in blob and "lan_ip" in blob and "lan" in blob
    assert len(errs) >= 5


def test_validate_conf_accepts_good_service_ports():
    c = _conf()
    c["network"]["service_ports"] = "8096, 7878/tcp 53/udp"
    errs, _ = state.validate_conf(c)
    assert errs == []


def test_validate_conf_rejects_bad_service_ports():
    c = _conf()
    c["network"]["service_ports"] = "8096 70000 53/sctp abc"
    errs, _ = state.validate_conf(c)
    blob = " ".join(errs)
    assert "70000" in blob and "53/sctp" in blob and "abc" in blob
    assert "8096" not in blob               # the valid token is not flagged


def test_validate_conf_firewall_scope():
    c = _conf()
    for good in ("exclusive", "cooperative", ""):       # blank = template default (exclusive)
        c["machine"]["firewall_scope"] = good
        assert state.validate_conf(c)[0] == []
    c["machine"]["firewall_scope"] = "shared"
    errs, _ = state.validate_conf(c)
    assert any("firewall_scope" in e and "shared" in e for e in errs)


def test_validate_conf_accepts_good_zones():
    # CIDR source (proves the trusted_hosts named-set CIDR bug is sidestepped — inline rules accept
    # CIDRs that a named set without `flags interval` rejects), iface source, any source, `all`.
    c = _conf()
    c["zones"] = {
        "lan": "192.168.1.0/24 -> 8096, 8989",
        "vms": "iface:virbr0 -> all",
        "ztctl": "any -> 9993",
        "v6": "fd00::/8 -> 22",
    }
    errs, _ = state.validate_conf(c)
    assert errs == []


def test_validate_conf_rejects_bad_zones():
    c = _conf()
    c["zones"] = {
        "noarrow": "192.168.1.0/24 8096",       # missing ->
        "badsrc": "not-an-ip -> 8096",
        "badport": "any -> 70000",
        "badproto": "any -> 53/sctp",
        "badiface": "iface:this-name-is-way-too-long -> all",
    }
    errs, _ = state.validate_conf(c)
    blob = " ".join(errs)
    assert all(t in blob for t in ("noarrow", "not-an-ip", "70000", "53/sctp", "badiface"))


def test_validate_conf_warns_on_default_route():
    c = _conf()
    c["network"]["lan_cidr"] = "0.0.0.0/0"
    errs, warns = state.validate_conf(c)
    assert errs == []                      # valid, just dangerous
    assert any("default route" in w for w in warns)


def test_generate_check_rejects_invalid_conf(tmp_path, capsys):
    from bastion import cli
    bad = tmp_path / "machine.conf"
    text = EXAMPLE.read_text().replace("mode = edge", "mode = sideways")
    bad.write_text(text)
    rc = cli.main(["generate", "--check", "--conf", str(bad)])
    assert rc == 1
    assert "mode" in capsys.readouterr().err


def test_nft_syntax_check_catches_broken_ruleset():
    from bastion import cli
    ok, _ = cli._nft_syntax_check("table inet x { chain c { type filter hook input")  # truncated
    # On a box with no nft this skips (ok=True); where nft exists it must reject the broken text.
    import shutil
    if shutil.which("nft"):
        assert ok is False
    valid = "table inet x {\n  chain c {\n    type filter hook input priority 0; policy accept;\n  }\n}\n"
    ok2, _ = cli._nft_syntax_check(valid)
    assert ok2 is True


# --------------------------------------------------------------------------- A3
def _render(rel: str, mode: str) -> str:
    from bastion import templates
    c = _conf()
    c["machine"]["mode"] = mode
    return templates.render_file(TEMPLATES / rel, c)


@pytest.mark.parametrize("rel,mode", [("nftables-edge.nft", "edge"),
                                      ("nftables-endpoint.nft", "endpoint")])
def test_icmpv6_is_scoped_and_rate_limited(rel, mode):
    body = _render(rel, mode)
    # the blanket accept is gone as a RULE (it survives only inside an explanatory comment)
    rules = [l.strip() for l in body.splitlines() if not l.strip().startswith("#")]
    assert "ip6 nexthdr ipv6-icmp accept" not in rules
    # ND scoped by hop-limit 255, MLD by link-local, echo rate-limited
    assert "ip6 hoplimit 255 icmpv6 type" in body
    assert "ip6 saddr fe80::/10 icmpv6 type" in body
    assert "icmpv6 type echo-request limit rate" in body


def test_edge_forward_icmpv6_has_no_nd():
    body = _render("nftables-edge.nft", "edge")
    fwd = body[body.index("chain forward"):body.index("chain output")]
    assert "icmpv6 type echo-request limit rate" in fwd
    assert "hoplimit 255" not in fwd            # ND is never forwarded


# --------------------------------------------------------------------------- A7
@pytest.fixture
def ctl():
    return _load(SCRIPTS / "edge-ctl", "edge_ctl_a7")


def test_norm_net_canonicalizes_both_families(ctl):
    assert ctl._norm_net("1.2.3.4") == "1.2.3.4/32"
    assert ctl._norm_net("1.2.3.4/32") == "1.2.3.4/32"
    assert ctl._norm_net("2001:db8::1") == "2001:db8::1/128"
    assert ctl._norm_net("2001:db8::1/128") == "2001:db8::1/128"
    assert ctl._norm_net("garbage") is None


@pytest.mark.parametrize("elem,intent", [("2001:db8::1/128", "2001:db8::1"),   # v6 (the bug)
                                         ("1.2.3.23/32", "1.2.3.23")])         # v4 regression
def test_rollback_prunes_intent_across_form(ctl, tmp_path, elem, intent):
    import types
    ctl.AUDIT = str(tmp_path / "audit.jsonl")
    ctl.INTENTS = str(tmp_path / "intents.json")
    setname = "ai_block6" if ":" in elem else "ai_block"
    Path(ctl.AUDIT).write_text(json.dumps(
        {"id": "r1", "set": setname, "ai_elements": [elem]}) + "\n")
    Path(ctl.INTENTS).write_text(json.dumps({"intents": [{"cidr": intent}]}))
    ctl.nft = lambda *a: types.SimpleNamespace(returncode=0, stdout="", stderr="")
    rc = ctl.cmd_rollback("r1")
    assert rc == 0
    assert json.loads(Path(ctl.INTENTS).read_text())["intents"] == []   # pruned -> not re-added


# --------------------------------------------------------------------------- C4
def test_ensure_root_returns_when_root(ctl, monkeypatch):
    monkeypatch.setattr(ctl.os, "geteuid", lambda: 0)
    assert ctl.ensure_root() is None       # no exec, no exit


def test_header_has_no_stale_sudoers_claim():
    body = (SCRIPTS / "edge-ctl").read_text()
    assert "granted via /etc/sudoers.d/edge-ctl" not in body   # the false grant claim is gone
    assert "There is NO" in body and "sudoers" in body          # the honest note replaced it


# --------------------------------------------------------------------------- D6
def test_analyze_clean_strips_control_chars():
    m = _load(SCRIPTS / "edge-ai-analyze", "edge_ai_analyze_d6")
    dirty = "block \x1b[31mRED\x1b[0m\nthen\ttab\x07bell"
    out = m._clean(dirty, 280)
    assert "\x1b" not in out and "\n" not in out and "\x07" not in out and "\t" not in out
    assert out.startswith("block ")


def test_ctl_safe_strips_control_chars(ctl):
    assert "\x1b" not in ctl._safe("x\x1b[2Jy")
    assert ctl._safe("a" * 500, 160) == "a" * 160


# --------------------------------------------------------------------------- D5
def test_analyze_passes_minimal_env_to_backend(tmp_path, monkeypatch):
    import sys as _sys
    m = _load(SCRIPTS / "edge-ai-analyze", "edge_ai_analyze_d5")
    envdump = tmp_path / "backend_env.json"
    backend = tmp_path / "fake_backend.py"
    backend.write_text("import os, json, sys\n"
                       f"open({str(envdump)!r}, 'w').write(json.dumps(dict(os.environ)))\n"
                       "print(json.dumps({'version': 1, 'backend': 'fake', 'intents': []}))\n")
    conf = tmp_path / "backend.conf"
    # run the backend via the interpreter (pytest tmp_path is on a noexec mount)
    conf.write_text(f"BACKEND_CMD={_sys.executable} {backend}\n")
    m.BACKENDCONF = str(conf)
    m.SIGNALS = str(tmp_path / "signals.json"); Path(m.SIGNALS).write_text("{}")
    m.INTENTS = str(tmp_path / "intents.json")
    m.PROPOSALS = str(tmp_path / "proposals.jsonl")
    schema = tmp_path / "schema.json"; schema.write_text('{"type": "object"}')
    m.SCHEMA = str(schema)                            # permissive schema -> validation passes
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("SOME_OTHER_SECRET", "should-not-leak")
    assert m.main() == 0
    passed = json.loads(envdump.read_text())
    assert passed.get("ANTHROPIC_API_KEY") == "sk-secret"   # the declared key reaches the backend
    assert "SOME_OTHER_SECRET" not in passed                # nothing else does


# --------------------------------------------------------------------------- C5
def test_flowcheck_no_eval_injection(tmp_path):
    ck = subprocess.run(["sed", "-n", "/^ck(){/,/^}/p", str(SCRIPTS / "flowcheck")],
                        capture_output=True, text=True, check=True).stdout
    lan_dns = subprocess.run(["sed", "-n", "/^_ck_lan_dns()/p", str(SCRIPTS / "flowcheck")],
                             capture_output=True, text=True, check=True).stdout
    assert "ck(){" in ck and "_ck_lan_dns()" in lan_dns
    assert "eval" not in ck                          # the injection vector is gone
    marker = tmp_path / "PWNED"
    driver = textwrap.dedent(f"""
        set -u
        pass=0; fail=0
        ss(){{ echo 'UNCONN 0 0 1.2.3.4:53 0.0.0.0:*'; }}
    """) + ck + lan_dns + textwrap.dedent(f"""
        LAN_IP='1.2.3.4'
        ck "benign" _ck_lan_dns
        LAN_IP='x$(touch {marker})x'      # a metachar payload — must be DATA, never executed
        ck "evil" _ck_lan_dns || true
        [ -f "{marker}" ] && echo INJECTED || echo SAFE
    """)
    out = subprocess.run(["bash", "-c", driver], capture_output=True, text=True).stdout
    assert "SAFE" in out and "INJECTED" not in out
    assert not marker.exists()


# --------------------------------------------------------------------------- C1
def test_recovery_punches_accept_into_main_table(tmp_path):
    # the three helpers are contiguous (resolve -> remove -> ensure); grab the whole block
    fns = subprocess.run(
        ["awk", r'/^resolve_main_table\(\)/{f=1} f{print} /^ensure_main_accept\(\)/{e=1} e&&/^}/{exit}',
         str(SCRIPTS / "bastion-recovery")], capture_output=True, text=True, check=True).stdout
    assert "ensure_main_accept()" in fns and "resolve_main_table()" in fns
    out = tmp_path / "nftcalls"
    driver = textwrap.dedent(f"""
        set -u
        MAIN_TABLE="inet edge"
        RECOVERY_RULE_TAG="bastion-recovery"
        log(){{ :; }}
        nft(){{ echo "nft $*" >> "{out}"; return 0; }}
    """) + fns + "\nensure_main_accept 2222,22\n"
    subprocess.run(["bash", "-c", driver], check=True)
    calls = out.read_text()
    assert "insert rule inet edge input tcp dport" in calls
    assert "bastion-recovery" in calls


# --------------------------------------------------------------------------- C2 / C3
def test_recovery_serializes_start_and_guards_active():
    body = (SCRIPTS / "bastion-recovery").read_text()
    assert "flock -n 9" in body                              # C2: concurrent-start lock
    assert "ALREADY ACTIVE" in body                          # C2: refuse over a live session
    assert "need sshd useradd chpasswd nft ss flock" in body  # flock preflighted


def test_recovery_otp_is_console_only():
    body = (SCRIPTS / "bastion-recovery").read_text()
    assert 'announce "  one-time pass' in body               # C3: OTP via announce (stderr only)
    assert 'log "  one-time pass' not in body                # never via logger -> journal
