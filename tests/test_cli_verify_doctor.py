"""B3 `bastion verify` (drift detection) + D2 `bastion doctor` (triage).

verify/doctor compare generated configs to disk, so the tests stage a real tree with
`bastion generate` (under --root) and then read it back. doctor's binary/unit probes hit the
real host, so a small System subclass pins `nft` present + a controlled config for determinism.

The `--json` cases (E8) pin the machine-readable projections the GUI consumes.
"""
import argparse
import json
import subprocess
from pathlib import Path

from bastion import cli, state
from bastion.layers.base import Context

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _stage(tmp_path: Path) -> Path:
    """Render the full-edge example config tree under tmp_path (configs only, like generate)."""
    ns = argparse.Namespace(conf=str(EXAMPLE), templates=None, out=str(tmp_path), check=False)
    assert cli.cmd_generate(ns) == 0
    return tmp_path


# --- B3: verify -----------------------------------------------------------
def test_verify_clean_after_generate(tmp_path, capsys):
    _stage(tmp_path)
    args = cli.build_parser().parse_args(["verify", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    assert cli.cmd_verify(args) == 0
    assert "no drift" in capsys.readouterr().out


def test_verify_detects_drift(tmp_path, capsys):
    _stage(tmp_path)
    (tmp_path / "etc" / "nftables.conf").write_text("# hand-edited\n")
    args = cli.build_parser().parse_args(["verify", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    assert cli.cmd_verify(args) == 1
    out = capsys.readouterr().out
    assert "DRIFTED" in out and "/etc/nftables.conf" in out


def test_verify_detects_missing(tmp_path, capsys):
    _stage(tmp_path)
    (tmp_path / "etc" / "bastion" / "machine.env").unlink()
    args = cli.build_parser().parse_args(["verify", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    assert cli.cmd_verify(args) == 1
    assert "MISSING" in capsys.readouterr().out


def test_verify_json_clean(tmp_path, capsys):
    _stage(tmp_path)
    capsys.readouterr()                       # drop the `generate` chatter so only JSON remains
    args = cli.build_parser().parse_args(
        ["verify", "--json", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    assert cli.cmd_verify(args) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["clean"] is True and doc["drift"]["issues"] == [] and doc["drift"]["ok"] > 0


def test_verify_json_reports_drift(tmp_path, capsys):
    _stage(tmp_path)
    (tmp_path / "etc" / "nftables.conf").write_text("# hand-edited\n")
    capsys.readouterr()                       # drop the `generate` chatter so only JSON remains
    args = cli.build_parser().parse_args(
        ["verify", "--json", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    assert cli.cmd_verify(args) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["clean"] is False
    assert {"dest": "/etc/nftables.conf", "status": "DRIFTED"} in doc["drift"]["issues"]


def test_verify_no_conf_errors(monkeypatch, capsys):
    # build_context yields an empty config when no machine.conf exists.
    ctx = Context(system=cli.System(root=Path("/nope")), config={}, templates_dir=TEMPLATES,
                  scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)
    args = cli.build_parser().parse_args(["verify"])
    assert cli.cmd_verify(args) == 1
    assert "no machine.conf" in capsys.readouterr().err


# --- D2: doctor -----------------------------------------------------------
class DoctorSystem(cli.System):
    """Pins `nft` present so doctor doesn't FAIL on a box without nftables; everything else
    (file existence/reads, is_live=False under --root) uses the real staged tree."""
    def command_exists(self, name: str) -> bool:
        return name == "nft"


def _doctor_ctx(monkeypatch, root, config):
    sys_ = DoctorSystem(root=root)
    ctx = Context(system=sys_, config=config, templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)
    return ctx


def test_doctor_ok_on_clean_stage(monkeypatch, tmp_path, capsys):
    _stage(tmp_path)
    _doctor_ctx(monkeypatch, tmp_path, state.load_conf(EXAMPLE))
    args = cli.build_parser().parse_args(["doctor"])
    assert cli.cmd_doctor(args) == 0          # no FAIL (recovery WARN is fine — scripts not staged)
    out = capsys.readouterr().out
    assert "config drift" in out and "0 fail" in out


def test_doctor_warns_on_drift(monkeypatch, tmp_path, capsys):
    _stage(tmp_path)
    (tmp_path / "etc" / "nftables.conf").write_text("garbage\n")
    _doctor_ctx(monkeypatch, tmp_path, state.load_conf(EXAMPLE))
    args = cli.build_parser().parse_args(["doctor"])
    assert cli.cmd_doctor(args) == 0          # drift is a WARN, not a FAIL
    assert "config drift — 1 file" in capsys.readouterr().out


def test_doctor_fails_without_machine_conf(monkeypatch, tmp_path):
    _doctor_ctx(monkeypatch, tmp_path, {})    # no machine.conf -> FAIL
    args = cli.build_parser().parse_args(["doctor"])
    assert cli.cmd_doctor(args) == 1


def test_doctor_fails_without_nft(monkeypatch, tmp_path, capsys):
    _stage(tmp_path)
    sys_ = cli.System(root=tmp_path)          # real command_exists; force nft absent
    monkeypatch.setattr(sys_, "command_exists", lambda name: False)
    ctx = Context(system=sys_, config=state.load_conf(EXAMPLE), templates_dir=TEMPLATES,
                  scripts_dir=SCRIPTS)
    monkeypatch.setattr(cli, "build_context", lambda args: ctx)
    args = cli.build_parser().parse_args(["doctor"])
    assert cli.cmd_doctor(args) == 1
    assert "nft binary" in capsys.readouterr().out


def test_doctor_json_structured(monkeypatch, tmp_path, capsys):
    _stage(tmp_path)
    _doctor_ctx(monkeypatch, tmp_path, state.load_conf(EXAMPLE))
    capsys.readouterr()                       # drop the `generate` chatter so only JSON remains
    args = cli.build_parser().parse_args(["doctor", "--json"])
    assert cli.cmd_doctor(args) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["fail"] == 0
    names = {c["name"]: c["level"] for c in doc["checks"]}
    assert names["machine.conf"] == "OK" and "config drift" in names


def test_doctor_json_fail_without_machine_conf(monkeypatch, tmp_path, capsys):
    _doctor_ctx(monkeypatch, tmp_path, {})
    args = cli.build_parser().parse_args(["doctor", "--json"])
    assert cli.cmd_doctor(args) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["fail"] >= 1
    assert any(c["name"] == "machine.conf" and c["level"] == "FAIL" for c in doc["checks"])


# --- E8: status --json (the status projection of the world-state document) ----
def test_status_json_projection(tmp_path, capsys):
    # Pin --conf so the projection is hermetic — without it, find_conf falls through to a real
    # /etc/bastion/machine.conf on a host that has bastion installed (endpoint), not the example.
    rc = cli.main(["status", "--json", "--conf", str(EXAMPLE), "--root", str(tmp_path)])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema_version"] == 2 and doc["mode"] == "edge"
    assert isinstance(doc["layers"], list) and len(doc["layers"]) == 7
    assert "firewall" in doc and "loaded" in doc["firewall"]
    # the projection is exactly the status-scoped keys — no AI/audit/recovery noise
    assert set(doc) == {"schema_version", "mode", "root", "table", "firewall", "layers"}


# --- H6: live-kernel-vs-rendered-file staleness (doctor "ruleset current") ----
import pytest
from bastion.layers.base import Context as _Ctx


def _netns_available() -> bool:
    try:
        r = subprocess.run(["unshare", "-rn", "nft", "list", "ruleset"],
                           capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


_HAS_NETNS = _netns_available()


def test_normalize_strips_volatile_counter_recovery():
    dump = (
        "table inet bastion {\n"
        "\tset blk_feed {\n\t\ttype ipv4_addr\n\t\tflags interval,timeout\n"
        "\t\telements = { 10.0.0.0/8,\n\t\t             172.16.0.0/12 }\n\t}\n"
        "\tset trusted_hosts {\n\t\ttype ipv4_addr\n\t\telements = { 192.168.9.9 }\n\t}\n"
        "\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n"
        "\t\tct state established,related accept\n"
        "\t\ttcp dport 22 accept counter packets 5 bytes 300\n"
        "\t\ttcp dport { 22 } accept comment \"bastion-recovery\"\n"
        "\t\tudp dport 51820 accept\n\t}\n}")
    norm = cli._normalize_table_dump(dump)
    assert "10.0.0.0/8" not in norm and "172.16.0.0/12" not in norm   # volatile set elements gone
    assert "192.168.9.9" in norm                                       # trusted_hosts kept
    assert "counter packets" not in norm and "tcp dport 22 accept" in norm  # counter stripped, rule kept
    assert "bastion-recovery" not in norm                              # recovery punch stripped
    assert "udp dport 51820 accept" in norm                            # real rule kept


def test_normalize_detects_missing_rule():
    good = ("chain input {\n\t\tct state established,related accept\n"
            "\t\tudp dport 51820 accept\n\t\ttcp dport 1111 accept\n}")
    stale = good.replace("\t\tudp dport 51820 accept\n", "")
    assert cli._normalize_table_dump(good) != cli._normalize_table_dump(stale)


def test_split_table_dumps():
    marked = "@@ inet edge\ntable inet edge {\n\tx\n}\n@@ ip edge_nat\ntable ip edge_nat {\n\ty\n}"
    d = cli._split_table_dumps(marked)
    assert set(d) == {("inet", "edge"), ("ip", "edge_nat")}
    assert "x" in d[("inet", "edge")] and "y" in d[("ip", "edge_nat")]


class _LiveFake(cli.System):
    """A System that reports live+root and serves canned nft/unshare output, so _ruleset_stale's
    orchestration + gating are exercised without a real kernel (the honest kernel check is the
    unshare test below)."""
    @property
    def is_live(self): return True
    @property
    def is_root(self): return True

    def path(self, p):
        return self._conf if str(p) == "/etc/nftables.conf" else super().path(p)

    def run(self, *args, capture=True, input=None):
        if args[0] == "unshare":
            return subprocess.CompletedProcess(args, self._exp_rc, self._expected, "")
        if args[:3] == ("nft", "list", "table"):
            key = (args[3], args[4])
            txt = self._live.get(key)
            return subprocess.CompletedProcess(args, 0 if txt is not None else 1, txt or "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def _mk_livefake(tmp_path, expected, live, exp_rc=0):
    conf = tmp_path / "nftables.conf"
    conf.write_text("# stub\n")
    s = _LiveFake(root=Path("/"))
    s._conf, s._expected, s._live, s._exp_rc = conf, expected, live, exp_rc
    return _Ctx(system=s, config={"machine": {"mode": "endpoint"}}, templates_dir=TEMPLATES,
                scripts_dir=SCRIPTS)


def test_ruleset_stale_true_when_kernel_missing_rule(tmp_path):
    exp = "@@ inet bastion\ntable inet bastion {\n\tchain input {\n\t\tudp dport 51820 accept\n\t}\n}"
    live = {("inet", "bastion"): "table inet bastion {\n\tchain input {\n\t}\n}"}  # accept missing
    ctx = _mk_livefake(tmp_path, exp, live)
    assert cli._ruleset_stale(ctx) == (True, "inet bastion")


def test_ruleset_stale_false_when_in_sync(tmp_path):
    body = "table inet bastion {\n\tchain input {\n\t\tudp dport 51820 accept\n\t}\n}"
    ctx = _mk_livefake(tmp_path, "@@ inet bastion\n" + body, {("inet", "bastion"): body})
    assert cli._ruleset_stale(ctx) == (False, "")


def test_ruleset_stale_none_when_unshare_unavailable(tmp_path):
    # exp_rc != 0 models a hardened kernel with no userns/netns -> unknown, never a false STALE.
    ctx = _mk_livefake(tmp_path, "", {("inet", "bastion"): "x"}, exp_rc=1)
    assert cli._ruleset_stale(ctx) is None


def test_ruleset_stale_none_when_not_live(tmp_path):
    # staged --root tree (is_live False) must skip the live-kernel probe entirely.
    _stage(tmp_path)
    ctx = _Ctx(system=cli.System(root=tmp_path), config=state.load_conf(EXAMPLE),
               templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    assert cli._ruleset_stale(ctx) is None


def test_doctor_omits_ruleset_row_under_root(monkeypatch, tmp_path, capsys):
    # Regression: the new row is gated on is_live, so a staged doctor run must not emit it.
    _stage(tmp_path)
    _doctor_ctx(monkeypatch, tmp_path, state.load_conf(EXAMPLE))
    cli.cmd_doctor(cli.build_parser().parse_args(["doctor"]))
    assert "ruleset current" not in capsys.readouterr().out


@pytest.mark.skipif(not _HAS_NETNS, reason="needs working unshare -rn + nft (userns/netns)")
def test_ruleset_stale_real_kernel_differential(tmp_path):
    """Honest anchor: prove differential canonicalization against REAL nft output — identical
    content normalizes equal (even with a volatile set filled live), a missing rule differs."""
    def dump(text):
        r = subprocess.run(["unshare", "-rn", "bash", "-c", "nft -f - >/dev/null 2>&1 && "
                            "nft list table inet bastion"], input=text, text=True, capture_output=True)
        assert r.returncode == 0, r.stderr
        return r.stdout

    base = ("table inet bastion {{\n"
            "  set blk_feed {{ type ipv4_addr; flags interval,timeout; {feed} }}\n"
            "  set trusted_hosts {{ type ipv4_addr; flags interval; elements = {{ 192.168.9.9 }} }}\n"
            "  chain input {{ type filter hook input priority 0; policy drop;\n"
            "    ct state established,related accept\n{wg}"
            "    tcp dport 1111 accept\n  }}\n}}\n")
    expected = dump(base.format(feed="", wg="    udp dport 51820 accept\n"))              # ships empty
    live_ok  = dump(base.format(feed="elements = { 10.0.0.0/8 }",                          # feed FILLED live
                                wg="    udp dport 51820 accept\n"))
    live_bad = dump(base.format(feed="", wg=""))                                           # wg accept MISSING

    n = cli._normalize_table_dump
    assert n(expected) == n(live_ok)      # volatile-set fill does NOT trip a false STALE
    assert n(expected) != n(live_bad)     # a genuinely missing rule IS caught
    assert "192.168.9.9" in n(live_ok)    # trusted_hosts survived normalization on real nft output
