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
