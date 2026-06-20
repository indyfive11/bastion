"""L2 crowdsec layer (Phase 4 / L2 gate).

L2 owns no bastion files — it manages the distro-packaged crowdsec.service and reuses the L1
reconciler as the bouncer. Its live checks (cscli present, unit active) query the real host
regardless of --root, so the deterministic tests assert the structural invariants; health_check
correctness against a running agent is validated separately on ES (the reference machine).
"""
from pathlib import Path

from bastion import layers
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict) -> Context:
    return Context(system=System(root=root, dry_run=True), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l2_in_registry():
    l2 = layers.get("l2")
    assert "l2" in layers.REGISTRY
    assert l2.title == "crowdsec"
    assert l2.prerequisites == ("l0", "l1")


def test_l2_owns_no_bastion_files():
    # Commandment #7: no second nft writer. L2 installs no script/unit/template — the L1
    # reconciler is the sole bouncer. This invariant guards against a firewall-bouncer creeping in.
    l2 = layers.get("l2")
    assert l2.scripts == ()
    assert l2.units == ()
    assert l2.template_dests == ()


def test_l2_staged_install_writes_nothing(tmp_path):
    # A non-live install only manages the system crowdsec.service; it must not touch the tree.
    layers.get("l2").install(_ctx(tmp_path, {}))
    assert not any(tmp_path.iterdir())


def test_l2_table_selection_by_mode():
    l2 = layers.get("l2")
    assert l2._table(_ctx(Path("/"), {"machine": {"mode": "edge"}})) == ("inet", "edge")
    assert l2._table(_ctx(Path("/"), {"machine": {"mode": "endpoint"}})) == ("inet", "bastion")


# --- live install: accurate reporting (polish items 1 & 2) ----------------

import subprocess


class _LiveSys(System):
    """A live-claiming System for L2's install branch: scripts cscli presence + ss output and
    records every run() so we can assert whether crowdsec.service was (not) enabled."""
    def __init__(self, root, *, have_cscli: bool, ss_text: str = "", enable_rc: int = 0):
        super().__init__(root=root)
        self._have_cscli = have_cscli
        self._ss_text = ss_text
        self._enable_rc = enable_rc
        self.calls = []

    @property
    def is_live(self) -> bool:
        return True

    def command_exists(self, name: str) -> bool:
        return name == "cscli" and self._have_cscli

    def run(self, *args, **kwargs):
        self.calls.append(tuple(args))
        if args[:2] == ("ss", "-ltnH"):
            return subprocess.CompletedProcess(args, 0, self._ss_text, "")
        if args[:3] == ("systemctl", "enable", "--now"):
            return subprocess.CompletedProcess(args, self._enable_rc, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def _live_ctx(sysobj):
    return Context(system=sysobj, config={"machine": {"mode": "edge"}},
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l2_install_absent_package_does_not_enable_or_claim_success(capsys):
    # Polish #1: with crowdsec absent the unit doesn't exist — don't run enable --now and don't
    # print the old "enabled + started" success line.
    sysobj = _LiveSys(Path("/"), have_cscli=False)
    layers.get("l2").install(_live_ctx(sysobj))
    assert not any(c[:2] == ("systemctl", "enable") for c in sysobj.calls)
    out = capsys.readouterr().out
    assert "enabled + started" not in out
    assert "crowdsec package absent" in out


def test_l2_install_present_package_enables_and_reports(capsys):
    sysobj = _LiveSys(Path("/"), have_cscli=True, ss_text="")
    layers.get("l2").install(_live_ctx(sysobj))
    assert ("systemctl", "enable", "--now", "crowdsec.service") in sysobj.calls
    assert "crowdsec.service enabled + started" in capsys.readouterr().out


def test_l2_install_warns_on_busy_lapi_port(capsys):
    # Polish #2: :8080 already listening -> warn about the LAPI clash before starting.
    ss = "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n"
    sysobj = _LiveSys(Path("/"), have_cscli=True, ss_text=ss)
    layers.get("l2").install(_live_ctx(sysobj))
    out = capsys.readouterr().out
    assert "8080 is already in use" in out
    assert "listen_uri" in out
    # a busy port is only a WARNING — install still tries to enable the service
    assert ("systemctl", "enable", "--now", "crowdsec.service") in sysobj.calls


def test_l2_install_warns_when_enable_fails(capsys):
    sysobj = _LiveSys(Path("/"), have_cscli=True, enable_rc=1)
    layers.get("l2").install(_live_ctx(sysobj))
    out = capsys.readouterr().out
    assert "did not succeed" in out
    assert "enabled + started" not in out


def test_port_listening_parses_ss():
    from bastion.layers import l2_crowdsec
    sysobj = _LiveSys(Path("/"), have_cscli=True,
                      ss_text="LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\n")
    assert l2_crowdsec._port_listening(sysobj, 8080) is True
    assert l2_crowdsec._port_listening(sysobj, 9090) is False
