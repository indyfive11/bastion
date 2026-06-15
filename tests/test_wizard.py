"""Setup wizard (Phase 5 / wizard.py).

`build_machine_conf` is exercised pure; the full `Wizard.run()` is driven non-interactively
(assume_defaults=True) against a fake System so the §10 flow + dry-run preview are covered with
no host access and no writes.
"""
import subprocess
from pathlib import Path

import pytest

from bastion import state, templates
from bastion.setup import detect, wizard
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"

LINK = ("2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT\n"
        "3: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT\n")
ADDR = ("2: enp3s0    inet 192.168.1.10/24 scope global enp3s0\n"
        "3: enp4s0    inet 10.0.1.1/24 scope global enp4s0\n")
ROUTE = "default via 192.168.1.1 dev enp3s0 proto dhcp\n"


class FakeSystem(System):
    def __init__(self, cmds, files, have, *, live=False):
        super().__init__()
        self._cmds, self._files, self._have, self._live = cmds, files, have, live

    @property
    def is_live(self):
        return self._live

    def run(self, *args, capture=True):
        out = self._cmds.get(args, "")
        return subprocess.CompletedProcess(args, 0 if args in self._cmds else 1, out, "")

    def read(self, p):
        return self._files.get(str(p), "")

    def exists(self, p):
        return str(p) in self._files

    def command_exists(self, name):
        return name in self._have

    def unit_active(self, unit):
        return unit in self._have


def edge_system(live=False):
    cmds = {
        ("ip", "-o", "link", "show"): LINK,
        ("ip", "-o", "-4", "addr", "show"): ADDR,
        ("ip", "route", "show", "default"): ROUTE,
        ("sshd", "-T"): "port 1122\n",
    }
    files = {"/etc/os-release": "ID=arch\n"}
    have = {"pacman", "nft", "nftables.service"}
    return FakeSystem(cmds, files, have, live=live)


# --- pure build_machine_conf ----------------------------------------------

def test_profile_layers_table():
    assert wizard.PROFILE_LAYERS["full-edge"] == "l0,l1,l2,l3,l4,l5,l6"
    assert wizard.PROFILE_LAYERS["minimal-endpoint"] == "l0,l1,l6"
    assert wizard.profile_mode("basic-edge") == "edge"
    assert wizard.profile_mode("full-endpoint") == "endpoint"
    assert wizard.profile_mode("custom") is None


def test_build_machine_conf_edge_overlays_detection():
    base = state.load_conf(EXAMPLE)
    d = detect.detect(edge_system())
    conf = wizard.build_machine_conf(d, "full-edge", {}, base)
    assert conf["machine"]["mode"] == "edge"
    assert conf["machine"]["profile"] == "full-edge"
    assert conf["machine"]["layers"] == "l0,l1,l2,l3,l4,l5,l6"
    assert conf["machine"]["distro"] == "arch"
    assert conf["interfaces"]["wan"] == "enp3s0"
    assert conf["interfaces"]["lan"] == "enp4s0"
    assert conf["network"]["lan_ip"] == "10.0.1.1"
    assert conf["network"]["lan_cidr"] == "10.0.1.0/24"
    assert conf["network"]["gateway"] == "192.168.1.1"
    assert conf["ports"]["ssh"] == "1122"


def test_derive_dhcp_pool():
    # /24 -> familiar .100–.249 window, inside the subnet.
    assert wizard.derive_dhcp_pool("192.168.50.0/24") == ("192.168.50.100", "192.168.50.249")
    # an off-base CIDR still derives within the right network.
    assert wizard.derive_dhcp_pool("10.20.30.0/24") == ("10.20.30.100", "10.20.30.249")
    # small subnet: upper half, never outside the range.
    lo, hi = wizard.derive_dhcp_pool("192.168.9.0/28")
    import ipaddress
    net = ipaddress.ip_network("192.168.9.0/28")
    assert ipaddress.ip_address(lo) in net and ipaddress.ip_address(hi) in net
    # unparseable / blank -> no derivation (caller keeps skeleton default).
    assert wizard.derive_dhcp_pool("") == (None, None)
    assert wizard.derive_dhcp_pool(None) == (None, None)


def test_build_machine_conf_dhcp_pool_tracks_lan_cidr():
    # The gap fix: a user-supplied LAN subnet must drag the DHCP pool with it (not leave the
    # skeleton's 10.0.1.x, which would be outside the LAN).
    base = state.load_conf(EXAMPLE)
    d = detect.detect(edge_system())
    conf = wizard.build_machine_conf(d, "full-edge", {"lan_cidr": "192.168.50.0/24"}, base)
    assert conf["network"]["lan_cidr"] == "192.168.50.0/24"
    assert conf["network"]["dhcp_range_start"] == "192.168.50.100"
    assert conf["network"]["dhcp_range_end"] == "192.168.50.249"
    import ipaddress
    net = ipaddress.ip_network("192.168.50.0/24")
    assert ipaddress.ip_address(conf["network"]["dhcp_range_start"]) in net


def test_build_machine_conf_dhcp_answers_override_derivation():
    base = state.load_conf(EXAMPLE)
    d = detect.detect(edge_system())
    conf = wizard.build_machine_conf(
        d, "full-edge",
        {"lan_cidr": "192.168.50.0/24", "dhcp_range_start": "192.168.50.50",
         "dhcp_range_end": "192.168.50.60"}, base)
    assert conf["network"]["dhcp_range_start"] == "192.168.50.50"
    assert conf["network"]["dhcp_range_end"] == "192.168.50.60"


def test_build_machine_conf_answers_win():
    base = state.load_conf(EXAMPLE)
    d = detect.detect(edge_system())
    conf = wizard.build_machine_conf(
        d, "full-edge", {"ssh_port": "2200", "trusted_hosts": "10.9.9.9", "lan_iface": "br0"}, base)
    assert conf["ports"]["ssh"] == "2200"
    assert conf["network"]["trusted_hosts"] == "10.9.9.9"
    assert conf["interfaces"]["lan"] == "br0"


def test_build_machine_conf_endpoint_blanks_wan():
    base = state.load_conf(EXAMPLE)
    one = FakeSystem({("ip", "-o", "link", "show"):
                      "2: enp3s0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP mode DEFAULT\n",
                      ("ip", "-o", "-4", "addr", "show"): ADDR,
                      ("sshd", "-T"): "port 22\n"},
                     {"/etc/os-release": "ID=debian\n"}, {"apt-get"})
    d = detect.detect(one)
    conf = wizard.build_machine_conf(d, "full-endpoint", {}, base)
    assert conf["machine"]["mode"] == "endpoint"
    assert conf["machine"]["layers"] == "l0,l1,l2,l3,l6"
    assert conf["interfaces"]["wan"] == ""


def test_build_machine_conf_resolves_all_templates():
    # The whole point of overlaying onto the example skeleton: generate has no unresolved keys.
    base = state.load_conf(EXAMPLE)
    d = detect.detect(edge_system())
    conf = wizard.build_machine_conf(d, "full-edge", {}, base)
    for tmpl in (REPO / "bastion" / "templates").rglob("*"):
        if tmpl.is_file():
            assert templates.check_file(tmpl, conf) == [], f"{tmpl} unresolved"


# --- full wizard run (non-interactive dry-run) ----------------------------

def test_wizard_writes_confirmed_mode_over_detection():
    # Regression: detection proposes edge (2 NICs + default route), but --profile minimal-endpoint
    # confirms endpoint. The WRITTEN conf must honour the confirmed mode, not fall back to
    # detection's proposed_mode.
    wiz = wizard.Wizard(edge_system(), dry_run=True, profile="minimal-endpoint",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    result = wiz.run()
    assert result.mode == "endpoint"
    assert result.config["machine"]["mode"] == "endpoint"
    assert result.config["interfaces"]["wan"] == ""   # endpoint blanks WAN


def test_wizard_dry_run_edge(capsys):
    wiz = wizard.Wizard(edge_system(), dry_run=True, profile="full-edge",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    result = wiz.run()
    assert result.dry_run and result.mode == "edge" and result.profile == "full-edge"
    assert result.config["network"]["lan_ip"] == "10.0.1.1"
    # edge writes the nft edge ruleset + dnsmasq + machine.conf/env among others
    assert "/etc/nftables.conf" in result.written
    assert "/etc/dnsmasq.conf" in result.written
    assert "/etc/bastion/machine.conf" in result.written
    # full-edge needs L1–L6 packages; crowdsec is one of them
    assert "crowdsec" in result.install_plan
    out = capsys.readouterr().out
    assert "DRY RUN" in out


def test_wizard_dry_run_endpoint_skips_edge_only_outputs():
    sysd = FakeSystem({("ip", "-o", "link", "show"):
                       "2: enp3s0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP mode DEFAULT\n",
                       ("ip", "-o", "-4", "addr", "show"): ADDR,
                       ("ip", "route", "show", "default"): ROUTE,
                       ("sshd", "-T"): "port 22\n"},
                      {"/etc/os-release": "ID=arch\n"}, {"pacman"})
    wiz = wizard.Wizard(sysd, dry_run=True, profile="minimal-endpoint",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    result = wiz.run()
    assert result.mode == "endpoint"
    # endpoint nft template -> /etc/nftables.conf, but NO dnsmasq (L4 is edge-only)
    assert "/etc/nftables.conf" in result.written
    assert "/etc/dnsmasq.conf" not in result.written


def test_wizard_explicit_endpoint_profile_drives_mode(capsys):
    # edge topology proposed, but an explicit endpoint --profile seeds endpoint mode (user intent);
    # the profile is honoured, not silently downgraded.
    wiz = wizard.Wizard(edge_system(), dry_run=True, profile="minimal-endpoint",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    result = wiz.run()
    assert result.mode == "endpoint" and result.profile == "minimal-endpoint"
    assert result.config["machine"]["layers"] == "l0,l1,l6"
    assert "/etc/dnsmasq.conf" not in result.written
    out = capsys.readouterr().out
    assert "detection proposed edge" in out and "implies endpoint" in out


def test_wizard_dry_run_writes_nothing(tmp_path, capsys):
    # Sanity: a dry run must not create any file under a redirected root.
    sysd = edge_system()
    sysd.root = tmp_path
    wiz = wizard.Wizard(sysd, dry_run=True, profile="full-edge",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    wiz.run()
    assert list(tmp_path.rglob("*")) == []


def test_wizard_live_apply_writes_conf_and_generates(tmp_path):
    # Non-dry-run step 6 (§10): the wizard SERIALIZES its own built config to machine.conf and
    # runs generate — no hand-authored conf. Staged under a temp root so the test stays offline.
    sysd = edge_system(live=False)
    sysd.root = tmp_path
    wiz = wizard.Wizard(sysd, dry_run=False, profile="full-edge",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    result = wiz.run()
    assert not result.dry_run
    # machine.conf written, loadable, and carries the detected values (round-trip).
    conf = tmp_path / "etc/bastion/machine.conf"
    assert conf.is_file()
    loaded = state.load_conf(conf)
    assert loaded["machine"]["mode"] == "edge"
    assert loaded["interfaces"]["wan"] == "enp3s0"
    assert loaded["network"]["lan_cidr"] == "10.0.1.0/24"
    # generate rendered the active-layer configs + machine.env under the staged root.
    assert (tmp_path / "etc/nftables.conf").is_file()
    assert (tmp_path / "etc/bastion/machine.env").is_file()
    assert (tmp_path / "etc/dnsmasq.conf").is_file()          # L4 active in full-edge
    # the rendered ruleset has no leftover placeholders.
    body = (tmp_path / "etc/nftables.conf").read_text()
    assert templates.find_placeholders(body) == set()


# --- live full orchestration (step 7 install + step 8 verify) -------------

class _StubLayer:
    """Records install() without touching the real system (nft/systemd/files). Delegates
    owned_templates to the real layer so step-6 generate (which also goes through layers.get)
    still resolves the active-layer template set."""
    def __init__(self, lid, calls, real=None):
        self.name, self.packages, self._lid, self._calls = lid, (f"{lid}-pkg",), lid, calls
        self._real = real

    def install(self, ctx):
        self._calls.append(self._lid)

    def owned_templates(self, mode):
        return self._real.owned_templates(mode) if self._real else set()


class _FakeMgr:
    name = "fakepkg"

    def __init__(self):
        self.installed = None

    def install(self, sysd, pkgs):
        from bastion.setup.pkg import InstallResult
        self.installed = list(pkgs)
        return InstallResult(command=["fakepkg", "-S", *pkgs], ran=True, returncode=0,
                             missing=list(pkgs))

    def install_command(self, pkgs):
        return ["fakepkg", "-S", *pkgs]

    def unavailable_hint(self, pkgs):
        return "n/a"


class _LiveFake(FakeSystem):
    """is_live=True but writes stay under a temp root; flowcheck rc is injectable."""
    def __init__(self, tmp_path, *, flowcheck_rc=0, has_flowcheck=True):
        cmds = {("ip", "-o", "link", "show"): LINK,
                ("ip", "-o", "-4", "addr", "show"): ADDR,
                ("ip", "route", "show", "default"): ROUTE,
                ("sshd", "-T"): "port 22\n"}
        files = {"/etc/os-release": "ID=arch\n"}
        if has_flowcheck:
            files["/usr/local/sbin/flowcheck"] = ""
        super().__init__(cmds, files, {"pacman", "nft", "nftables.service"}, live=True)
        self.root = tmp_path
        self._flowcheck_rc = flowcheck_rc

    def run(self, *args, capture=True):
        if args and str(args[0]).endswith("/flowcheck"):
            return subprocess.CompletedProcess(args, self._flowcheck_rc, "", "")
        return super().run(*args, capture=capture)


def _patch_orchestration(monkeypatch):
    """Stub the package manager + layer registry so the live path is exercised without installing
    anything or loading real nft rules. Returns (mgr, layer_install_calls)."""
    import bastion.layers as layermod
    from bastion.setup import pkg as pkgmod
    real = dict(layermod.REGISTRY)
    calls: list[str] = []
    mgr = _FakeMgr()
    monkeypatch.setattr(pkgmod, "detect_manager", lambda sysd, distro=None: mgr)
    monkeypatch.setattr(layermod, "get", lambda lid: _StubLayer(lid, calls, real.get(lid)))
    return mgr, calls


def test_wizard_live_orchestration_installs_and_verifies(tmp_path, monkeypatch, capsys):
    # A real live root install (is_live=True): step 7 batch-installs every active-layer package
    # then runs each layer's install() in order; step 8 runs `bastion check` (flowcheck) and,
    # since rc=0, reports all-pass. Writes are contained under tmp_path.
    mgr, calls = _patch_orchestration(monkeypatch)
    sysd = _LiveFake(tmp_path)
    wiz = wizard.Wizard(sysd, dry_run=False, profile="minimal-endpoint",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    result = wiz.run()
    # step 7: all active-layer packages handed to the manager once, layers installed in order.
    assert mgr.installed == ["l0-pkg", "l1-pkg", "l6-pkg"]
    assert calls == ["l0", "l1", "l6"]
    assert result.install_plan == ["l0-pkg", "l1-pkg", "l6-pkg"]
    # step 8: flowcheck ran and passed.
    out = capsys.readouterr().out
    assert "running bastion check" in out and "all flows pass" in out
    # machine.conf still written under the staged root (step 6 unchanged).
    assert (tmp_path / "etc/bastion/machine.conf").is_file()


def test_wizard_live_verify_flags_failed_check(tmp_path, monkeypatch, capsys):
    # When flowcheck fails (rc!=0), step 8 surfaces it and records a note (operator-visible).
    _patch_orchestration(monkeypatch)
    sysd = _LiveFake(tmp_path, flowcheck_rc=1)
    wiz = wizard.Wizard(sysd, dry_run=False, profile="minimal-endpoint",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    result = wiz.run()
    assert any("bastion check reported failures" in n for n in result.notes)
    assert "FAILED" in capsys.readouterr().out


def test_wizard_staged_root_stays_preview(tmp_path, monkeypatch, capsys):
    # --root staging (not is_live) must NOT install packages or run layers — preview only.
    mgr, calls = _patch_orchestration(monkeypatch)
    sysd = edge_system(live=False)
    sysd.root = tmp_path
    wiz = wizard.Wizard(sysd, dry_run=False, profile="full-edge",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    wiz.run()
    assert mgr.installed is None and calls == []
    assert "install command (preview)" in capsys.readouterr().out


def test_generate_apply_aborts_on_incomplete_conf(tmp_path, capsys):
    # The defensive guard: if a config can't resolve every template, step 6 ABORTS before writing
    # — never a half-resolved machine.conf on disk. (Normal flow can't trigger this because the
    # example-skeleton overlay backfills every key; exercise the guard directly with a bare conf.)
    sysd = edge_system(live=False)
    sysd.root = tmp_path
    wiz = wizard.Wizard(sysd, dry_run=False, profile="full-edge",
                        assume_defaults=True, example_conf=str(EXAMPLE))
    incomplete = {"machine": {"mode": "edge", "layers": "l0,l1,l2,l3,l4,l5,l6"}}
    written, notes = wiz._generate_apply(incomplete, "edge")
    assert written == []
    assert any("aborted" in n for n in notes)
    assert not (tmp_path / "etc/bastion/machine.conf").exists()
    assert "ABORT" in capsys.readouterr().out
