"""L0 core layer + `bastion status` (Phase 3 gate)."""
import subprocess
from pathlib import Path

import pytest

from bastion import cli, layers, state
from bastion.layers.base import Context, FirewallConflict
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict, dry_run=True) -> Context:
    return Context(system=System(root=root, dry_run=dry_run), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l0_in_registry():
    assert "l0" in layers.REGISTRY
    assert layers.get("l0").title == "core"


def test_l0_status_fresh_system_not_installed(tmp_path):
    st = layers.get("l0").status(_ctx(tmp_path, {}))
    assert st.installed is False
    assert "missing" in st.detail


def test_l0_install_then_status_installed(tmp_path):
    config = state.load_conf(EXAMPLE)
    ctx = _ctx(tmp_path, config)
    layers.get("l0").install(ctx)

    # All declared artifacts now exist under the staged root.
    assert (tmp_path / "etc/nftables.conf").is_file()
    assert (tmp_path / "etc/edge-reconciler/policy.allowlist").is_file()
    recovery = tmp_path / "usr/local/sbin/bastion-recovery"
    assert recovery.is_file() and recovery.stat().st_mode & 0o111  # executable
    assert (tmp_path / "etc/systemd/system/bastion-recovery.service").is_file()

    # Rendered ruleset is fully resolved.
    assert "{{" not in (tmp_path / "etc/nftables.conf").read_text()

    st = layers.get("l0").status(ctx)
    assert st.installed is True


def test_l0_endpoint_mode_installs_input_only_ruleset(tmp_path):
    config = state.load_conf(EXAMPLE)
    config["machine"]["mode"] = "endpoint"
    ctx = _ctx(tmp_path, config)
    layers.get("l0").install(ctx)
    body = (tmp_path / "etc/nftables.conf").read_text()
    assert "chain forward" not in body and "edge_nat" not in body


class _FwSys(System):
    """A live-claiming System whose chosen firewall reports active; run/command are stubbed so no
    real systemctl/nft runs. Lets us exercise the L0 live firewall-conflict guard in a test."""
    def __init__(self, root, active_fw=None):
        super().__init__(root=root)
        self._active_fw = active_fw
        self.calls = []

    @property
    def is_live(self) -> bool:
        return True

    def unit_active(self, unit: str) -> bool:
        return unit == self._active_fw

    def command_exists(self, name: str) -> bool:
        return True

    def run(self, *args, **kwargs):
        self.calls.append(tuple(args))
        # Model real enforcement, not just unit-active: the conflict guard now asks the tool itself.
        if args[:2] == ("ufw", "status"):
            body = "Status: active\n" if self._active_fw == "ufw" else "Status: inactive\n"
            return subprocess.CompletedProcess(args, 0, body, "")
        if args[:2] == ("firewall-cmd", "--state"):
            if self._active_fw == "firewalld":
                return subprocess.CompletedProcess(args, 0, "running\n", "")
            return subprocess.CompletedProcess(args, 1, "not running\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def _fw_ctx(root, active_fw):
    return Context(system=_FwSys(root, active_fw=active_fw), config=state.load_conf(EXAMPLE),
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l0_install_aborts_when_ufw_active(tmp_path):
    # bastion's ruleset would `flush ruleset` and wipe ufw — refuse, before touching anything.
    with pytest.raises(FirewallConflict) as exc:
        layers.get("l0").install(_fw_ctx(tmp_path, "ufw"))
    assert exc.value.firewall == "ufw"
    assert not (tmp_path / "etc/nftables.conf").exists()  # guard fired before any render


def test_l0_install_aborts_when_firewalld_active(tmp_path):
    with pytest.raises(FirewallConflict):
        layers.get("l0").install(_fw_ctx(tmp_path, "firewalld"))


def test_l0_install_override_env_allows_takeover(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_ALLOW_FIREWALL_TAKEOVER", "1")
    layers.get("l0").install(_fw_ctx(tmp_path, "ufw"))   # override → no raise
    assert (tmp_path / "etc/nftables.conf").is_file()


def test_l0_install_no_conflict_proceeds(tmp_path):
    layers.get("l0").install(_fw_ctx(tmp_path, None))    # nothing active
    assert (tmp_path / "etc/nftables.conf").is_file()


class _UfwLoadedNotEnforcingSys(_FwSys):
    """ufw's systemd unit is active (RemainAfterExit oneshot) but `ufw status` is inactive — ufw
    enforces nothing and owns no nft table. This must NOT count as a conflict."""
    def unit_active(self, unit: str) -> bool:
        return unit == "ufw"

    def run(self, *args, **kwargs):
        self.calls.append(tuple(args))
        if args[:2] == ("ufw", "status"):
            return subprocess.CompletedProcess(args, 0, "Status: inactive\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def test_loaded_but_inactive_ufw_is_not_a_conflict():
    # The EM case: ufw.service active, `ufw status` inactive. Unit-active alone over-reported it.
    from bastion.layers.base import active_conflicting_firewall
    assert active_conflicting_firewall(_UfwLoadedNotEnforcingSys(Path("/"))) is None


def test_l0_exclusive_install_proceeds_over_loaded_but_inactive_ufw(tmp_path):
    # Even in exclusive scope, a ufw that enforces nothing must not abort the install.
    ctx = Context(system=_UfwLoadedNotEnforcingSys(tmp_path), config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").install(ctx)                        # no FirewallConflict raised
    assert (tmp_path / "etc/nftables.conf").is_file()


def test_l0_cooperative_scope_coexists_with_active_ufw(tmp_path, capsys):
    # In cooperative scope bastion no longer flushes the ruleset, so an active ufw is a WARN, not an
    # abort — the install proceeds and renders the (table-scoped) ruleset. Exclusive still aborts.
    ctx = _fw_ctx(tmp_path, "ufw")
    ctx.config["machine"]["firewall_scope"] = "cooperative"
    layers.get("l0").install(ctx)                        # no FirewallConflict raised
    assert (tmp_path / "etc/nftables.conf").is_file()
    out = capsys.readouterr().out
    assert "ufw" in out and "COOPERATIVE" in out         # coexist warning surfaced
    # and the rendered ruleset uses the table-scoped reset, not a global flush
    assert "flush ruleset" not in (tmp_path / "etc/nftables.conf").read_text()


# --- runtime hard-warn: exclusive scope will flush co-resident tables -----------------------------
from bastion.layers import base as _base


class _NftSys(System):
    """Live+root System whose `nft list tables` returns a scripted listing; other commands rc 0."""
    def __init__(self, root, tables_out=""):
        super().__init__(root=root)
        self._tables_out = tables_out
    @property
    def is_live(self): return True
    @property
    def is_root(self): return True
    def command_exists(self, name): return True
    def unit_active(self, unit): return False            # no conflicting firewall active
    def run(self, *args, **kw):
        if args[:3] == ("nft", "list", "tables"):
            return subprocess.CompletedProcess(args, 0, self._tables_out, "")
        return subprocess.CompletedProcess(args, 0, "", "")


def test_live_foreign_nft_tables_filters_bastions_own():
    out = "table inet bastion\ntable ip libvirt_network\ntable ip edge_nat\ntable ip6 kube_proxy\n"
    foreign = _base.live_foreign_nft_tables(_NftSys(Path("/"), out))
    assert ("ip", "libvirt_network") in foreign and ("ip6", "kube_proxy") in foreign
    assert ("inet", "bastion") not in foreign and ("ip", "edge_nat") not in foreign


def test_warn_if_exclusive_flush_fires_on_foreign_table():
    lines = []
    res = _base.warn_if_exclusive_flush(_NftSys(Path("/"), "table ip libvirt_network\n"),
                                        "exclusive", out=lines.append)
    blob = "\n".join(lines)
    assert ("ip", "libvirt_network") in res
    assert "flush ruleset" in blob and "libvirt_network" in blob and "cooperative" in blob


def test_warn_if_exclusive_flush_silent_in_cooperative_and_when_clean():
    # cooperative never flushes -> no warning even with foreign tables present
    lines = []
    assert _base.warn_if_exclusive_flush(_NftSys(Path("/"), "table ip libvirt_network\n"),
                                         "cooperative", out=lines.append) == []
    assert lines == []
    # exclusive but only bastion's own table -> nothing to warn about
    lines2 = []
    assert _base.warn_if_exclusive_flush(_NftSys(Path("/"), "table inet bastion\n"),
                                         "exclusive", out=lines2.append) == []
    assert lines2 == []


def test_l0_install_warns_when_exclusive_would_flush_foreign(tmp_path, capsys):
    sys_ = _NftSys(tmp_path, "table ip libvirt_network\n")
    cfg = state.load_conf(EXAMPLE); cfg["machine"]["firewall_scope"] = "exclusive"
    layers.get("l0").install(Context(system=sys_, config=cfg, templates_dir=TEMPLATES,
                                     scripts_dir=SCRIPTS))
    out = capsys.readouterr().out
    assert "flush ruleset" in out and "libvirt_network" in out      # the hard-warn fired


def test_l0_install_enables_nftables_for_persistence(tmp_path):
    # The ruleset must survive a reboot: L0 enables nftables.service (persist) and restarts it so
    # the pinned ExecStart loads /etc/nftables.conf NOW, even on a reinstall where the oneshot is
    # already active (`start` would not re-run ExecStart).
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").install(ctx)
    assert ("systemctl", "enable", "nftables") in sysobj.calls
    assert ("systemctl", "restart", "nftables") in sysobj.calls


def test_l0_install_enables_boot_reaper(tmp_path):
    # 0.1: the boot reaper must be enabled so an orphaned rescue surface (rescue user + NOPASSWD
    # sudoers left by a crash mid-recovery) is torn down on the next boot.
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").install(ctx)
    assert ("systemctl", "enable", "bastion-recovery-reap.service") in sysobj.calls
    assert (tmp_path / "etc/systemd/system/bastion-recovery-reap.service").is_file()


# --- G4: edge IP-forwarding sysctl ---------------------------------------------------------------
FORWARD = "etc/sysctl.d/99-bastion-forward.conf"


def test_l0_edge_renders_forward_sysctl(tmp_path):
    # Edge mode must enable kernel forwarding or the forward chain is inert. Default ipv6_forward=yes
    # → v4 + v6 forwarding, and accept_ra=2 pinned on the WAN so v6 forwarding can't strip the box's
    # own uplink address.
    config = state.load_conf(EXAMPLE)
    layers.get("l0").install(_ctx(tmp_path, config))
    body = (tmp_path / FORWARD).read_text()
    assert "net.ipv4.ip_forward = 1" in body
    assert "net.ipv6.conf.all.forwarding = 1" in body
    assert f"net.ipv6.conf.{config['interfaces']['wan']}.accept_ra = 2" in body


def test_l0_ipv6_forward_no_omits_v6(tmp_path):
    config = state.load_conf(EXAMPLE)
    config["network"]["ipv6_forward"] = "no"
    layers.get("l0").install(_ctx(tmp_path, config))
    body = (tmp_path / FORWARD).read_text()
    assert "net.ipv4.ip_forward = 1" in body
    assert "forwarding = 1" not in body.replace("ip_forward = 1", "")   # no v6 forwarding line
    assert "accept_ra" not in body


def test_l0_endpoint_writes_no_forward_sysctl(tmp_path):
    # An endpoint never routes (defense-in-depth) — it must NOT enable forwarding.
    config = state.load_conf(EXAMPLE)
    config["machine"]["mode"] = "endpoint"
    layers.get("l0").install(_ctx(tmp_path, config))
    assert not (tmp_path / FORWARD).exists()


def test_l0_endpoint_removes_stale_forward_sysctl(tmp_path):
    # Converting an edge node to an endpoint must tear down the forwarding drop-in left behind.
    stale = tmp_path / FORWARD
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("net.ipv4.ip_forward = 1\n")
    config = state.load_conf(EXAMPLE)
    config["machine"]["mode"] = "endpoint"
    layers.get("l0").install(_ctx(tmp_path, config))
    assert not stale.exists()


def test_l0_live_applies_forward_sysctl(tmp_path):
    # A live edge install must re-apply sysctls so forwarding takes effect without a reboot.
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").install(ctx)
    assert ("sysctl", "--system") in sysobj.calls


def test_l0_uninstall_removes_forward_sysctl(tmp_path):
    config = state.load_conf(EXAMPLE)
    layers.get("l0").install(_ctx(tmp_path, config))
    assert (tmp_path / FORWARD).exists()
    layers.get("l0").uninstall(_ctx(tmp_path, config))
    assert not (tmp_path / FORWARD).exists()


def test_l0_uninstall_disables_boot_reaper(tmp_path):
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").install(ctx)
    layers.get("l0").uninstall(ctx)
    assert ("systemctl", "disable", "--now", "bastion-recovery-reap.service") in sysobj.calls
    assert not (tmp_path / "etc/systemd/system/bastion-recovery-reap.service").exists()


def test_l0_install_pins_nftables_loader_path(tmp_path):
    # Cross-distro fix: a systemd drop-in pins nftables.service to load /etc/nftables.conf, so the
    # ruleset loads on Fedora/RHEL too (their stock unit reads /etc/sysconfig/nftables.conf).
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").install(ctx)
    drop = tmp_path / "etc/systemd/system/nftables.service.d/10-bastion-load.conf"
    assert drop.is_file()
    body = drop.read_text()
    assert "ExecStart=\n" in body                       # reset before re-setting (systemd idiom)
    assert "-f /etc/nftables.conf" in body
    # The drop-in re-asserts oneshot+RemainAfterExit so the unit reads `active (exited)` after a
    # successful load (not `inactive`) on any distro base unit — `is-active` then reflects reality.
    assert "Type=oneshot\n" in body
    assert "RemainAfterExit=yes\n" in body
    # ...and clears any distro ExecStop (some ship `nft flush ruleset`): with RemainAfterExit=yes a
    # stop/restart would otherwise flush every table, wiping a co-resident manager's under cooperative.
    assert "ExecStop=\n" in body


def test_l0_uninstall_removes_loader_dropin(tmp_path):
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").install(ctx)
    drop = tmp_path / "etc/systemd/system/nftables.service.d/10-bastion-load.conf"
    assert drop.is_file()
    layers.get("l0").uninstall(ctx)
    assert not drop.exists()


def test_l0_uninstall_disables_nftables_only_if_bastion_enabled_it(tmp_path):
    # F12: uninstall disables nftables.service ONLY when bastion enabled it (marker present), so a box
    # that already used the nft loader is left enabled.
    from bastion.layers.l0_core import L0Core
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    marker = sysobj.path(L0Core.NFT_ENABLED_MARKER)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("1\n")
    layers.get("l0").uninstall(ctx)
    assert ("systemctl", "disable", "nftables") in sysobj.calls       # we enabled it -> disable
    assert not marker.exists()                                        # marker cleared


def test_l0_uninstall_keeps_preexisting_nftables_enabled(tmp_path):
    # No marker = nftables.service was already enabled before bastion -> leave it alone.
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l0").uninstall(ctx)
    assert ("systemctl", "disable", "nftables") not in sysobj.calls


def test_nft_health_unknown_when_live_and_nonroot():
    # On a live host without root, `nft list` is denied — report unknown, not a false FAIL.
    from bastion.layers.base import nft_table_health, nft_set_health

    class S(System):
        @property
        def is_live(self): return True
        @property
        def is_root(self): return False
        def nft_table_exists(self, *a): raise AssertionError("must not query nft when non-root")
        def nft_set_exists(self, *a): raise AssertionError("must not query nft when non-root")

    t = nft_table_health(S(), "base ruleset", "inet", "bastion")
    assert t.unknown and not t.ok and "root" in t.detail
    s = nft_set_health(S(), "blk_feed", "inet", "edge", "blk_feed")
    assert s.unknown and not s.ok


def test_nft_health_queries_when_root():
    from bastion.layers.base import nft_table_health

    class S(System):
        @property
        def is_live(self): return True
        @property
        def is_root(self): return True
        def nft_table_exists(self, *a): return True

    t = nft_table_health(S(), "base ruleset", "inet", "bastion")
    assert t.ok and not t.unknown


def test_cli_status_on_fresh_root_returns_zero(tmp_path, capsys):
    rc = cli.main(["status", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "l0" in out
    assert "no layers installed yet" in out


def test_recovery_traps_signals_during_start():
    # do_start creates a privileged OTP user + NOPASSWD sudoers BEFORE the self-destruct is armed.
    # An interrupt (TimeoutStartSec, Ctrl-C, OOM) must tear that surface down, not leave a
    # never-expiring backdoor. The trap is set in do_start and cleared only after arm_destruct.
    body = (SCRIPTS / "bastion-recovery").read_text()
    assert "do_stop quiet; exit 1' INT TERM" in body
    # cleared on success (after the self-destruct is armed) so the timer owns teardown thereafter
    set_trap = body.index("do_stop quiet; exit 1' INT TERM")
    clear_trap = body.index("trap - INT TERM")
    assert clear_trap > set_trap


# --- F4: foreign /etc/nftables.conf guard (warn + recovery backup before overwrite) -------------

class _LiveSys(System):
    """A System that reports live + nftables.service enabled, for the foreign-nftables guard."""
    @property
    def is_live(self) -> bool:
        return True

    def unit_enabled(self, unit: str) -> bool:
        return True

    def unit_active(self, unit: str) -> bool:
        return False


def test_warn_if_foreign_nftables_conf_backs_up_and_warns(tmp_path):
    from bastion.layers import base
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/nftables.conf").write_text(
        "table inet filter { chain input { type filter hook input priority 0; policy drop; } }\n")
    lines: list[str] = []
    bak = base.warn_if_foreign_nftables_conf(_LiveSys(root=tmp_path), "endpoint", out=lines.append)
    assert bak == "/etc/nftables.conf.pre-bastion"
    saved = (tmp_path / "etc/nftables.conf.pre-bastion").read_text()
    assert saved.startswith("table inet filter")
    assert any("WARNING" in l for l in lines)


def test_warn_if_foreign_nftables_conf_noop_on_bastion_file(tmp_path):
    from bastion.layers import base
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/nftables.conf").write_text("flush ruleset\ntable inet bastion {\n}\n")
    out = base.warn_if_foreign_nftables_conf(_LiveSys(root=tmp_path), "endpoint", out=lambda *_: None)
    assert out is None                                            # already ours -> safe reinstall
    assert not (tmp_path / "etc/nftables.conf.pre-bastion").exists()


def test_warn_if_foreign_nftables_conf_noop_when_staged(tmp_path):
    # A staged (--root, non-live) install loads no ruleset, so the guard must never fire.
    from bastion.layers import base
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/nftables.conf").write_text("table inet filter {}\n")
    assert base.warn_if_foreign_nftables_conf(System(root=tmp_path), "endpoint",
                                              out=lambda *_: None) is None


# --- F11/F12: teardown + nftables.conf restore on uninstall ------------------------------------

def test_l0_uninstall_restores_foreign_nftables_backup(tmp_path):
    # F12: a foreign /etc/nftables.conf backed up by F4 is restored on uninstall (so a still-enabled
    # nftables.service reloads the operator's ruleset, not a dangling/empty file).
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc/nftables.conf").write_text("table inet bastion {}\n")
    (tmp_path / "etc/nftables.conf.pre-bastion").write_text("table inet filter {}\n")
    layers.get("l0").uninstall(ctx)
    assert (tmp_path / "etc/nftables.conf").read_text() == "table inet filter {}\n"
    assert not (tmp_path / "etc/nftables.conf.pre-bastion").exists()


def test_l0_uninstall_removes_own_nftables_conf_when_no_backup(tmp_path):
    sysobj = _FwSys(tmp_path, active_fw=None)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc/nftables.conf").write_text("table inet bastion {}\n")
    layers.get("l0").uninstall(ctx)
    assert not (tmp_path / "etc/nftables.conf").exists()


def test_teardown_removes_config_dirs(tmp_path):
    # F11: `bastion teardown` removes the runtime config dirs `pacman -R` leaves behind. No layers are
    # "installed" under this empty staged root, so only the config-dir cleanup runs.
    for d in ("etc/bastion", "etc/edge-ai", "etc/edge-reconciler"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "f").write_text("x")
    rc = cli.main(["teardown", "--yes", "--root", str(tmp_path), "--conf", str(tmp_path / "none.conf")])
    assert rc == 0
    assert not (tmp_path / "etc/bastion").exists()
    assert not (tmp_path / "etc/edge-ai").exists()
    assert not (tmp_path / "etc/edge-reconciler").exists()


def test_teardown_keep_config(tmp_path):
    (tmp_path / "etc/bastion").mkdir(parents=True)
    rc = cli.main(["teardown", "--yes", "--keep-config", "--root", str(tmp_path),
                   "--conf", str(tmp_path / "none.conf")])
    assert rc == 0
    assert (tmp_path / "etc/bastion").exists()                # --keep-config preserves it
