"""L6 monitoring layer (Phase 4 / L6 gate)."""
from pathlib import Path

from bastion import layers, state
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict, dry_run=True) -> Context:
    return Context(system=System(root=root, dry_run=dry_run), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l6_in_registry():
    l6 = layers.get("l6")
    assert "l6" in layers.REGISTRY
    assert l6.title == "monitoring"


def test_l6_install_writes_full_monitoring_surface(tmp_path):
    config = state.load_conf(EXAMPLE)
    ctx = _ctx(tmp_path, config)
    layers.get("l6").install(ctx)

    for s in ("edge-watchdog", "net-snapshot", "net-rollback", "flowcheck",
              "lan-verify", "net-confirm", "notify-alert", "notify-failure"):
        p = tmp_path / f"usr/local/sbin/{s}"
        assert p.is_file() and p.stat().st_mode & 0o111

    # Both units, including the OnFailure shim template (extracted this layer).
    assert (tmp_path / "etc/systemd/system/edge-watchdog.service").is_file()
    assert (tmp_path / "etc/systemd/system/notify-failure@.service").is_file()

    # edge-watchdog.service had a {{ interfaces.wg_vps_iface }} placeholder — fully resolved.
    wd = (tmp_path / "etc/systemd/system/edge-watchdog.service").read_text()
    assert "{{" not in wd

    st = layers.get("l6").status(ctx)
    assert st.installed is True


def test_l6_does_not_install_operator_alert_conf(tmp_path):
    # notify-alert.conf holds the ntfy topic / email (operator secret) — never installed by L6.
    layers.get("l6").install(_ctx(tmp_path, state.load_conf(EXAMPLE)))
    assert not (tmp_path / "etc/bastion/notify-alert.conf").exists()
    assert layers.get("l6").template_dests == ()


def test_flowcheck_resolv_leak_probes_resolved_upstreams():
    # Deep host-resolver leak guard: when resolv.conf is the systemd-resolved stub (127.0.0.53),
    # resolv_leak must probe resolved's *upstreams* (resolvectl) so a "resolved -> ISP" forward is
    # caught — not just a direct public nameserver in resolv.conf.
    body = (SCRIPTS / "flowcheck").read_text()
    assert "resolved_upstreams_leak()" in body
    assert "resolvectl" in body
    assert "127.0.0.53)" in body                  # the stub is special-cased, then probed deeper
    assert 'leak=$(resolved_upstreams_leak)' in body
    # the stale "deferred polish-phase item" caveat must be gone now that it's implemented
    assert "deferred polish-phase item" not in body


def test_edge_watchdog_actively_surfaces_dns_leak():
    # The resolv_leak guard must run in edge-watchdog's steady-state loop (not only at flowcheck
    # time), alert-once + latch like the WAN-carrier guard, and NEVER rewrite resolv.conf.
    body = (SCRIPTS / "edge-watchdog").read_text()
    assert "dns_leak_watch()" in body
    assert "resolv_leak()" in body                # the probe is carried here too (mirrors flowcheck)
    assert "dns-leak-alerted" in body             # alert-once latch file
    assert "dns_leak_watch\n" in body             # wired into evaluate()'s healthy path
    # edge-only + loopback-stub gate (an endpoint / external upstream legitimately points elsewhere)
    assert '[ "$MODE" = endpoint ] && return 0' in body
