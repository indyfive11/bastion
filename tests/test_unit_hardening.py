"""F1 — systemd confinement of the two root scripts that were the weakest-sandboxed: the sole nft
writer (edge-reconciler, fully hardened) and the always-on self-heal tool (edge-watchdog,
deliberately LIGHT — it must shell out to systemctl/ping/net-rollback and write its own runtime
state, so strict/syscall-filter confinement is intentionally withheld).

The runtime behaviour (the reconciler still writes nft/lock/audit; the watchdog stays active; both
free of confinement denials) is VM-validated; these are cheap regression guards so a later edit
can't silently drop the directives or accidentally over-confine the self-heal tool.
"""
from pathlib import Path

SYSTEMD = Path(__file__).resolve().parent.parent / "bastion" / "templates" / "systemd"


def test_reconciler_fully_hardened():
    rec = (SYSTEMD / "edge-reconciler.service").read_text()
    for directive in (
        "ProtectSystem=strict",
        "CapabilityBoundingSet=CAP_NET_ADMIN",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",   # AF_NETLINK = nft
        "SystemCallFilter=@system-service",
        "MemoryDenyWriteExecute=true",
        # the three write targets must be punched back in (audit log, runtime dir, /run lock)
        "ReadWritePaths=/var/log/edge-reconciler /var/lib/edge-reconciler /run",
    ):
        assert directive in rec, directive


def test_watchdog_light_confinement_only():
    wd = (SYSTEMD / "edge-watchdog.service").read_text()
    # what it DOES take: capability ceiling + address families (can't break the self-heal paths)
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" in wd
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in wd
    # what it deliberately WITHHOLDS (newline-anchored so the explanatory comment doesn't trip this)
    assert "\nProtectSystem=strict" not in wd
    assert "\nSystemCallFilter" not in wd
