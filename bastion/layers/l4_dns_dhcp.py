"""L4 — dns-dhcp. LAN DNS + DHCP (dnsmasq) in front of a local validating resolver (unbound on
127.0.0.1:5335), plus a DNS sinkhole: `edge-dnsblock-update` renders ads/trackers/malware domains
to `/etc/unbound/blocklist.conf` as `always_nxdomain` local-zones, validates with unbound-checkconf,
reloads unbound, and reverts on a bad config.

EDGE MODE ONLY. An endpoint relies on the upstream router/edge box for DHCP and default routing
(§5), so L4 is skipped there — it would fight the existing DHCP server.

Prerequisites: L0.
"""
from __future__ import annotations

from .base import Layer, Context, LayerStatus, HealthCheck

BLOCKLIST = "/etc/unbound/blocklist.conf"
ANCHOR = "/var/lib/unbound/root.key"   # RFC5011 DNSSEC root trust anchor (unbound.conf references it)
ANCHOR_DIR = "/var/lib/unbound"
# unbound.service drop-in: the RFC5011 auto-trust anchor (auto-trust-anchor-file) must be WRITABLE by
# the unbound process for its periodic re-signing. The distro unit runs unbound as root and lets it
# self-drop to the `unbound` user via the config's `username:` — but StateDirectory=unbound then owns
# /var/lib/unbound as root (the service's User), so the dropped process dies "could not open autotrust
# file: Permission denied" (a live-validated failure, 2026-06-18). Pinning User/Group=unbound makes
# StateDirectory own the state dir as unbound (the in-config drop becomes a harmless no-op); unbound's
# listeners are on :5335, an unprivileged port, so it needs no root. This is the fix the Plan flagged
# as the sandbox-interaction fallback — shipped because the live test proved it necessary.
UNBOUND_DROPIN = "/etc/systemd/system/unbound.service.d/10-bastion-anchor.conf"
UNBOUND_DROPIN_BODY = (
    "# bastion (L4): run unbound as the unbound user so StateDirectory owns /var/lib/unbound as\n"
    "# unbound and the RFC5011 auto-trust anchor (root.key) is writable. See l4_dns_dhcp.py.\n"
    "[Service]\n"
    "User=unbound\n"
    "Group=unbound\n"
)


class L4DnsDhcp(Layer):
    name = "l4"
    title = "dns-dhcp"
    description = "dnsmasq DHCP/DNS + unbound resolver + DNS sinkhole (edge mode only)"
    prerequisites = ("l0",)
    packages = ("dnsmasq", "unbound")
    scripts = ("edge-dnsblock-update",)
    template_dests = (
        ("dnsmasq.conf", "/etc/dnsmasq.conf"),
        ("unbound.conf", "/etc/unbound/unbound.conf"),
        ("dns-allowlist", "/etc/edge-dnsblock/allowlist"),   # F2 never-sink list for the sinkhole
    )
    units = ("edge-dnsblock.service", "edge-dnsblock.timer")
    services = ("unbound.service", "dnsmasq.service")   # package-provided daemons L4 manages
    timers = ("edge-dnsblock.timer",)

    def _endpoint(self, ctx: Context) -> bool:
        return ctx.mode == "endpoint"

    def _seed_trust_anchor(self, ctx: Context) -> None:
        """Seed/refresh the RFC5011 root trust anchor so unbound validates DNSSEC from first start.

        unbound.conf sets `auto-trust-anchor-file: /var/lib/unbound/root.key`; without the key file
        unbound does not validate (and refuses to start). `unbound-anchor` ships a built-in ICANN
        fallback key (no network needed), writes the file, and exits 1 on a normal "anchor
        (re)written" — only rc > 1 is a real failure. Idempotent: a re-run just refreshes the file.
        LIVE-ONLY: a staged --root tree / dry-run starts no daemon and needs no anchor, so
        `generate --check` and `--root` installs stay command-free."""
        sys = ctx.system
        if not sys.is_live:
            return
        var = sys.path(ANCHOR_DIR)
        var.mkdir(parents=True, exist_ok=True)
        if not sys.command_exists("unbound-anchor"):
            print("l4: WARNING — unbound-anchor not found; DNSSEC trust anchor NOT seeded. unbound "
                  "will fail to start with auto-trust-anchor-file set. Install the unbound package "
                  "(it provides unbound-anchor) and re-run.")
            return
        rc = sys.run("unbound-anchor", "-a", ANCHOR).returncode
        if rc > 1:   # 0 = anchor already valid; 1 = (re)written from the bundled key (both normal)
            print(f"l4: WARNING — unbound-anchor exited {rc}; DNSSEC validation may not initialize.")
        # The daemon runs as the unbound user and must rewrite the key for RFC5011 refreshes.
        sys.run("chown", "unbound:unbound", ANCHOR)
        sys.run("chown", "unbound:unbound", str(var))

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system
        if self._endpoint(ctx):
            print("l4: skipped — dns-dhcp is edge-mode only (an endpoint uses the upstream "
                  "router's DHCP/DNS; L4 would conflict with it).")
            return

        missing = [b for b in ("dnsmasq", "unbound") if not sys.command_exists(b)]
        if missing:
            print(f"l4: WARNING — required binaries not found: {', '.join(missing)} "
                  f"(install packages {', '.join(self.packages)} first)")

        for script in self.scripts:
            self.install_script(ctx, script)
        for template_rel, dest in self.template_dests:
            self.render_to(ctx, template_rel, dest)
        for unit in self.units:
            self.install_unit(ctx, unit)
        # unbound.conf `include:`s the sinkhole file; create it empty so unbound starts before
        # the first edge-dnsblock-update run (the include is not tolerant of a missing file).
        blk = sys.path(BLOCKLIST)
        blk.parent.mkdir(parents=True, exist_ok=True)
        if not blk.exists():
            blk.write_text("# bastion DNS sinkhole — populated by edge-dnsblock-update.\n")
        # dnsmasq.conf reads /etc/dnsmasq.d/*.conf — create the dir so operator drop-ins (e.g.
        # machine-specific DHCP reservations, which carry MACs and never enter the repo) have a home.
        sys.path("/etc/dnsmasq.d").mkdir(parents=True, exist_ok=True)

        # unbound.service drop-in so the unbound user can write the RFC5011 anchor (see UNBOUND_DROPIN).
        # Written even when staged so a later live `systemctl enable` honours it.
        drop = sys.path(UNBOUND_DROPIN)
        drop.parent.mkdir(parents=True, exist_ok=True)
        drop.write_text(UNBOUND_DROPIN_BODY)

        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
            # Seed the DNSSEC anchor BEFORE unbound's first start (auto-trust-anchor-file must exist).
            self._seed_trust_anchor(ctx)
            for svc in self.services:
                sys.run("systemctl", "enable", "--now", svc)
            for timer in self.timers:
                sys.run("systemctl", "enable", "--now", timer)
            print("l4: installed + started (dnsmasq + unbound; sinkhole refreshes daily).")
        else:
            print("l4: staged install (root != / or dry-run) — files written, services/timers "
                  "NOT enabled/started.")

    def uninstall(self, ctx: Context) -> None:
        sys = ctx.system
        if self._endpoint(ctx):
            print("l4: nothing to remove — not installed in endpoint mode.")
            return
        if sys.is_live:
            for timer in self.timers:
                sys.run("systemctl", "disable", "--now", timer)
            # Leave dnsmasq/unbound running by default? No — L4 owns DHCP/DNS for the LAN; on
            # teardown stop them so the box stops serving (operator chose to remove the layer).
            for svc in self.services:
                sys.run("systemctl", "disable", "--now", svc)
            sys.run("systemctl", "daemon-reload")
        for unit in self.units:
            sys.path(f"/etc/systemd/system/{unit}").unlink(missing_ok=True)
        for script in self.scripts:
            sys.path(f"{ctx.sbin_dir}/{script}").unlink(missing_ok=True)
        for _, dest in self.template_dests:
            sys.path(dest).unlink(missing_ok=True)
        # Remove the unbound anchor drop-in (restores the distro unit's default sandbox).
        drop = sys.path(UNBOUND_DROPIN)
        drop.unlink(missing_ok=True)
        try:
            drop.parent.rmdir()              # only if we left it empty
        except OSError:
            pass
        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
        print("l4: uninstalled (dnsmasq + unbound stopped, sinkhole timer removed).")

    def status(self, ctx: Context) -> LayerStatus:
        sys = ctx.system
        if self._endpoint(ctx):
            return LayerStatus(self.name, self.title, False, False,
                               "N/A — edge mode only (skipped on endpoint)")
        artifacts = {
            "dnsmasq.conf": sys.exists("/etc/dnsmasq.conf"),
            "unbound.conf": sys.exists("/etc/unbound/unbound.conf"),
            "edge-dnsblock-update": sys.exists(f"{ctx.sbin_dir}/edge-dnsblock-update"),
            "edge-dnsblock.timer": sys.exists("/etc/systemd/system/edge-dnsblock.timer"),
        }
        installed = all(artifacts.values())
        active = sys.unit_active("unbound.service") and sys.unit_active("dnsmasq.service")
        if not installed:
            missing = [k for k, v in artifacts.items() if not v]
            detail = f"missing: {', '.join(missing)}"
        else:
            detail = "DNS/DHCP serving" if active else "installed; dnsmasq/unbound not both active"
        return LayerStatus(self.name, self.title, installed, active, detail)

    def health_check(self, ctx: Context) -> list[HealthCheck]:
        sys = ctx.system
        if self._endpoint(ctx):
            return [HealthCheck("edge-mode only (skipped on endpoint)", True)]
        return [
            HealthCheck("dnsmasq present", sys.command_exists("dnsmasq")),
            HealthCheck("unbound present", sys.command_exists("unbound")),
            HealthCheck("unbound-checkconf present", sys.command_exists("unbound-checkconf")),
            HealthCheck("dnsmasq.conf present", sys.exists("/etc/dnsmasq.conf")),
            HealthCheck("unbound.conf present", sys.exists("/etc/unbound/unbound.conf")),
            HealthCheck("blocklist.conf present (sinkhole)", sys.exists(BLOCKLIST)),
            HealthCheck("edge-dnsblock-update installed",
                        sys.exists(f"{ctx.sbin_dir}/edge-dnsblock-update")),
            HealthCheck("unbound.service active", sys.unit_active("unbound.service")),
            HealthCheck("dnsmasq.service active", sys.unit_active("dnsmasq.service")),
        ]
