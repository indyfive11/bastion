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
    )
    units = ("edge-dnsblock.service", "edge-dnsblock.timer")
    services = ("unbound.service", "dnsmasq.service")   # package-provided daemons L4 manages
    timers = ("edge-dnsblock.timer",)

    def _endpoint(self, ctx: Context) -> bool:
        return ctx.mode == "endpoint"

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

        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
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
