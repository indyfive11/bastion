"""L6 — monitoring. The self-heal + verify + alert surface:

  * edge-watchdog        — standing egress/relay self-heal (long-running service)
  * net-snapshot/rollback — known-good network state capture + restore (wrapped by
                            `bastion snapshot` / `bastion rollback`)
  * flowcheck            — egress/flow checks (wrapped by `bastion check`)
  * lan-verify           — conntrack LAN-client forward-path check (`bastion check --lan`)
  * net-confirm          — canary confirm/disarm after a risky change (`bastion confirm`)
  * notify-alert         — no-arch-leak tiered alerter (external = degraded-only template;
                           internal = full detail, operator network only)
  * notify-failure@      — systemd OnFailure= shim instance -> notify-alert

The alerter's sink config (/etc/bastion/notify-alert.conf — ntfy topic, email, internal URL) is
operator/secret material: it is NOT installed here. notify-alert tolerates its absence (sinks no-op);
the setup wizard renders the real conf from operator input (Phase 5), same pattern as claude.env.
The machine.env keys these scripts source (LAN_NET, RELAY_DST, EGRESS_PROBE, NM_CONN, NFT_TABLE)
come from `bastion generate`.

Prerequisites: L0.
"""
from __future__ import annotations

from .base import Layer, Context, LayerStatus, HealthCheck

WATCHDOG = "edge-watchdog.service"


class L6Monitoring(Layer):
    name = "l6"
    title = "monitoring"
    description = "watchdog + snapshot/rollback + flow/LAN verify + canary confirm + alerter"
    prerequisites = ("l0",)
    packages = ("curl", "conntrack-tools")
    # curl: net-confirm/notify-alert. conntrack-tools: lan-verify's fallback when
    # /proc/net/nf_conntrack is absent (modern kernels build CONFIG_NF_CONNTRACK_PROCFS off,
    # so `conntrack -L` over netlink is the only way to read the table the nft ruleset populates).
    scripts = ("edge-watchdog", "net-snapshot", "net-rollback", "flowcheck",
               "lan-verify", "net-confirm", "notify-alert", "notify-failure")
    units = ("edge-watchdog.service", "notify-failure@.service")
    template_dests = ()      # notify-alert.conf is operator/secret config (Phase-5 wizard)

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system

        for script in self.scripts:
            self.install_script(ctx, script)
        for unit in self.units:
            self.install_unit(ctx, unit)

        if not sys.exists("/etc/bastion/machine.env"):
            print("l6: NOTE — /etc/bastion/machine.env not found; the watchdog/lan-verify/"
                  "net-confirm scripts will use generic fallbacks. Run `bastion generate`.")
        if not sys.exists("/etc/bastion/notify-alert.conf"):
            print("l6: NOTE — /etc/bastion/notify-alert.conf absent; alerts no-op until "
                  "configured (sink config is operator/secret — set via `bastion setup`).")

        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
            # notify-failure@ is a template (instantiated per-unit via OnFailure=), not started.
            sys.run("systemctl", "enable", "--now", WATCHDOG)
            print("l6: installed + watchdog started.")
        else:
            print("l6: staged install (root != / or dry-run) — files written, watchdog NOT "
                  "enabled/started.")

    def uninstall(self, ctx: Context) -> None:
        sys = ctx.system
        if sys.is_live:
            sys.run("systemctl", "disable", "--now", WATCHDOG)
            sys.run("systemctl", "daemon-reload")
        for unit in self.units:
            sys.path(f"/etc/systemd/system/{unit}").unlink(missing_ok=True)
        for script in self.scripts:
            sys.path(f"{ctx.sbin_dir}/{script}").unlink(missing_ok=True)
        print("l6: uninstalled (watchdog stopped, scripts/units removed).")

    def status(self, ctx: Context) -> LayerStatus:
        sys = ctx.system
        artifacts = {s: sys.exists(f"{ctx.sbin_dir}/{s}") for s in self.scripts}
        artifacts["edge-watchdog.service"] = sys.exists("/etc/systemd/system/edge-watchdog.service")
        artifacts["notify-failure@.service"] = sys.exists(
            "/etc/systemd/system/notify-failure@.service")
        installed = all(artifacts.values())
        active = sys.unit_active(WATCHDOG)
        if not installed:
            missing = [k for k, v in artifacts.items() if not v]
            detail = f"missing: {', '.join(missing)}"
        else:
            detail = "watchdog running" if active else "installed; watchdog not active"
        return LayerStatus(self.name, self.title, installed, active, detail)

    def health_check(self, ctx: Context) -> list[HealthCheck]:
        sys = ctx.system
        return [
            HealthCheck("edge-watchdog installed", sys.exists(f"{ctx.sbin_dir}/edge-watchdog")),
            HealthCheck("edge-watchdog.service active", sys.unit_active(WATCHDOG)),
            HealthCheck("net-snapshot installed", sys.exists(f"{ctx.sbin_dir}/net-snapshot")),
            HealthCheck("net-rollback installed", sys.exists(f"{ctx.sbin_dir}/net-rollback")),
            HealthCheck("flowcheck installed", sys.exists(f"{ctx.sbin_dir}/flowcheck")),
            HealthCheck("lan-verify installed", sys.exists(f"{ctx.sbin_dir}/lan-verify")),
            HealthCheck("net-confirm installed", sys.exists(f"{ctx.sbin_dir}/net-confirm")),
            HealthCheck("notify-alert installed", sys.exists(f"{ctx.sbin_dir}/notify-alert")),
            HealthCheck("notify-failure@ unit installed",
                        sys.exists("/etc/systemd/system/notify-failure@.service")),
            HealthCheck("machine.env present", sys.exists("/etc/bastion/machine.env")),
        ]
