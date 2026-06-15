"""L1 — feeds. IP blocklist management: the `blk_feed` nft set, fed by `edge-feed-fetch`
(zero-privilege public-feed fetcher) and applied by `edge-reconciler` — the SOLE validated
writer to the managed nft sets (Commandment #7). Reconciler + feed timers live here; L2/L3
add more *sources* but reuse this same single writer.

Available in every profile (edge and endpoint). The base table the reconciler writes into is
mode-dependent (`inet edge` vs `inet bastion`); it is selected via NFT_TABLE in machine.env.
"""
from __future__ import annotations

from .base import Layer, Context, LayerStatus, HealthCheck


class L1Feeds(Layer):
    name = "l1"
    title = "feeds"
    description = "public IP blocklist feeds (blk_feed) + edge-reconciler (sole nft writer)"
    prerequisites = ("l0",)
    packages = ("nftables", "curl")
    scripts = ("edge-reconciler", "edge-feed-fetch")
    units = ("edge-reconciler.service", "edge-reconciler.timer",
             "edge-feed.service", "edge-feed.timer")

    # Runtime dirs the reconciler reads/writes (its unit lists them in ReadWritePaths, which
    # does not create them). /var/lib/edge-feed is handled by the feed unit's StateDirectory.
    runtime_dirs = ("/var/lib/edge-reconciler", "/var/log/edge-reconciler")
    # Timers that drive the layer; "active" status keys off the reconciler timer.
    timers = ("edge-reconciler.timer", "edge-feed.timer")

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system

        missing = [b for b in ("nft", "curl") if not sys.command_exists(b)]
        if missing:
            print(f"l1: WARNING — required binaries not found: {', '.join(missing)} "
                  f"(install packages {', '.join(self.packages)} first)")

        for script in self.scripts:
            self.install_script(ctx, script)
        for unit in self.units:
            self.install_unit(ctx, unit)
        for d in self.runtime_dirs:
            sys.path(d).mkdir(parents=True, exist_ok=True)

        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
            for timer in self.timers:
                sys.run("systemctl", "enable", "--now", timer)
        else:
            print("l1: staged install (root != / or dry-run) — files written, timers NOT "
                  "enabled/started.")
        print("l1: installed. Feeds refresh daily (edge-feed.timer); reconciler reconciles "
              "blk_feed every 60s (edge-reconciler.timer).")

    def uninstall(self, ctx: Context) -> None:
        sys = ctx.system
        if sys.is_live:
            for timer in self.timers:
                sys.run("systemctl", "disable", "--now", timer)
            # Destructive set flush is an operator action (allowed; only ADDS are reconciler-only).
            family, table = self._table(ctx)
            sys.run("nft", "flush", "set", family, table, "blk_feed")
            sys.run("systemctl", "daemon-reload")
        for unit in self.units:
            sys.path(f"/etc/systemd/system/{unit}").unlink(missing_ok=True)
        for script in self.scripts:
            sys.path(f"{ctx.sbin_dir}/{script}").unlink(missing_ok=True)
        print("l1: uninstalled (timers removed, blk_feed flushed, scripts removed).")

    def status(self, ctx: Context) -> LayerStatus:
        sys = ctx.system
        artifacts = {
            "edge-reconciler": sys.exists(f"{ctx.sbin_dir}/edge-reconciler"),
            "edge-feed-fetch": sys.exists(f"{ctx.sbin_dir}/edge-feed-fetch"),
            "edge-reconciler.timer": sys.exists("/etc/systemd/system/edge-reconciler.timer"),
            "edge-feed.timer": sys.exists("/etc/systemd/system/edge-feed.timer"),
        }
        installed = all(artifacts.values())
        active = sys.unit_active("edge-reconciler.timer")
        missing = [k for k, v in artifacts.items() if not v]
        detail = "all feed artifacts present" if installed else f"missing: {', '.join(missing)}"
        return LayerStatus(self.name, self.title, installed, active, detail)

    def health_check(self, ctx: Context) -> list[HealthCheck]:
        sys = ctx.system
        family, table = self._table(ctx)
        return [
            HealthCheck("nft binary present", sys.command_exists("nft")),
            HealthCheck("curl present (feed fetch)", sys.command_exists("curl")),
            HealthCheck("edge-reconciler installed", sys.exists(f"{ctx.sbin_dir}/edge-reconciler")),
            HealthCheck("edge-feed-fetch installed", sys.exists(f"{ctx.sbin_dir}/edge-feed-fetch")),
            HealthCheck("blk_feed set present", sys.nft_set_exists(family, table, "blk_feed")),
            HealthCheck("reconciler timer active", sys.unit_active("edge-reconciler.timer")),
            HealthCheck("feed timer active", sys.unit_active("edge-feed.timer")),
        ]

    # --- helpers ----------------------------------------------------------
    def _table(self, ctx: Context) -> tuple[str, str]:
        return ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")
