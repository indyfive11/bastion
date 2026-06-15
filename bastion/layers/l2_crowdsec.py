"""L2 — crowdsec. The CrowdSec agent as a behavioural detection SOURCE for the firewall.

CrowdSec parses logs and issues ban decisions; it holds ZERO firewall privilege. The L1
`edge-reconciler` is the bouncer — it reads `cscli decisions list` and reconciles them into the
`cs_block` nft set (validated against the allowlist + width floor like every other source). There
is deliberately NO crowdsec-firewall-bouncer: that would be a second nft writer, violating
Commandment #7. L2 therefore owns no bastion files — it manages the distro-packaged
`crowdsec.service` lifecycle and verifies the cscli → cs_block path L1 already wired.

Prerequisites: L0 (base table holds `cs_block`), L1 (the reconciler that populates it).
"""
from __future__ import annotations

from .base import Layer, Context, LayerStatus, HealthCheck, nft_set_health

UNIT = "crowdsec.service"


class L2Crowdsec(Layer):
    name = "l2"
    title = "crowdsec"
    description = "CrowdSec detection agent feeding the cs_block set via the L1 reconciler"
    prerequisites = ("l0", "l1")
    packages = ("crowdsec",)          # provides the daemon + cscli + crowdsec.service
    scripts = ()                       # none — the L1 reconciler is the bouncer
    units = ()                         # crowdsec.service is package-provided, not bastion-owned

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system

        if not sys.command_exists("cscli"):
            print("l2: WARNING — cscli not found; install the 'crowdsec' package first. "
                  "On Arch it is AUR-only (e.g. `paru -S crowdsec`); bastion does not build it "
                  "for you. Then re-run `bastion layer install l2`.")

        if not sys.exists(f"{ctx.sbin_dir}/edge-reconciler"):
            print("l2: WARNING — edge-reconciler (L1) is not installed; cs_block will not be "
                  "populated until L1 is installed (L2 prerequisite).")

        if sys.is_live:
            sys.run("systemctl", "enable", "--now", UNIT)
            print("l2: crowdsec.service enabled + started. The reconciler picks up its "
                  "decisions into cs_block on the next pass (≤60s).")
        else:
            print("l2: staged — L2 owns no bastion files; it only manages the system "
                  "crowdsec.service (skipped: root != / or dry-run).")

    def uninstall(self, ctx: Context) -> None:
        sys = ctx.system
        if sys.is_live:
            sys.run("systemctl", "disable", "--now", UNIT)
            # Operator destructive flush (allowed; only ADDS are reconciler-only — Commandment #7).
            family, table = self._table(ctx)
            sys.run("nft", "flush", "set", family, table, "cs_block")
            print("l2: crowdsec.service disabled + stopped, cs_block flushed.")
        else:
            print("l2: nothing to remove under a staged root (no bastion-owned files).")

    def status(self, ctx: Context) -> LayerStatus:
        sys = ctx.system
        # L2 stages no files; its state is the host crowdsec service. Under a non-live root
        # (--root staging) there is nothing bastion-installed to report.
        if not sys.is_live:
            return LayerStatus(self.name, self.title, False, False,
                               "host-managed (crowdsec) — inspect on the live system")
        # "Installed" = the CrowdSec package is present (cscli binary). L2 stages no files.
        installed = sys.command_exists("cscli")
        active = sys.unit_active(UNIT)
        if not installed:
            detail = "crowdsec package not installed (cscli missing)"
        elif active:
            detail = "crowdsec agent running; decisions feed cs_block via the reconciler"
        else:
            detail = "crowdsec installed but not running"
        return LayerStatus(self.name, self.title, installed, active, detail)

    def health_check(self, ctx: Context) -> list[HealthCheck]:
        sys = ctx.system
        family, table = self._table(ctx)
        return [
            HealthCheck("cscli present", sys.command_exists("cscli")),
            HealthCheck("crowdsec.service active", sys.unit_active(UNIT)),
            HealthCheck("crowdsec.service enabled", sys.unit_enabled(UNIT)),
            HealthCheck("edge-reconciler present (bouncer)",
                        sys.exists(f"{ctx.sbin_dir}/edge-reconciler")),
            nft_set_health(sys, "cs_block set present", family, table, "cs_block"),
        ]

    # --- helpers ----------------------------------------------------------
    def _table(self, ctx: Context) -> tuple[str, str]:
        return ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")
