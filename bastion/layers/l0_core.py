"""L0 — core. nftables base ruleset + policy.allowlist + the always-installed
bastion-recovery service. Foundation for every profile; prerequisite of all other layers.
"""
from __future__ import annotations

from .base import (Layer, Context, LayerStatus, HealthCheck,
                   FirewallConflict, blocking_conflicting_firewall)


class L0Core(Layer):
    name = "l0"
    title = "core"
    description = "nftables base ruleset + never-block allowlist + always-installed recovery service"
    prerequisites = ()
    packages = ("nftables", "openssh")
    scripts = ("bastion-recovery",)
    units = ("bastion-recovery.service",)

    # --- mode-dependent pieces -------------------------------------------
    def _nft_template(self, ctx: Context) -> str:
        return "nftables-endpoint.nft" if ctx.mode == "endpoint" else "nftables-edge.nft"

    def owned_templates(self, mode: str) -> set[str]:
        # L0 renders these in install() via render_to (not template_dests); declare them here so
        # generate writes the mode-correct ruleset + the never-block allowlist for L0.
        rels = super().owned_templates(mode)
        rels.add("nftables-endpoint.nft" if mode == "endpoint" else "nftables-edge.nft")
        rels.add("policy.allowlist")
        return rels

    def _nft_table(self, ctx: Context) -> tuple[str, str]:
        # edge template defines `table inet edge`; endpoint defines `table inet bastion`.
        return ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system

        # SAFETY: never load our ruleset (it begins with `flush ruleset`) while another OS firewall
        # is active — it would wipe ufw/firewalld's rules and the two would fight. Abort with an
        # instruction; the operator disables the other firewall (or sets the override env var).
        if sys.is_live:
            fw = blocking_conflicting_firewall(sys)
            if fw:
                raise FirewallConflict(fw)

        # Packages are checked, not installed, until pkg.py (Phase 5). Surface what's missing.
        missing = [p for p in ("nft", "sshd") if not sys.command_exists(p)]
        if missing:
            print(f"l0: WARNING — required binaries not found: {', '.join(missing)} "
                  f"(install packages {', '.join(self.packages)} first)")

        # Render the base ruleset + never-block allowlist.
        self.render_to(ctx, self._nft_template(ctx), "/etc/nftables.conf")
        self.render_to(ctx, "policy.allowlist", "/etc/edge-reconciler/policy.allowlist")

        # Install the always-present recovery script + unit (recovery stays DISABLED).
        for script in self.scripts:
            self.install_script(ctx, script)
        for unit in self.units:
            self.install_unit(ctx, unit)

        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
            # Validate then load the base ruleset.
            conf = str(sys.path("/etc/nftables.conf"))
            if sys.run("nft", "-c", "-f", conf).returncode == 0:
                sys.run("nft", "-f", conf)
            else:
                print("l0: WARNING — rendered nftables.conf failed `nft -c`; not loaded")
        else:
            print("l0: staged install (root != / or dry-run) — files written, live "
                  "firewall/systemd NOT touched.")
        print(f"l0: installed (mode={ctx.mode}). bastion-recovery is installed and DISABLED "
              f"(start from console only).")

    def uninstall(self, ctx: Context) -> None:
        sys = ctx.system
        if sys.is_live:
            sys.run("systemctl", "stop", "bastion-recovery")
            family, table = self._nft_table(ctx)
            sys.run("nft", "delete", "table", family, table)
        for unit in self.units:
            p = sys.path(f"/etc/systemd/system/{unit}")
            p.unlink(missing_ok=True)
        for script in self.scripts:
            sys.path(f"{ctx.sbin_dir}/{script}").unlink(missing_ok=True)
        print("l0: uninstalled (base ruleset flushed, recovery removed).")

    def status(self, ctx: Context) -> LayerStatus:
        sys = ctx.system
        artifacts = {
            "nftables.conf": sys.exists("/etc/nftables.conf"),
            "policy.allowlist": sys.exists("/etc/edge-reconciler/policy.allowlist"),
            "bastion-recovery script": sys.exists(f"{ctx.sbin_dir}/bastion-recovery"),
            "bastion-recovery.service": sys.exists("/etc/systemd/system/bastion-recovery.service"),
        }
        installed = all(artifacts.values())
        family, table = self._nft_table(ctx)
        active = sys.nft_table_exists(family, table)
        missing = [k for k, v in artifacts.items() if not v]
        detail = "all core artifacts present" if installed else f"missing: {', '.join(missing)}"
        return LayerStatus(self.name, self.title, installed, active, detail)

    def health_check(self, ctx: Context) -> list[HealthCheck]:
        sys = ctx.system
        family, table = self._nft_table(ctx)
        allowlist = sys.path("/etc/edge-reconciler/policy.allowlist")
        return [
            HealthCheck("nft binary present", sys.command_exists("nft")),
            HealthCheck("sshd present (recovery)", sys.command_exists("sshd")),
            HealthCheck(f"base ruleset loaded ({family} {table})", sys.nft_table_exists(family, table)),
            HealthCheck("recovery unit installed", sys.exists("/etc/systemd/system/bastion-recovery.service")),
            HealthCheck("policy.allowlist non-empty",
                        allowlist.is_file() and allowlist.stat().st_size > 0),
        ]
