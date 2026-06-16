"""L0 — core. nftables base ruleset + policy.allowlist + the always-installed
bastion-recovery service. Foundation for every profile; prerequisite of all other layers.
"""
from __future__ import annotations

from .base import (Layer, Context, LayerStatus, HealthCheck, nft_table_health,
                   FirewallConflict, blocking_conflicting_firewall)


class L0Core(Layer):
    name = "l0"
    title = "core"
    description = "nftables base ruleset + never-block allowlist + always-installed recovery service"
    prerequisites = ()
    packages = ("nftables", "openssh")
    scripts = ("bastion-recovery",)
    # bastion-recovery.service is installed but NEVER auto-enabled (console-start only).
    # bastion-recovery-reap.service IS enabled (install() below): it runs once at boot to tear down
    # a recovery surface orphaned by an unclean reboot — the only recovery unit that is auto-enabled.
    units = ("bastion-recovery.service", "bastion-recovery-reap.service")
    REAP_UNIT = "bastion-recovery-reap.service"

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

    # nftables.service ExecStart override — pins the canonical loader to /etc/nftables.conf so the
    # bastion ruleset loads on every distro (Fedora/RHEL otherwise read /etc/sysconfig/nftables.conf).
    NFT_DROPIN = "/etc/systemd/system/nftables.service.d/10-bastion-load.conf"

    @staticmethod
    def _nft_path(sys) -> str:
        """Absolute path to the nft binary for a systemd ExecStart (which can't use PATH)."""
        for cand in ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"):
            if sys.exists(cand):
                return cand
        return "/usr/sbin/nft"            # sane default (staging trees have no nft)

    def _write_nft_loader_dropin(self, ctx: Context) -> None:
        nft = self._nft_path(ctx.system)
        out = ctx.system.path(self.NFT_DROPIN)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            "# bastion (L0): load the ruleset bastion renders, independent of the distro's default\n"
            "# nftables.conf path (Arch/Debian: /etc/nftables.conf; Fedora/RHEL: /etc/sysconfig/...).\n"
            "[Service]\n"
            "ExecStart=\n"
            f"ExecStart={nft} -f /etc/nftables.conf\n"
        )

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

        # Pin nftables.service to load the file we just wrote. Its default ExecStart path is
        # distro-specific — Arch/Debian load /etc/nftables.conf, but Fedora/RHEL load
        # /etc/sysconfig/nftables.conf — so enabling the stock service on Fedora "succeeds" yet
        # never loads our ruleset. The drop-in makes the canonical loader read /etc/nftables.conf
        # everywhere (and persist it across reboot). Written even when staged so a later live
        # `systemctl enable` honours it.
        self._write_nft_loader_dropin(ctx)

        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
            # Enable the boot reaper so an orphaned rescue surface (rescue user + NOPASSWD sudoers
            # left by a crash mid-recovery) is torn down on the next boot. This is the one recovery
            # unit that is auto-enabled; bastion-recovery.service itself stays disabled.
            if sys.run("systemctl", "enable", self.REAP_UNIT).returncode != 0:
                print(f"l0: WARNING — could not enable {self.REAP_UNIT} (boot orphan reaper); "
                      "an unclean reboot mid-recovery would not be auto-cleaned")
            # Validate, then load the base ruleset via nftables.service as the canonical loader (now
            # pinned to /etc/nftables.conf by the drop-in above) so the load persists across reboot
            # and `systemctl is-active nftables` truthfully reports firewall state. `restart` (not
            # just `enable --now`) because a reinstall finds the oneshot already active and `start`
            # would NOT re-run ExecStart — restart guarantees the pinned loader runs now. Fall back
            # to a direct (non-persistent) load only if the service can't be driven.
            conf = str(sys.path("/etc/nftables.conf"))
            if sys.run("nft", "-c", "-f", conf).returncode == 0:
                enabled = sys.run("systemctl", "enable", "nftables").returncode == 0
                loaded = sys.run("systemctl", "restart", "nftables").returncode == 0
                if not (enabled and loaded):
                    print("l0: WARNING — could not drive nftables.service; loading the ruleset "
                          "directly (it will NOT persist across reboot)")
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
            sys.run("systemctl", "disable", "--now", self.REAP_UNIT)
            # Stop persisting our ruleset (install() enabled it) so the flushed table is not
            # reloaded from /etc/nftables.conf on the next boot.
            sys.run("systemctl", "disable", "nftables")
            family, table = self._nft_table(ctx)
            sys.run("nft", "delete", "table", family, table)
        # Remove the nftables.service loader drop-in (restores the distro's default ExecStart).
        drop = sys.path(self.NFT_DROPIN)
        drop.unlink(missing_ok=True)
        try:
            drop.parent.rmdir()              # only succeeds if we left it empty
        except OSError:
            pass
        if sys.is_live:
            sys.run("systemctl", "daemon-reload")
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
            "bastion-recovery-reap.service": sys.exists(f"/etc/systemd/system/{self.REAP_UNIT}"),
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
            nft_table_health(sys, f"base ruleset loaded ({family} {table})", family, table),
            HealthCheck("recovery unit installed", sys.exists("/etc/systemd/system/bastion-recovery.service")),
            HealthCheck("policy.allowlist non-empty",
                        allowlist.is_file() and allowlist.stat().st_size > 0),
        ]
