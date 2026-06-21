"""L0 — core. nftables base ruleset + policy.allowlist + the always-installed
bastion-recovery service. Foundation for every profile; prerequisite of all other layers.
"""
from __future__ import annotations

from .base import (Layer, Context, LayerStatus, HealthCheck, nft_table_health,
                   FirewallConflict, blocking_conflicting_firewall, warn_if_exclusive_flush,
                   warn_if_foreign_nftables_conf)


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
        if mode != "endpoint":
            rels.add("sysctl-forward.conf")   # edge forwarding sysctl; endpoints never forward
        return rels

    def _nft_table(self, ctx: Context) -> tuple[str, str]:
        # edge template defines `table inet edge`; endpoint defines `table inet bastion`.
        return ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")

    # nftables.service ExecStart override — pins the canonical loader to /etc/nftables.conf so the
    # bastion ruleset loads on every distro (Fedora/RHEL otherwise read /etc/sysconfig/nftables.conf).
    NFT_DROPIN = "/etc/systemd/system/nftables.service.d/10-bastion-load.conf"

    # Edge IP-forwarding sysctl drop-in. Without it the forward chain (incl. the v6 rules) is inert.
    FORWARD_SYSCTL = "/etc/sysctl.d/99-bastion-forward.conf"
    # F12: marker written ONLY when L0 enables a previously-DISABLED nftables.service, so uninstall
    # disables it again (and leaves a box that never used the nft loader as it found it).
    NFT_ENABLED_MARKER = "/etc/bastion/.nftables-enabled-by-bastion"

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
            # Re-assert the oneshot + RemainAfterExit semantics in our own drop-in so the unit
            # reports `active (exited)` after a successful load (not `inactive`) regardless of what
            # the distro base unit sets — `systemctl is-active nftables` then truthfully reflects
            # that the ruleset is loaded (the l0 install comment below relies on this).
            "Type=oneshot\n"
            "RemainAfterExit=yes\n"
            # Clear any distro ExecStop (several ship `nft flush ruleset`). With RemainAfterExit=yes
            # the unit is active, so a `systemctl restart`/`stop` would otherwise run ExecStop and
            # wipe EVERY table — including a co-resident manager's (libvirt/Docker) under cooperative
            # scope, re-introducing the very flush the cooperative mode exists to prevent. The
            # service is a pure loader; tear-down is bastion's job (layer uninstall / net-rollback /
            # firewall verbs), which is scope-aware.
            "ExecStop=\n"
        )

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system

        # SAFETY: never load our ruleset (it begins with `flush ruleset`) while another OS firewall
        # is active — it would wipe ufw/firewalld's rules and the two would fight. Abort with an
        # instruction; the operator disables the other firewall (or sets the override env var).
        if sys.is_live:
            scope = ctx.config.get("machine", {}).get("firewall_scope", "exclusive")
            fw = blocking_conflicting_firewall(sys, scope)
            if fw:
                raise FirewallConflict(fw)
            # Hard-warn if exclusive scope will flush a co-resident manager's tables (the general
            # safety net — libvirt/Docker/k8s/Tailscale/hand-written; install proceeds).
            warn_if_exclusive_flush(sys, scope)
            # F4: back up + warn before overwriting a foreign, actively-loaded /etc/nftables.conf
            # (a hand-rolled nft firewall) — runs before render_to replaces the file below.
            warn_if_foreign_nftables_conf(sys, ctx.mode)

        # Packages are checked, not installed, until pkg.py (Phase 5). Surface what's missing.
        missing = [p for p in ("nft", "sshd") if not sys.command_exists(p)]
        if missing:
            print(f"l0: WARNING — required binaries not found: {', '.join(missing)} "
                  f"(install packages {', '.join(self.packages)} first)")

        # Render the base ruleset + never-block allowlist.
        self.render_to(ctx, self._nft_template(ctx), "/etc/nftables.conf")
        self.render_to(ctx, "policy.allowlist", "/etc/edge-reconciler/policy.allowlist")

        # Edge mode routes between networks — enable kernel IP forwarding so the forward chain
        # (LAN<->WAN, LAN<->tunnels, and the v6 rules) is not inert. An endpoint never forwards
        # (defense-in-depth), so it gets no drop-in; remove a stale one from a prior edge install.
        if ctx.mode != "endpoint":
            self.render_to(ctx, "sysctl-forward.conf", self.FORWARD_SYSCTL)
        else:
            sys.path(self.FORWARD_SYSCTL).unlink(missing_ok=True)

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
                if not sys.unit_enabled("nftables"):
                    # nftables.service wasn't enabled before us — record that WE turned it on, so
                    # uninstall can turn it back off (F12). If it was already enabled, leave that be.
                    marker = sys.path(self.NFT_ENABLED_MARKER)
                    marker.parent.mkdir(parents=True, exist_ok=True)
                    marker.write_text("1\n")
                enabled = sys.run("systemctl", "enable", "nftables").returncode == 0
                loaded = sys.run("systemctl", "restart", "nftables").returncode == 0
                if not (enabled and loaded):
                    print("l0: WARNING — could not drive nftables.service; loading the ruleset "
                          "directly (it will NOT persist across reboot)")
                    sys.run("nft", "-f", conf)
            else:
                print("l0: WARNING — rendered nftables.conf failed `nft -c`; not loaded")
            # Apply the forwarding sysctl now (edge only) so routing works without a reboot.
            # `--system` re-reads all of /etc/sysctl.d (idempotent); a no-op in endpoint mode.
            if ctx.mode != "endpoint":
                sys.run("sysctl", "--system")
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
            # F12: restore nftables.service to its pre-bastion enabled-state — disable it ONLY if WE
            # enabled it (marker present). If it was already enabled before us, leave it enabled.
            if sys.path(self.NFT_ENABLED_MARKER).exists():
                sys.run("systemctl", "disable", "nftables")
                sys.path(self.NFT_ENABLED_MARKER).unlink(missing_ok=True)
            family, table = self._nft_table(ctx)
            sys.run("nft", "delete", "table", family, table)
        # Don't leave a dangling loader (F11/F12): restore a foreign /etc/nftables.conf we backed up
        # (F4) so a still-enabled nftables.service reloads the operator's ruleset; else remove our own
        # so the service doesn't fail at boot on a missing file.
        nft_conf, backup = sys.path("/etc/nftables.conf"), sys.path("/etc/nftables.conf.pre-bastion")
        if backup.exists():
            nft_conf.write_text(backup.read_text())
            backup.unlink(missing_ok=True)
        else:
            nft_conf.unlink(missing_ok=True)
        # Remove the forwarding sysctl drop-in so it doesn't persist across reboot. (The running
        # kernel keeps its current ip_forward value until a reboot or an explicit `sysctl -w`; we
        # don't force it off live, which could disrupt traffic mid-teardown.)
        sys.path(self.FORWARD_SYSCTL).unlink(missing_ok=True)
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
