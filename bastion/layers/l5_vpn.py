"""L5 — vpn. WireGuard tunnels + ZeroTier interface lifecycle. OPTIONAL, any mode.

L5 owns no bastion files. Two reasons: (1) the firewall's VPN policy routing — forward rules and
masquerade for the WG/ZT interfaces — already lives in L0's nftables template (rendered from the
interface/CIDR keys in machine.conf), so there is nothing for L5 to add there; (2) WireGuard
configs carry PRIVATE KEYS and peer endpoints, and the ZeroTier network ID is installation secret —
none of that can live in the repo (Commandments #1/#8). Generating wg configs (keygen, peer
exchange) and joining the ZeroTier network is interactive, secret-bearing setup-wizard work
(Phase 5). L5 here manages the service lifecycle for the interfaces named in machine.conf and
verifies them; it never writes a key.

Routing-related behaviour is edge-only (§5), but bringing a tunnel up as a client works in any
mode, so the layer itself is mode-agnostic — the edge nft forward chain is what gates routing.

Prerequisites: L0.
"""
from __future__ import annotations

from .base import Layer, Context, LayerStatus, HealthCheck

ZT_UNIT = "zerotier-one.service"


class L5Vpn(Layer):
    name = "l5"
    title = "vpn"
    description = "WireGuard + ZeroTier interface lifecycle (optional; configs/keys are Phase-5/secrets)"
    prerequisites = ("l0",)
    packages = ("wireguard-tools", "zerotier-one")
    scripts = ()                 # none — wg-quick@/zerotier-one are package-provided
    units = ()                   # wg-quick@<iface>.service is a packaged template unit
    template_dests = ()          # no committed VPN config — keys/IDs are secret

    # --- machine.conf-driven interface discovery --------------------------
    def _wg_ifaces(self, ctx: Context) -> list[str]:
        ifaces = ctx.config.get("interfaces", {})
        # server tunnel + upstream relay tunnel; blank = not configured.
        return [v for v in (ifaces.get("wg_server_iface", ""),
                            ifaces.get("wg_vps_iface", "")) if v]

    def _zt_configured(self, ctx: Context) -> bool:
        return bool(ctx.config.get("interfaces", {}).get("zt_iface", ""))

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system
        wg_ifaces = self._wg_ifaces(ctx)

        if not wg_ifaces and not self._zt_configured(ctx):
            print("l5: no VPN interfaces configured in machine.conf — nothing to enable "
                  "(configure WireGuard/ZeroTier via `bastion setup`, Phase 5).")
            return

        if sys.is_live:
            for iface in wg_ifaces:
                if sys.exists(f"/etc/wireguard/{iface}.conf"):
                    sys.run("systemctl", "enable", "--now", f"wg-quick@{iface}")
                else:
                    print(f"l5: WARNING — /etc/wireguard/{iface}.conf absent; generate it "
                          f"(keygen + peers) via `bastion setup` (Phase 5). Skipping {iface}.")
            if self._zt_configured(ctx):
                sys.run("systemctl", "enable", "--now", ZT_UNIT)
                print("l5: zerotier-one enabled. Join your network with `zerotier-cli join "
                      "<network-id>` (the network ID is installation-specific; never committed).")
            print(f"l5: installed. Managed WG interfaces: {', '.join(wg_ifaces) or 'none'}.")
        else:
            print("l5: staged — L5 owns no bastion files; it only manages wg-quick@/zerotier-one "
                  "for the configured interfaces (skipped: root != / or dry-run).")

    def uninstall(self, ctx: Context) -> None:
        sys = ctx.system
        if sys.is_live:
            for iface in self._wg_ifaces(ctx):
                sys.run("systemctl", "disable", "--now", f"wg-quick@{iface}")
            if self._zt_configured(ctx):
                sys.run("systemctl", "disable", "--now", ZT_UNIT)
        # Leave /etc/wireguard/* in place — those are operator secrets, not bastion artifacts.
        print("l5: uninstalled (tunnels brought down; /etc/wireguard keys left untouched).")

    def status(self, ctx: Context) -> LayerStatus:
        sys = ctx.system
        # L5 stages no files; its state is the host's service/interface state. Under a non-live
        # root (--root staging) there is nothing bastion-installed to report.
        if not sys.is_live:
            return LayerStatus(self.name, self.title, False, False,
                               "host-managed (wg/zerotier) — inspect on the live system")
        wg_ifaces = self._wg_ifaces(ctx)
        up = [i for i in wg_ifaces if sys.run("ip", "link", "show", i).returncode == 0]
        zt_active = sys.unit_active(ZT_UNIT)
        installed = sys.command_exists("wg") or sys.command_exists("zerotier-cli")
        active = bool(up) or zt_active
        if not installed:
            detail = "no VPN tooling installed (wireguard-tools / zerotier-one)"
        elif not wg_ifaces and not self._zt_configured(ctx):
            detail = "tooling present; no VPN interfaces configured"
        else:
            parts = []
            if wg_ifaces:
                parts.append(f"wg up: {', '.join(up) or 'none'} of {', '.join(wg_ifaces)}")
            if self._zt_configured(ctx):
                parts.append(f"zerotier: {'active' if zt_active else 'inactive'}")
            detail = "; ".join(parts)
        return LayerStatus(self.name, self.title, installed, active, detail)

    def health_check(self, ctx: Context) -> list[HealthCheck]:
        sys = ctx.system
        checks = [
            HealthCheck("wg present", sys.command_exists("wg")),
            HealthCheck("zerotier-cli present", sys.command_exists("zerotier-cli")),
        ]
        for iface in self._wg_ifaces(ctx):
            checks.append(HealthCheck(f"wg interface {iface} up",
                                      sys.run("ip", "link", "show", iface).returncode == 0))
        if self._zt_configured(ctx):
            checks.append(HealthCheck("zerotier-one active", sys.unit_active(ZT_UNIT)))
        return checks
