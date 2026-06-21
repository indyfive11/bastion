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
LAPI_DEFAULT_PORT = 8080          # CrowdSec's local API default (127.0.0.1:8080)


def _lapi_port_conflict(sys, port: int, bind: str = "127.0.0.1") -> bool:
    """True if a LISTENing socket would actually CLASH with binding ``bind:port`` (crowdsec's LAPI
    default 127.0.0.1:8080). A clash needs a listener on ``bind`` itself OR a wildcard listener
    (0.0.0.0 / :: / *) on ``port`` — those share the address. A listener on a DIFFERENT specific
    address (e.g. another service on 10.0.0.1:8080) does NOT clash: separate sockets coexist (this is
    the F8 false-positive fix — the old check matched the port on any address). Fail-soft: ss missing
    or unparseable -> False, so an install is never blocked on a check we couldn't run."""
    res = sys.run("ss", "-ltnH")
    if res.returncode != 0:
        return False
    for line in res.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        addr, _, p = fields[3].rpartition(":")   # Local Address:Port column
        if p != str(port):
            continue
        addr = addr.strip("[]")                  # "[::]" -> "::"
        if addr == bind or addr in ("0.0.0.0", "::", "*"):
            return True
    return False


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

        have_cscli = sys.command_exists("cscli")
        if not have_cscli:
            print("l2: WARNING — cscli not found; install the 'crowdsec' package first. "
                  "On Arch it is AUR-only (e.g. `paru -S crowdsec`); bastion does not build it "
                  "for you. Then re-run `bastion layer install l2`.")

        if not sys.exists(f"{ctx.sbin_dir}/edge-reconciler"):
            print("l2: WARNING — edge-reconciler (L1) is not installed; cs_block will not be "
                  "populated until L1 is installed (L2 prerequisite).")

        if not sys.is_live:
            print("l2: staged — L2 owns no bastion files; it only manages the system "
                  "crowdsec.service (skipped: root != / or dry-run).")
            return

        # Don't claim to have enabled a service whose package isn't installed — the unit doesn't
        # exist, so `systemctl enable --now` would just error and the old success line lied.
        if not have_cscli:
            print("l2: crowdsec package absent — NOT enabling crowdsec.service (the unit does not "
                  "exist yet). Install crowdsec, then re-run `bastion layer install l2`.")
            return

        # CrowdSec's local API defaults to 127.0.0.1:8080; if that port is already taken the daemon
        # FATALs 'address already in use' on start (a silent failure: enable succeeds, start dies).
        # Warn (don't block) with the concrete fix before we try to start it. But if crowdsec is
        # ALREADY active it legitimately owns that socket — a re-install/upgrade must NOT warn about
        # crowdsec's OWN LAPI listener (F14: the self-collision false positive on the install path;
        # dry-run never tripped it because it skips this live check entirely).
        if not sys.unit_active(UNIT) and _lapi_port_conflict(sys, LAPI_DEFAULT_PORT):
            print(f"l2: WARNING — TCP :{LAPI_DEFAULT_PORT} is already in use. CrowdSec's local API "
                  f"(LAPI) defaults to 127.0.0.1:{LAPI_DEFAULT_PORT} and will FATAL 'address "
                  "already in use' on start. Move it to a free port in BOTH "
                  "/etc/crowdsec/config.yaml (api.server.listen_uri) and "
                  "/etc/crowdsec/local_api_credentials.yaml (url), then `systemctl restart crowdsec`.")

        if sys.run("systemctl", "enable", "--now", UNIT).returncode == 0:
            print("l2: crowdsec.service enabled + started. The reconciler picks up its "
                  "decisions into cs_block on the next pass (≤60s).")
        else:
            print(f"l2: WARNING — `systemctl enable --now {UNIT}` did not succeed. Check "
                  "`systemctl status crowdsec` / `journalctl -u crowdsec` (a busy LAPI port is "
                  "the common cause).")

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
