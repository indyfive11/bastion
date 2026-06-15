"""L3 — ai-analysis. The full edge-ai stack: a privileged read-only collector sanitizes signals
(the no-arch-leak egress boundary), an UNPRIVILEGED analyzer hands them to a pluggable backend and
writes an intents.json spool, and the L1 reconciler (re-validating below the AI) reconciles those
intents into the ai_block / ai_ratelimit / ai_tarpit sets. `edge-ctl` is the operator kill switch.

Pipeline dependency (the canonical §3#3 exception): edge-ai.service Requires= edge-ai-collect.service
— same subsystem, split only for privilege separation, timer-triggered, non-core. The AI layer is
OPT-IN: the timer installs DISABLED and is armed via `bastion ai enable` (Commandment #6 kill switch).

Prerequisites: L0 (base table holds the ai_* sets), L1 (the reconciler that applies intents).
"""
from __future__ import annotations

from .base import Layer, Context, LayerStatus, HealthCheck

AI_USER = "edge-ai"
TIMER = "edge-ai.timer"


class L3AiAnalysis(Layer):
    name = "l3"
    title = "ai-analysis"
    description = "edge-ai collect→analyze→intents pipeline + edge-ctl kill switch (opt-in timer)"
    prerequisites = ("l0", "l1")
    packages = ("python", "curl")      # analyzer is stdlib-only; curl for the claude backend
    scripts = ("edge-ai-collect", "edge-ai-analyze", "edge-ai-backend-claude",
               "edge-ai-backend-mock", "edge-ctl")
    template_dests = (
        ("backend.conf", "/etc/edge-ai/backend.conf"),
        ("intent.schema.json", "/etc/edge-ai/intent.schema.json"),
    )
    units = ("edge-ai-collect.service", "edge-ai.service", "edge-ai.timer")

    runtime_dirs = ("/etc/edge-ai", "/var/lib/edge-ai")

    # --- lifecycle --------------------------------------------------------
    def install(self, ctx: Context) -> None:
        sys = ctx.system

        if not sys.exists(f"{ctx.sbin_dir}/edge-reconciler"):
            print("l3: WARNING — edge-reconciler (L1) not installed; AI intents will not be "
                  "applied until L1 is present (L3 prerequisite).")

        for d in self.runtime_dirs:
            sys.path(d).mkdir(parents=True, exist_ok=True)
        for script in self.scripts:
            self.install_script(ctx, script)
        for template_rel, dest in self.template_dests:
            self.render_to(ctx, template_rel, dest)
        for unit in self.units:
            self.install_unit(ctx, unit)

        if sys.is_live:
            # Unprivileged service identity for the analyzer (idempotent).
            if sys.run("getent", "passwd", AI_USER).returncode != 0:
                sys.run("useradd", "--system", "--no-create-home",
                        "--shell", "/usr/sbin/nologin", AI_USER)
            sys.run("chown", "-R", f"{AI_USER}:{AI_USER}", "/var/lib/edge-ai")
            sys.run("systemctl", "daemon-reload")
            print("l3: installed. AI is OPT-IN and currently DISABLED — arm with "
                  "`bastion ai enable` (or `edge-ctl ai-enable`); kill with `bastion ai panic`.")
        else:
            print("l3: staged install (root != / or dry-run) — files written; edge-ai user, "
                  "ownership, and daemon-reload NOT applied.")

    def uninstall(self, ctx: Context) -> None:
        sys = ctx.system
        if sys.is_live:
            # Stop + disarm the AI cleanly via the kill switch (flushes ai_* + clears the spool).
            sys.run("systemctl", "disable", "--now", TIMER)
            sys.run(f"{ctx.sbin_dir}/edge-ctl", "ai-disable")
            sys.run("systemctl", "daemon-reload")
        for unit in self.units:
            sys.path(f"/etc/systemd/system/{unit}").unlink(missing_ok=True)
        for script in self.scripts:
            sys.path(f"{ctx.sbin_dir}/{script}").unlink(missing_ok=True)
        for _, dest in self.template_dests:
            sys.path(dest).unlink(missing_ok=True)
        print("l3: uninstalled (timer disabled, ai_* flushed via edge-ctl, scripts/configs removed).")

    def status(self, ctx: Context) -> LayerStatus:
        sys = ctx.system
        artifacts = {
            "edge-ai-collect": sys.exists(f"{ctx.sbin_dir}/edge-ai-collect"),
            "edge-ai-analyze": sys.exists(f"{ctx.sbin_dir}/edge-ai-analyze"),
            "edge-ctl": sys.exists(f"{ctx.sbin_dir}/edge-ctl"),
            "backend.conf": sys.exists("/etc/edge-ai/backend.conf"),
            "intent.schema.json": sys.exists("/etc/edge-ai/intent.schema.json"),
            "edge-ai.service": sys.exists("/etc/systemd/system/edge-ai.service"),
            "edge-ai.timer": sys.exists("/etc/systemd/system/edge-ai.timer"),
        }
        installed = all(artifacts.values())
        active = sys.unit_active(TIMER)          # "armed" = timer running
        if not installed:
            missing = [k for k, v in artifacts.items() if not v]
            detail = f"missing: {', '.join(missing)}"
        else:
            detail = "AI armed (timer active)" if active else "installed; AI disarmed (opt-in)"
        return LayerStatus(self.name, self.title, installed, active, detail)

    def health_check(self, ctx: Context) -> list[HealthCheck]:
        sys = ctx.system
        family, table = self._table(ctx)
        return [
            HealthCheck("edge-ai user exists",
                        sys.run("getent", "passwd", AI_USER).returncode == 0),
            HealthCheck("edge-ai-collect installed", sys.exists(f"{ctx.sbin_dir}/edge-ai-collect")),
            HealthCheck("edge-ai-analyze installed", sys.exists(f"{ctx.sbin_dir}/edge-ai-analyze")),
            HealthCheck("edge-ctl installed (kill switch)", sys.exists(f"{ctx.sbin_dir}/edge-ctl")),
            HealthCheck("backend.conf present", sys.exists("/etc/edge-ai/backend.conf")),
            HealthCheck("intent.schema.json present", sys.exists("/etc/edge-ai/intent.schema.json")),
            HealthCheck("edge-ai.service installed", sys.exists("/etc/systemd/system/edge-ai.service")),
            HealthCheck("ai_block set present", sys.nft_set_exists(family, table, "ai_block")),
        ]

    # --- helpers ----------------------------------------------------------
    def _table(self, ctx: Context) -> tuple[str, str]:
        return ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")
