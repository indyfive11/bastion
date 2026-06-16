"""bastion CLI entry point.

Phase 2 implements `bastion generate [--check]`. Other subcommands arrive in later phases.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import templates, state
from . import layers as layermod
from .layers.base import Context, FirewallConflict
from .system import System

# Templates that are pure examples / have no managed destination — skipped by generate's
# write step (still placeholder-checked, since they simply contain none).
SKIP_WRITE = {"notify-alert.conf.example"}


def find_templates_dir(explicit: str | None = None) -> Path:
    """Locate the templates/ directory: explicit arg, $BASTION_TEMPLATES, the packaged
    bastion/templates (ships with the wheel), or a cwd fallback for dev checkouts."""
    if explicit:
        return Path(explicit)
    env = os.environ.get("BASTION_TEMPLATES")
    if env:
        return Path(env)
    for candidate in (Path(__file__).resolve().parent / "templates", Path.cwd() / "templates"):
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("templates/ directory not found; pass --templates")


def iter_templates(templates_dir: Path):
    """Yield every regular file under templates/ (recursively), relative path + abs path."""
    for path in sorted(templates_dir.rglob("*")):
        if path.is_file():
            yield path.relative_to(templates_dir), path


def manifest_dest(rel: Path, mode: str, out_base: Path) -> Path | None:
    """Map a template relative path to its destination, or None if it isn't written.

    `out_base` is prepended (default '/'), so tests can redirect writes into a temp dir.
    The edge/endpoint nft template is selected by machine mode.
    """
    name = rel.as_posix()
    if name in SKIP_WRITE:
        return None
    mapping = {
        "dnsmasq.conf": "/etc/dnsmasq.conf",
        "unbound.conf": "/etc/unbound/unbound.conf",
        "backend.conf": "/etc/edge-ai/backend.conf",
        "intent.schema.json": "/etc/edge-ai/intent.schema.json",
        "policy.allowlist": "/etc/edge-reconciler/policy.allowlist",
    }
    if name == "nftables-edge.nft":
        return None if mode == "endpoint" else _join(out_base, "/etc/nftables.conf")
    if name == "nftables-endpoint.nft":
        return _join(out_base, "/etc/nftables.conf") if mode == "endpoint" else None
    if name.startswith("systemd/"):
        return _join(out_base, "/etc/systemd/system/" + rel.name)
    if name in mapping:
        return _join(out_base, mapping[name])
    return None  # unknown template — checked but not auto-written


def _join(out_base: Path, abs_path: str) -> Path:
    return out_base / abs_path.lstrip("/")


def active_template_rels(config: dict, mode: str) -> set[str]:
    """Template relpaths owned by the machine.conf's active layers (drives generate's scope so a
    partial profile never writes configs for layers it isn't installing — e.g. no dnsmasq.conf on
    an endpoint). Falls back to ALL layers when [machine] layers is unset."""
    declared = config.get("machine", {}).get("layers", "")
    ids = [l.strip() for l in declared.split(",") if l.strip()] or list(layermod.REGISTRY)
    rels: set[str] = set()
    for lid in ids:
        layer = layermod.get(lid)
        if layer:
            rels |= layer.owned_templates(mode)
    return rels


def _nft_syntax_check(text: str) -> tuple[bool, str | None]:
    """Parse-check a rendered nft ruleset with `nft -c` (no kernel commit), returning (ok, message).
    Prefers an unprivileged netns (`unshare -rn`) so it works without root. Only reports a FAILURE
    when the checker actually parsed our ruleset and rejected it (its error names the temp file);
    any environmental failure (no nft, userns disabled, no netlink) is a skip, so `generate --check`
    still runs on a toolless CI box rather than false-failing."""
    nft = shutil.which("nft")
    if not nft:
        return True, "skipped (nft not installed)"
    fd, path = tempfile.mkstemp(suffix=".nft")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        candidates = []
        if shutil.which("unshare"):
            candidates.append(["unshare", "-rn", nft, "-c", "-f", path])
        candidates.append([nft, "-c", "-f", path])
        for argv in candidates:
            p = subprocess.run(argv, capture_output=True, text=True)
            if p.returncode == 0:
                return True, None
            err = (p.stderr or p.stdout).strip()
            if path in err:                     # the checker parsed our ruleset and rejected it
                return False, err
            # else: environmental failure (userns/netlink) — fall through to the next candidate
        return True, "skipped (no usable nft checker / insufficient privilege)"
    finally:
        os.unlink(path)


def cmd_generate(args: argparse.Namespace) -> int:
    templates_dir = find_templates_dir(args.templates)
    conf_path = state.find_conf(args.conf)
    config = state.load_conf(conf_path)
    mode = config.get("machine", {}).get("mode", "edge")
    active_rels = active_template_rels(config, mode)

    # A1: type-check the conf values that get spliced into the ruleset/machine.env. Errors (bad
    # CIDR, non-numeric port, ...) block generate; warnings (a default-route LAN) are advisory.
    errs, warns = state.validate_conf(config)
    for w in warns:
        print(f"generate: WARNING — {w}", file=sys.stderr)
    if errs:
        print(f"generate: invalid values in {conf_path}:", file=sys.stderr)
        for e in errs:
            print(f"  {e}", file=sys.stderr)
        return 1

    # Validate machine.env renders (always should; surfaces a malformed conf early).
    env_text = state.render_machine_env(config)

    # Check every ACTIVE-layer template resolves (a machine validates the configs it will write).
    problems: dict[str, list[str]] = {}
    n_active = 0
    for rel, abs_path in iter_templates(templates_dir):
        if rel.as_posix() not in active_rels:
            continue
        n_active += 1
        missing = templates.check_file(abs_path, config)
        if missing:
            problems[rel.as_posix()] = missing

    if problems:
        print(f"generate: unresolved placeholders against {conf_path}:", file=sys.stderr)
        for name, missing in sorted(problems.items()):
            print(f"  {name}: {', '.join(missing)}", file=sys.stderr)
        return 1

    # A1: parse-check the rendered base ruleset so a structurally invalid splice is caught HERE,
    # before it is written and (on a live run) loaded by nftables.service.
    nft_rel = "nftables-endpoint.nft" if mode == "endpoint" else "nftables-edge.nft"
    for rel, abs_path in iter_templates(templates_dir):
        if rel.as_posix() != nft_rel:
            continue
        ok, msg = _nft_syntax_check(templates.render_file(abs_path, config))
        if not ok:
            print(f"generate: rendered {nft_rel} failed `nft -c`:\n{msg}", file=sys.stderr)
            return 1
        break

    if args.check:
        layers_desc = config.get("machine", {}).get("layers", "(all)")
        print(f"generate --check: OK — all placeholders in {n_active} active-layer templates "
              f"[{layers_desc}] resolve against {conf_path}")
        return 0

    # Write step — only active-layer templates.
    out_base = Path(args.out) if args.out else Path("/")
    written = []
    for rel, abs_path in iter_templates(templates_dir):
        if rel.as_posix() not in active_rels:
            continue
        dest = manifest_dest(rel, mode, out_base)
        if dest is None:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(templates.render_file(abs_path, config))
        written.append(str(dest))

    env_dest = _join(out_base, "/etc/bastion/machine.env")
    env_dest.parent.mkdir(parents=True, exist_ok=True)
    env_dest.write_text(env_text)
    written.append(str(env_dest))

    print(f"generate: wrote {len(written)} file(s) (mode={mode}):")
    for w in written:
        print(f"  {w}")
    return 0


def find_scripts_dir(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    for candidate in (Path(__file__).resolve().parent / "scripts", Path.cwd() / "scripts"):
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parent / "scripts"  # best effort; only needed for install


def build_context(args: argparse.Namespace) -> Context:
    """Assemble the layer Context. machine.conf is optional (a fresh system has none)."""
    try:
        config = state.load_conf(state.find_conf(getattr(args, "conf", None)))
    except FileNotFoundError:
        config = {}
    root = Path(getattr(args, "root", None) or "/")
    return Context(
        system=System(root=root),
        config=config,
        templates_dir=find_templates_dir(getattr(args, "templates", None)),
        scripts_dir=find_scripts_dir(getattr(args, "scripts", None)),
    )


def _print_status(st, show_health: bool, ctx: Context, layer) -> None:
    inst = "yes" if st.installed else "no"
    act = "yes" if st.active else "no"
    print(f"  {st.name:<4} {st.title:<10} installed: {inst:<4} active: {act}")
    if st.detail:
        print(f"       {st.detail}")
    if show_health:
        for chk in layer.health_check(ctx):
            mark = "????" if getattr(chk, "unknown", False) else ("OK  " if chk.ok else "FAIL")
            print(f"       [{mark}] {chk.name}" + (f" — {chk.detail}" if chk.detail else ""))


def cmd_status(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    print(f"bastion status (mode={ctx.mode}, root={ctx.system.root})")
    any_installed = False
    for layer in layermod.all_layers():
        st = layer.status(ctx)
        any_installed = any_installed or st.installed
        _print_status(st, args.health, ctx, layer)
    if not any_installed:
        print("  (no layers installed yet — run `bastion setup`)")
    return 0


def _install_layer_packages(ctx: Context, layer) -> None:
    """Install a layer's package dependencies before its install() runs (Option 1: layer install
    is self-sufficient — no separate manual pacman step). Reuses pkg.py: resolvable packages are
    installed idempotently (`pacman -S --needed`); packages the manager can't resolve (e.g.
    crowdsec, AUR-only on Arch) are surfaced as an operator prerequisite, non-fatal — the layer's
    own install() then warns about the still-missing binary. Staged/dry roots print the command
    but install nothing (pkg.install is no-op when not live). The wizard's batch equivalent
    (setup step 7) is a deferred follow-on built on top of this."""
    from .setup import pkg as pkgmod
    pkgs = list(getattr(layer, "packages", ()))
    if not pkgs:
        return
    mgr = pkgmod.detect_manager(ctx.system, ctx.config.get("machine", {}).get("distro"))
    if mgr is None:
        unsupported = pkgmod.unsupported_present(ctx.system)
        if unsupported:
            print(f"  {layer.name}: {unsupported} is detected but not yet supported by bastion "
                  "(supported: Arch/pacman, Debian-Ubuntu/apt, Fedora-RHEL/dnf) — install these "
                  f"manually, then re-run: {', '.join(pkgs)}")
        else:
            print(f"  {layer.name}: no supported package manager detected — ensure installed: "
                  f"{', '.join(pkgs)}")
        return
    mgr.refresh(ctx.system)        # sync the package DB once per run (no-op if already synced)
    res = mgr.install(ctx.system, pkgs)
    if not res.command and not res.unavailable:
        print(f"  {layer.name}: packages already present ({', '.join(pkgs)})")
    elif res.ran:
        ok = "OK" if res.returncode == 0 else f"FAILED (rc={res.returncode})"
        print(f"  {layer.name}: installed via {mgr.name} [{ok}]: {' '.join(res.command)}")
    elif res.command:
        print(f"  {layer.name}: would install via {mgr.name}: {' '.join(res.command)} "
              "(not live — staged)")
    if res.unavailable:
        print(f"  {layer.name}: {mgr.unavailable_hint(res.unavailable)}")


def cmd_layer(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    layer = layermod.get(args.name)
    if layer is None:
        print(f"unknown layer: {args.name} (known: {', '.join(layermod.REGISTRY)})", file=sys.stderr)
        return 2
    if args.action == "status":
        _print_status(layer.status(ctx), True, ctx, layer)
        return 0
    if args.action in ("install", "uninstall"):
        if os.geteuid() != 0 and ctx.system.root == Path("/"):
            print(f"layer {args.action} requires root (or use --root for a staged tree)", file=sys.stderr)
            return 1
        if not getattr(args, "force", False):
            blocked = _prerequisite_block(ctx, layer, args.action)
            if blocked:
                print(f"{args.name}: ABORT — {blocked} (use --force to override)", file=sys.stderr)
                return 1
        if args.action == "install":
            _install_layer_packages(ctx, layer)
        try:
            getattr(layer, args.action)(ctx)
        except FirewallConflict as exc:
            print(f"{args.name}: ABORT — {exc}", file=sys.stderr)
            return 1
        return 0
    return 2


def _prerequisite_block(ctx: Context, layer, action: str) -> str | None:
    """Enforce the layer dependency graph declared in each Layer.prerequisites. Returns a reason
    string if the action must be blocked, else None.

    - install: every prerequisite layer must already be installed (e.g. L3 needs L0+L1). Installing
      a layer whose base table / feeds are absent leaves it half-wired.
    - uninstall: no STILL-INSTALLED layer may depend on this one. Without this, `uninstall l0`
      deletes the base nft table (taking L1/L2/L3's sets with it) AND removes bastion-recovery +
      the kill switch while the dependent services keep running — Commandment 'recovery always in
      L0' / 'kill switch always present'. Tear down in reverse order (l6..l0) and this passes."""
    try:
        if action == "install":
            missing = [p for p in layer.prerequisites
                       if not (layermod.get(p) and layermod.get(p).status(ctx).installed)]
            if missing:
                return (f"requires {', '.join(missing)} installed first "
                        f"(prerequisites: {', '.join(layer.prerequisites)})")
        else:  # uninstall — reverse-dependency check
            dependents = [other.name for other in layermod.all_layers()
                          if layer.name in getattr(other, "prerequisites", ())
                          and other.status(ctx).installed]
            if dependents:
                return (f"still required by installed layer(s) {', '.join(dependents)} — "
                        f"uninstall them first (reverse order)")
    except Exception as exc:  # a status probe failing must not wedge the command
        print(f"warning: prerequisite check incomplete ({exc})", file=sys.stderr)
    return None


def cmd_firewall(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    sys_ = ctx.system
    conf = str(sys_.path("/etc/nftables.conf"))
    if args.action == "reload":
        if not sys_.exists("/etc/nftables.conf"):
            print(f"no ruleset at {conf} — run `bastion generate` / `bastion setup` first", file=sys.stderr)
            return 1
        if sys_.run("nft", "-c", "-f", conf).returncode != 0:
            print("firewall reload: validation (`nft -c`) FAILED — not applied", file=sys.stderr)
            return 1
        rc = sys_.run("nft", "-f", conf, capture=False).returncode
        print("firewall reloaded" if rc == 0 else "firewall reload FAILED")
        return rc
    if args.action == "status":
        family, table = ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")
        res = sys_.run("nft", "list", "table", family, table)
        if res.returncode != 0:
            print(f"firewall: base table {family} {table} not loaded (or need root)")
            return 1
        tables = sys_.run("nft", "list", "tables")
        print(tables.stdout.rstrip() or "(no tables)")
        sets = [ln for ln in res.stdout.splitlines() if "\tset " in ln or ln.strip().startswith("set ")]
        print(f"base table {family} {table}: loaded, {len(sets)} set(s)")
        return 0
    return 2


# `bastion ai <action>` maps to edge-ctl, the L3 operator kill switch (Commandment #6). edge-ctl
# is the implementation (it enforces root and does the nft flush / spool clear / timer toggle); this
# surfaces the human kill switch on the top-level CLI, as the docs and L3 install message promise.
# proposals = list the human-review queue (propose_base_change); accept/reject <id> resolve one;
# rollback <id> = undo one audit record's applied elements. edge-ctl self-elevates (`sudo -n`) for
# every subcommand, so all of these need root regardless.
_AI_ACTIONS = {"enable": "ai-enable", "disable": "ai-disable", "panic": "panic", "status": "status",
               "proposals": "proposals", "rollback": "rollback", "accept": "accept", "reject": "reject"}
_AI_ID_ACTIONS = {"rollback", "accept", "reject"}   # take a trailing <id>


def cmd_ai(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    sys_ = ctx.system
    if not sys_.exists(f"{ctx.sbin_dir}/edge-ctl"):
        print("bastion ai: edge-ctl not installed — run `bastion layer install l3` first",
              file=sys.stderr)
        return 1
    if os.geteuid() != 0 and sys_.root == Path("/"):
        print("bastion ai requires root (the kill switch toggles units and flushes nft sets)",
              file=sys.stderr)
        return 1
    edge_ctl = str(sys_.path(f"{ctx.sbin_dir}/edge-ctl"))
    argv = [edge_ctl, _AI_ACTIONS[args.action]]
    if args.action in _AI_ID_ACTIONS:
        if not getattr(args, "id", None):
            print(f"bastion ai {args.action} needs an id: `bastion ai {args.action} <id>` "
                  "(see ids in `bastion ai proposals` / the reconciler audit log)", file=sys.stderr)
            return 1
        argv.append(args.id)
    return sys_.run(*argv, capture=False).returncode


def cmd_check(args: argparse.Namespace) -> int:
    """Run connectivity/flow checks (§10 verify; founding-doc `bastion check`). Thin wrapper over
    the read-only L6 scripts: `flowcheck` (egress/DNS/relay flows) and `lan-verify` (LAN-client
    forward-path via conntrack). `--lan` runs only lan-verify; `--full` runs both. Read-only, so
    no root requirement — though some optional sub-checks (`sudo -n wg …`) need it to report."""
    ctx = build_context(args)
    sys_ = ctx.system
    if args.lan:
        targets = ["lan-verify"]
    elif args.full:
        targets = ["flowcheck", "lan-verify"]
    else:
        targets = ["flowcheck"]
    rc_total = 0
    for name in targets:
        rel = f"{ctx.sbin_dir}/{name}"
        if not sys_.exists(rel):
            print(f"bastion check: {name} not installed — run `bastion layer install l6` first",
                  file=sys.stderr)
            rc_total = rc_total or 1
            continue
        rc = sys_.run(str(sys_.path(rel)), capture=False).returncode
        rc_total = rc_total or rc
    return rc_total


# --- A1: thin top-level wrappers over the operational scripts (founding-doc §9). The capability
#     lives in the script; these just surface it on the unified `bastion` CLI so an operator never
#     has to remember `net-snapshot`/`net-rollback`/`net-confirm`/`bastion-recovery` by name. ---
def _run_sbin(ctx: Context, name: str, *args: str, need_root: bool = True) -> int:
    sys_ = ctx.system
    rel = f"{ctx.sbin_dir}/{name}"
    if not sys_.exists(rel):
        print(f"bastion: {name} not installed — install the layer that ships it first "
              "(e.g. L6 for the net-* tools, L0 for bastion-recovery)", file=sys.stderr)
        return 1
    if need_root and os.geteuid() != 0 and sys_.root == Path("/"):
        print(f"bastion {name.replace('bastion-', '')}: needs root — run with sudo", file=sys.stderr)
        return 1
    return sys_.run(str(sys_.path(rel)), *args, capture=False).returncode


# --- D4: first-class named snapshots. net-snapshot/net-rollback operate on a single canonical
#     blob (/var/lib/net-safe/snapshot — the watchdog's auto slot); naming is a save/restore layer
#     on top so an operator can keep several known-good points and roll back to one by name. ---
_NET_SAFE = "/var/lib/net-safe"
_SNAP_CANON = f"{_NET_SAFE}/snapshot"        # the canonical/auto slot net-snapshot+watchdog use
_SNAP_NAMED = f"{_NET_SAFE}/snapshots"       # /<name> — named copies
_SNAP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _valid_snapshot_name(name: str) -> bool:
    return bool(_SNAP_NAME_RE.fullmatch(name))


def _save_named_snapshot(sys_: System, name: str) -> bool:
    """Copy the canonical slot to snapshots/<name>. False if there's nothing to copy."""
    canon = sys_.path(_SNAP_CANON)
    if not canon.exists():
        return False
    dest = sys_.path(f"{_SNAP_NAMED}/{name}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(canon, dest)
    return True


def _restore_named_snapshot(sys_: System, name: str) -> bool:
    """Copy snapshots/<name> over the canonical slot so net-rollback restores from it. False if
    the named snapshot doesn't exist."""
    src = sys_.path(f"{_SNAP_NAMED}/{name}")
    if not src.exists():
        return False
    canon = sys_.path(_SNAP_CANON)
    if canon.exists():
        shutil.rmtree(canon)
    canon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, canon)
    return True


def _snapshot_taken_at(d: Path) -> str:
    f = d / "taken-at"
    return f.read_text().strip() if f.exists() else "?"


def cmd_snapshot(args: argparse.Namespace) -> int:
    """Capture known-good network/firewall state (net-snapshot). With --name, also save it as a
    named snapshot you can roll back to later."""
    ctx = build_context(args)
    sys_ = ctx.system
    name = getattr(args, "name", None)
    if name and not _valid_snapshot_name(name):
        print(f"bastion snapshot: invalid name {name!r} (letters/digits/._- , up to 64 chars)",
              file=sys.stderr)
        return 1
    rc = _run_sbin(ctx, "net-snapshot")          # refresh the canonical slot (root-enforced)
    if rc != 0 or not name:
        return rc
    if not _save_named_snapshot(sys_, name):
        print(f"bastion snapshot: net-snapshot produced no {_SNAP_CANON} to name", file=sys.stderr)
        return 1
    print(f"bastion snapshot: saved named snapshot '{name}' -> {_SNAP_NAMED}/{name}")
    return 0


def cmd_snapshots(args: argparse.Namespace) -> int:
    """List the canonical (auto) snapshot and any named snapshots with their capture time."""
    sys_ = build_context(args).system
    canon = sys_.path(_SNAP_CANON)
    print("bastion snapshots:")
    print(f"  {'current (auto)':<18} {_snapshot_taken_at(canon) if canon.exists() else '(none — run `bastion snapshot`)'}")
    base = sys_.path(_SNAP_NAMED)
    named = sorted(d for d in base.iterdir() if d.is_dir()) if base.exists() else []
    for d in named:
        print(f"  {d.name:<18} {_snapshot_taken_at(d)}")
    if not named:
        print("  (no named snapshots — `bastion snapshot --name <name>`)")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    """Restore a snapshot (net-rollback) — idempotent, gentle; safe when state matches. With a
    NAME, restore that named snapshot into the active slot first, then roll back to it."""
    ctx = build_context(args)
    sys_ = ctx.system
    name = getattr(args, "name", None)
    reason = getattr(args, "reason", None) or (f"rollback:{name}" if name else "manual")
    if name:
        if not _valid_snapshot_name(name):
            print(f"bastion rollback: invalid name {name!r}", file=sys.stderr)
            return 1
        if os.geteuid() != 0 and sys_.root == Path("/"):
            print("bastion rollback: needs root — run with sudo", file=sys.stderr)
            return 1
        if not _restore_named_snapshot(sys_, name):
            print(f"bastion rollback: no named snapshot {name!r} (see `bastion snapshots`)",
                  file=sys.stderr)
            return 1
        print(f"bastion rollback: restored named snapshot '{name}' to the active slot; "
              "running net-rollback...")
    return _run_sbin(ctx, "net-rollback", reason)


def cmd_confirm(args: argparse.Namespace) -> int:
    """Confirm egress is genuinely up + stable, then disarm the watchdog (net-confirm)."""
    return _run_sbin(build_context(args), "net-confirm")


def cmd_recovery(args: argparse.Namespace) -> int:
    """Operate the bastion-recovery rescue service (start/stop/extend/status)."""
    # status is read-only (it just reports the rescue user/timer/ports); the mutating actions
    # create the ephemeral user + OTP and toggle the transient unit, so they require root.
    return _run_sbin(build_context(args), "bastion-recovery", args.action,
                     need_root=args.action != "status")


_UPDATE_UNITS = {"feeds": "edge-feed.service", "dnsblock": "edge-dnsblock.service"}


def cmd_update(args: argparse.Namespace) -> int:
    """Trigger a feed/dnsblock refresh now (the systemd oneshot the timer normally runs), instead
    of waiting for the timer. The unit keeps the same sandboxing/StateDirectory as the scheduled run."""
    ctx = build_context(args)
    sys_ = ctx.system
    if os.geteuid() != 0 and sys_.root == Path("/"):
        print("bastion update: needs root — run with sudo", file=sys.stderr)
        return 1
    unit = _UPDATE_UNITS[args.target]
    print(f"bastion update: running {unit} now...")
    rc = sys_.run("systemctl", "start", unit, capture=False).returncode
    if rc == 0:
        extra = " — the reconciler applies the refreshed list within ~60s" if args.target == "feeds" else ""
        print(f"  {unit} completed{extra}.")
    else:
        print(f"  failed to run {unit} — is the layer that provides it installed?", file=sys.stderr)
    return rc


# --- B3: drift detection. Compare each active-layer managed config (and machine.env) to what
#     `bastion generate` would produce right now, so hand-edits / stale files / a failed reload
#     surface instead of silently diverging from machine.conf. ---
def _drift_report(ctx: Context, templates_dir: Path) -> tuple[list[tuple[str, str]], int]:
    """Returns (drift, n_ok): drift is a list of (dest, 'MISSING'|'DRIFTED'); n_ok counts files
    whose on-disk content matches the freshly-rendered template byte-for-byte."""
    sys_, config, mode = ctx.system, ctx.config, ctx.mode
    active_rels = active_template_rels(config, mode)
    drift: list[tuple[str, str]] = []
    n_ok = 0
    for rel, abs_path in iter_templates(templates_dir):
        if rel.as_posix() not in active_rels:
            continue
        dest = manifest_dest(rel, mode, Path("/"))
        if dest is None:
            continue
        want = templates.render_file(abs_path, config)
        live = sys_.path(str(dest))
        if not live.exists():
            drift.append((str(dest), "MISSING"))
        elif live.read_text() != want:
            drift.append((str(dest), "DRIFTED"))
        else:
            n_ok += 1
    env_dest = "/etc/bastion/machine.env"
    env_live = sys_.path(env_dest)
    want_env = state.render_machine_env(config)
    if not env_live.exists():
        drift.append((env_dest, "MISSING"))
    elif env_live.read_text() != want_env:
        drift.append((env_dest, "DRIFTED"))
    else:
        n_ok += 1
    return drift, n_ok


def cmd_verify(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    if not ctx.config:
        print("bastion verify: no machine.conf — run `bastion setup` / `bastion generate` first",
              file=sys.stderr)
        return 1
    templates_dir = find_templates_dir(getattr(args, "templates", None))
    drift, n_ok = _drift_report(ctx, templates_dir)
    print(f"bastion verify (mode={ctx.mode}, root={ctx.system.root}): "
          f"{n_ok} generated file(s) match disk")
    for dest, status in drift:
        print(f"  [{status}] {dest}")
    if drift:
        print(f"  {len(drift)} file(s) differ from `bastion generate`. Re-run `bastion generate` "
              "(then `bastion firewall reload` for the ruleset) to reconcile — or fold your "
              "hand-edits back into machine.conf.")
        return 1
    print("  no drift — live configs match what generate would produce.")
    return 0


# --- D2: one-shot triage. Encodes the dogfood hunt (missing binaries, drift, firewall not
#     persisted, recovery missing, AI off, unreadable secret) as a single read-only command. ---
def cmd_doctor(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    sys_ = ctx.system
    results: list[tuple[str, str, str]] = []

    def add(level: str, name: str, detail: str = "") -> None:
        results.append((level, name, detail))

    if not ctx.config:
        add("FAIL", "machine.conf", "absent — run `bastion setup` / `bastion generate`")
    else:
        add("OK", "machine.conf", f"mode={ctx.mode}, layers={ctx.config.get('machine', {}).get('layers', '')}")

    add("OK", "nft binary") if sys_.command_exists("nft") else \
        add("FAIL", "nft binary", "nftables not installed — the firewall cannot load")

    if sys_.exists("/etc/nftables.conf"):
        if sys_.is_live and not sys_.unit_enabled("nftables.service"):
            add("WARN", "firewall persistence",
                "nftables.service NOT enabled — the ruleset won't reload on reboot "
                "(`sudo systemctl enable nftables`)")
        else:
            add("OK", "firewall ruleset", "/etc/nftables.conf present")
    else:
        add("WARN", "firewall ruleset", "/etc/nftables.conf absent — run `bastion generate`")

    if ctx.config and sys_.is_live and sys_.is_root:
        fam, tbl = ("inet", "bastion") if ctx.mode == "endpoint" else ("inet", "edge")
        add("OK", "base table", f"{fam} {tbl} loaded") if sys_.nft_table_exists(fam, tbl) else \
            add("WARN", "base table", f"{fam} {tbl} not loaded — `bastion firewall reload`")

    if ctx.config:
        try:
            drift, _ = _drift_report(ctx, find_templates_dir(getattr(args, "templates", None)))
            add("WARN", "config drift", f"{len(drift)} file(s) differ — see `bastion verify`") \
                if drift else add("OK", "config drift", "none")
        except Exception as exc:                                       # noqa: BLE001
            add("WARN", "config drift", f"could not check ({exc})")

    add("OK", "recovery", "bastion-recovery installed") \
        if sys_.exists(f"{ctx.sbin_dir}/bastion-recovery") else \
        add("WARN", "recovery", "bastion-recovery missing — reinstall L0 (Commandment: always present)")

    layers = [x.strip() for x in (ctx.config.get("machine", {}).get("layers", "") if ctx.config else "").split(",")]
    if "l3" in layers:
        if sys_.is_live and not sys_.unit_enabled("edge-ai.timer"):
            add("WARN", "ai timer", "edge-ai.timer not enabled — AI analysis is off (`bastion ai enable`)")
        else:
            add("OK", "ai timer", "L3 selected")
        env = "/etc/edge-ai/claude.env"
        if sys_.exists(env):
            try:
                sys_.read(env)
                add("OK", "ai secret", f"{env} readable")
            except Exception:                                          # noqa: BLE001
                add("WARN", "ai secret", f"{env} present but unreadable")

    print(f"bastion doctor (mode={ctx.mode}, root={sys_.root})")
    for level, name, detail in results:
        print(f"  [{level:<4}] {name}" + (f" — {detail}" if detail else ""))
    fails = sum(1 for lvl, _, _ in results if lvl == "FAIL")
    warns = sum(1 for lvl, _, _ in results if lvl == "WARN")
    oks = sum(1 for lvl, _, _ in results if lvl == "OK")
    print(f"  {fails} fail, {warns} warn, {oks} ok")
    return 1 if fails else 0


def cmd_tui(args: argparse.Namespace) -> int:
    """Launch the read-only terminal dashboard (D1). Lazily imports Textual so the rest of the CLI
    works without the optional dep; a missing dep yields a friendly hint, not a traceback."""
    from . import tui
    ctx = build_context(args)
    try:
        return tui.run_tui(ctx)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def cmd_state(args: argparse.Namespace) -> int:
    """Emit the canonical world-state document (Innovation #1) — the single versioned snapshot the
    TUI and the future GUI render from, instead of each re-probing the box. Read-only; works under
    --root. Includes the config-drift section when a machine.conf + templates are resolvable."""
    import json as _json
    from . import worldstate
    ctx = build_context(args)
    drift = None
    if ctx.config:
        try:
            drift = _drift_report(ctx, find_templates_dir(getattr(args, "templates", None)))
        except Exception:
            drift = None      # drift is best-effort; the rest of the document still emits
    doc = worldstate.gather_state(ctx, drift=drift)
    print(_json.dumps(doc, indent=(None if getattr(args, "compact", False) else 2), default=str))
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    """Interactive setup wizard (§10). Phase 5: rule-based; --dry-run writes nothing."""
    from .setup.wizard import Wizard, parse_overrides
    root = Path(getattr(args, "root", None) or "/")
    if not args.dry_run and os.geteuid() != 0 and root == Path("/"):
        print("bastion setup requires root (or use --dry-run / --root for a staged preview)",
              file=sys.stderr)
        return 1
    try:
        overrides = parse_overrides(getattr(args, "set", None))
    except ValueError as e:
        print(f"bastion setup: {e}", file=sys.stderr)
        return 1
    wiz = Wizard(System(root=root), dry_run=args.dry_run, profile=args.profile, no_ai=args.no_ai,
                 overrides=overrides, bootstrap=getattr(args, "bootstrap", False))
    result = wiz.run()
    if result.notes:
        print("\nnotes:")
        for n in result.notes:
            print(f"  - {n}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bastion", description="Layered Linux firewall framework.")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="interactive setup wizard (detect, configure, install)")
    setup.add_argument("--dry-run", action="store_true",
                       help="walk the wizard, show what would be written; write nothing, no API calls")
    setup.add_argument("--profile", help="skip profile selection (full-edge|basic-edge|full-endpoint|"
                       "minimal-endpoint|custom)")
    setup.add_argument("--no-ai", action="store_true",
                       help="skip AI-assisted setup (Phase 5 is always rule-based; flag reserved)")
    setup.add_argument("--bootstrap", action="store_true",
                       help="soft recovery: re-detect from scratch, do NOT trust the existing "
                            "machine.conf for detected values, and show where it disagrees with the "
                            "live system (e.g. a wrong SSH port that locked you out)")
    setup.add_argument("--set", action="append", metavar="KEY=VALUE", dest="set",
                       help="set a config answer non-interactively (overrides detection + prompts); "
                            "repeatable, e.g. --set trusted_hosts=10.0.0.2 --set ssh_port=1111")
    setup.add_argument("--root", help="operate under this base dir instead of / (staged preview/testing)")
    setup.set_defaults(func=cmd_setup)

    gen = sub.add_parser("generate", help="resolve templates -> config files")
    gen.add_argument("--check", action="store_true",
                     help="validate all placeholders resolve; write nothing, make no network calls")
    gen.add_argument("--conf", help="path to machine.conf (default: standard search order)")
    gen.add_argument("--templates", help="path to templates/ dir (default: cwd or package dir)")
    gen.add_argument("--out", help="write under this base dir instead of / (for testing/dry-run)")
    gen.set_defaults(func=cmd_generate)

    st = sub.add_parser("status", help="show layer install/active state")
    st.add_argument("--health", action="store_true", help="also run each layer's health checks")
    st.add_argument("--conf", help="path to machine.conf")
    st.add_argument("--root", help="inspect under this base dir instead of / (chroot/bootstrap/testing)")
    st.set_defaults(func=cmd_status)

    tui = sub.add_parser("tui", help="read-only terminal dashboard (layers, sets, AI, audit)")
    tui.add_argument("--conf", help="path to machine.conf")
    tui.add_argument("--root", help="inspect under this base dir instead of / (testing)")
    tui.set_defaults(func=cmd_tui)

    sta = sub.add_parser("state", help="emit the canonical world-state JSON document (the TUI/GUI contract)")
    sta.add_argument("--json", action="store_true", help="(default) machine-readable JSON document")
    sta.add_argument("--compact", action="store_true", help="single-line JSON instead of indented")
    sta.add_argument("--conf", help="path to machine.conf")
    sta.add_argument("--templates", help="templates dir (for the drift section)")
    sta.add_argument("--root", help="inspect under this base dir instead of / (testing)")
    sta.set_defaults(func=cmd_state)

    lay = sub.add_parser("layer", help="manage an individual layer")
    lay.add_argument("action", choices=["status", "install", "uninstall"])
    lay.add_argument("name", help="layer id, e.g. l0")
    lay.add_argument("--conf", help="path to machine.conf")
    lay.add_argument("--root", help="operate under this base dir instead of / (staged install/testing)")
    lay.add_argument("--templates", help="path to templates/ dir")
    lay.add_argument("--scripts", help="path to scripts/ dir")
    lay.add_argument("--force", action="store_true",
                     help="bypass the prerequisite/dependency check (e.g. force-uninstall l0 "
                          "while dependent layers remain)")
    lay.set_defaults(func=cmd_layer)

    fw = sub.add_parser("firewall", help="manage the live nftables ruleset")
    fw.add_argument("action", choices=["reload", "status"])
    fw.add_argument("--conf", help="path to machine.conf")
    fw.add_argument("--root", help="operate under this base dir instead of /")
    fw.set_defaults(func=cmd_firewall)

    ai = sub.add_parser("ai", help="control the L3 AI analysis layer (operator kill switch)")
    ai.add_argument("action", choices=["enable", "disable", "panic", "status", "proposals",
                                       "accept", "reject", "rollback"],
                    help="enable/disable arm the AI timer; panic flushes ai_* now; status shows state; "
                         "proposals lists the review queue; accept/reject <id> resolve a proposal; "
                         "rollback <id> undoes one audit record")
    ai.add_argument("id", nargs="?", help="id for accept/reject/rollback")
    ai.add_argument("--conf", help="path to machine.conf")
    ai.add_argument("--root", help="operate under this base dir instead of /")
    ai.set_defaults(func=cmd_ai)

    snap = sub.add_parser("snapshot", help="capture known-good network/firewall state (net-snapshot)")
    snap.add_argument("--name", help="also save this capture as a named snapshot")
    snap.add_argument("--conf", help="path to machine.conf")
    snap.add_argument("--root", help="operate under this base dir instead of /")
    snap.set_defaults(func=cmd_snapshot)

    snaps = sub.add_parser("snapshots", help="list the auto snapshot + any named snapshots")
    snaps.add_argument("--conf", help="path to machine.conf")
    snaps.add_argument("--root", help="operate under this base dir instead of /")
    snaps.set_defaults(func=cmd_snapshots)

    rb = sub.add_parser("rollback", help="restore a snapshot (net-rollback); pass a name for a named one")
    rb.add_argument("name", nargs="?", help="named snapshot to restore (omit = the auto slot)")
    rb.add_argument("--reason", help="reason string recorded in the log (default: manual)")
    rb.add_argument("--conf", help="path to machine.conf")
    rb.add_argument("--root", help="operate under this base dir instead of /")
    rb.set_defaults(func=cmd_rollback)

    cf = sub.add_parser("confirm", help="confirm egress is stable, then disarm the watchdog (net-confirm)")
    cf.add_argument("--conf", help="path to machine.conf")
    cf.add_argument("--root", help="operate under this base dir instead of /")
    cf.set_defaults(func=cmd_confirm)

    rec = sub.add_parser("recovery", help="operate the bastion-recovery rescue service")
    rec.add_argument("action", choices=["start", "stop", "extend", "status"])
    rec.add_argument("--conf", help="path to machine.conf")
    rec.add_argument("--root", help="operate under this base dir instead of /")
    rec.set_defaults(func=cmd_recovery)

    upd = sub.add_parser("update", help="refresh threat feeds / DNS blocklist now (run the timer's oneshot)")
    upd.add_argument("target", choices=["feeds", "dnsblock"])
    upd.add_argument("--conf", help="path to machine.conf")
    upd.add_argument("--root", help="operate under this base dir instead of /")
    upd.set_defaults(func=cmd_update)

    vfy = sub.add_parser("verify", help="check live configs match what `bastion generate` would produce")
    vfy.add_argument("--conf", help="path to machine.conf")
    vfy.add_argument("--templates", help="path to templates/ dir")
    vfy.add_argument("--root", help="inspect under this base dir instead of /")
    vfy.set_defaults(func=cmd_verify)

    doc = sub.add_parser("doctor", help="triage a sick box (binaries, drift, persistence, recovery, AI)")
    doc.add_argument("--conf", help="path to machine.conf")
    doc.add_argument("--templates", help="path to templates/ dir")
    doc.add_argument("--root", help="inspect under this base dir instead of /")
    doc.set_defaults(func=cmd_doctor)

    chk = sub.add_parser("check", help="run connectivity/flow checks (wraps L6 flowcheck/lan-verify)")
    chk.add_argument("--full", action="store_true",
                     help="also run the LAN forward-path check (lan-verify)")
    chk.add_argument("--lan", action="store_true",
                     help="run only the LAN forward-path check (lan-verify); run while a LAN client "
                          "is generating traffic")
    chk.add_argument("--conf", help="path to machine.conf")
    chk.add_argument("--root", help="operate under this base dir instead of /")
    chk.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
