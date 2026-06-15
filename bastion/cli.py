"""bastion CLI entry point.

Phase 2 implements `bastion generate [--check]`. Other subcommands arrive in later phases.
"""
from __future__ import annotations

import argparse
import os
import sys
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


def cmd_generate(args: argparse.Namespace) -> int:
    templates_dir = find_templates_dir(args.templates)
    conf_path = state.find_conf(args.conf)
    config = state.load_conf(conf_path)
    mode = config.get("machine", {}).get("mode", "edge")
    active_rels = active_template_rels(config, mode)

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
        print(f"  {layer.name}: no supported package manager detected — ensure installed: "
              f"{', '.join(pkgs)}")
        return
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
        if args.action == "install":
            _install_layer_packages(ctx, layer)
        try:
            getattr(layer, args.action)(ctx)
        except FirewallConflict as exc:
            print(f"{args.name}: ABORT — {exc}", file=sys.stderr)
            return 1
        return 0
    return 2


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
_AI_ACTIONS = {"enable": "ai-enable", "disable": "ai-disable", "panic": "panic", "status": "status"}


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
    return sys_.run(edge_ctl, _AI_ACTIONS[args.action], capture=False).returncode


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
                 overrides=overrides)
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

    lay = sub.add_parser("layer", help="manage an individual layer")
    lay.add_argument("action", choices=["status", "install", "uninstall"])
    lay.add_argument("name", help="layer id, e.g. l0")
    lay.add_argument("--conf", help="path to machine.conf")
    lay.add_argument("--root", help="operate under this base dir instead of / (staged install/testing)")
    lay.add_argument("--templates", help="path to templates/ dir")
    lay.add_argument("--scripts", help="path to scripts/ dir")
    lay.set_defaults(func=cmd_layer)

    fw = sub.add_parser("firewall", help="manage the live nftables ruleset")
    fw.add_argument("action", choices=["reload", "status"])
    fw.add_argument("--conf", help="path to machine.conf")
    fw.add_argument("--root", help="operate under this base dir instead of /")
    fw.set_defaults(func=cmd_firewall)

    ai = sub.add_parser("ai", help="control the L3 AI analysis layer (operator kill switch)")
    ai.add_argument("action", choices=["enable", "disable", "panic", "status"],
                    help="enable/disable arm the AI timer; panic flushes ai_* now; status shows state")
    ai.add_argument("--conf", help="path to machine.conf")
    ai.add_argument("--root", help="operate under this base dir instead of /")
    ai.set_defaults(func=cmd_ai)

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
