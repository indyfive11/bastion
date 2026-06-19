# Command reference

The full `bastion` CLI. Every command accepts `--conf PATH` (point at a non-standard
`machine.conf`) and most accept `--root DIR` (operate under a staged tree instead of `/`, for
chroot/bootstrap/testing — no live kernel or systemd is touched under `--root`). Run `bastion
<command> --help` for the authoritative, version-matched flags.

Anything that loads nft rules, installs units, or installs packages needs **root**.

## Setup & configuration

| Command | What it does |
|---|---|
| `bastion setup` | Guided wizard: detect topology → confirm mode/profile → write `/etc/bastion/machine.conf` → generate configs → install packages → bring layers up → verify. The intended install path. |
| `bastion setup --dry-run` | Walk the wizard and print what *would* be written/installed. Writes nothing, makes no API calls — safe offline. |
| `bastion setup --profile <p>` | Skip profile selection. `p` = `full-edge` / `basic-edge` / `full-endpoint` / `minimal-endpoint` / `custom`. |
| `bastion setup --set KEY=VALUE` | Answer a prompt non-interactively (overrides detection *and* prompts). Repeatable: `--set lan_iface=eth1 --set ssh_port=1111`. Enables fully scripted installs. |
| `bastion setup --bootstrap` | Soft recovery: re-detect from scratch, do **not** trust the existing `machine.conf` for detected values, and show where it disagrees with the live system (the "wrong SSH port locked me out" case). |
| `bastion setup --no-ai` | Skip AI-assisted setup (setup is always rule-based today; flag reserved). |
| `bastion generate` | Re-render every active layer's templates from `machine.conf` → `/etc/bastion/machine.env` + config files. Run after editing `machine.conf`. |
| `bastion generate --check` | Validate that every template placeholder resolves. Writes nothing, no network — the config gate used in CI. |

## Inspection

| Command | What it does |
|---|---|
| `bastion status` | Per-layer install/active state. Add `--json` for the machine-readable projection (a status-scoped slice of `bastion state`). |
| `bastion status --health` | …plus each layer's health checks (binaries present, sets loaded, units enabled). |
| `bastion tui` | Live terminal dashboard: layer health, nftables set counts, AI timer/proposals, reconciler audit tail, recovery state, and a command palette that can drive every operation. Needs `python-textual`. |
| `bastion verify` | Drift check: do the live configs match what `bastion generate` would produce now? Flags hand-edits and stale renders. Add `--json` for the structured drift report. |
| `bastion doctor` | One-shot triage of a sick box: required binaries, config drift, reboot persistence, recovery readiness, AI state. Read-only. Add `--json` for the structured triage report. |
| `bastion check` | Connectivity/flow checks (wraps L6 `flowcheck`): egress, DNS, firewall state. Read-only, no root. |
| `bastion check --full` | …also run the LAN forward-path check (`lan-verify`). |
| `bastion check --lan` | Run *only* the LAN forward-path check — run it while a LAN client is generating traffic. |

## Layers & firewall

| Command | What it does |
|---|---|
| `bastion layer status <id>` | State of one layer (e.g. `l0`). |
| `bastion layer install <id>` | Install one layer (renders its templates, installs its resolvable packages, does the live nft/systemd work). |
| `bastion layer uninstall <id>` | Remove one layer. Blocked if other layers depend on it — `--force` to override. |
| `bastion firewall status` | Show the live nftables ruleset state. |
| `bastion firewall reload` | Re-apply the rendered ruleset (`nft -f`). |
| `bastion zones list` | Show the `[zones]` inbound-access rules (`source -> action`). |
| `bastion zones add <name> <source> <all\|ports…>` | Add/replace a zone, then generate + reload. `source` = `any` / IP-or-CIDR / `iface:NAME`; ports are space-separated (`8096 53/udp`). |
| `bastion zones remove <name>` | Delete a zone, then generate + reload. |
| `bastion switch [--minutes N]` | **Deadman cutover.** Print the manual rollback one-liner, snapshot, apply (generate + reload), then arm an auto-revert timer (default 10 min) that runs `net-rollback` unless `bastion confirm` cancels it. `--dry-run` previews only. Live-only; needs root. |

See **[options/zones-and-ownership.md](options/zones-and-ownership.md)** for zones, ownership mode
(`firewall_scope`), and `switch` in depth.

## AI layer (L3) — operator kill switch

Nothing the AI proposes for base/access config (e.g. an SSH-port change) is ever auto-applied; it
goes to a human-review queue. These verbs are the controls.

| Command | What it does |
|---|---|
| `bastion ai status` | Timer state, last run, counts, pending proposals. |
| `bastion ai enable` / `disable` | Arm / disarm the analysis timer. |
| `bastion ai panic` | Immediately flush the `ai_*` nftables sets (drop everything the AI added). |
| `bastion ai proposals` | List the human-review queue. |
| `bastion ai accept <id>` / `reject <id>` | Resolve a proposal. |
| `bastion ai rollback <id>` | Undo one applied audit record. |

## Network safety net (known-good state, watchdog, recovery)

| Command | What it does |
|---|---|
| `bastion snapshot` | Capture current known-good network/firewall state (`net-snapshot`). |
| `bastion snapshot --name <n>` | …and also save it as a named snapshot. |
| `bastion snapshots` | List the auto snapshot + any named ones. |
| `bastion rollback [name]` | Restore a snapshot (`net-rollback`). Omit the name for the auto slot; `--reason "..."` is logged. |
| `bastion confirm` | Confirm egress is stable (~45 s), then disarm the watchdog and accept the current config as the new baseline (`net-confirm`). Also cancels a pending `bastion switch` deadman. |
| `bastion recovery start` | Stand up the emergency console-initiated rescue SSH (ephemeral user + one-time password on a free port; self-destructs after the window). Run from the **console**. |
| `bastion recovery stop` / `extend` / `status` | Tear down / extend the window / report state. |

## Maintenance

| Command | What it does |
|---|---|
| `bastion feeds <list\|add\|remove> [url]` | Manage the IP-blocklist feed URLs `edge-feed-fetch` pulls (blank = built-in defaults). |
| `bastion dnsblock <list\|add\|remove> [url]` | Manage the DNS-sinkhole blocklist feed URLs (L4). |
| `bastion update feeds` | Refresh the threat-intel feeds now (runs the timer's oneshot). |
| `bastion update dnsblock` | Rebuild the DNS sinkhole now (L4). |

See **[troubleshooting.md](troubleshooting.md)** when a command reports a failure.
