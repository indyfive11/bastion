# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-06-15

A large feature release: full IPv6 parity for the threat-intel layer, a terminal
dashboard, a completed operator CLI, and a round of robustness and UX work.

### Added

- **`bastion tui` — a live terminal dashboard and command surface.** Shows layer
  health, nftables set counts, AI timer/proposals, the reconciler audit tail and
  recovery state, and a command palette that can drive every operation. State
  changes ask for a single confirmation; destructive ones (layer teardown,
  firewall reload, network rollback) require a typed confirmation. The command
  surface is a UI-agnostic action layer intended to also back a future GUI.
- **Full IPv6 parity for the managed intel sets.** Every managed set
  (threat-feed, CrowdSec, AI block/ratelimit/tarpit, and `trusted_hosts`) now has
  an `ipv6_addr` sibling, and the whole data path — nftables rules, the feed
  fetcher, the AI collector, and the reconciler's per-family validation/routing —
  handles both families, so a host attacking over IPv6 is filtered like IPv4.
- **The operator CLI is now complete.** New: `verify` (config-drift detection),
  `doctor` (one-shot triage), `snapshot [--name]` / `snapshots` / `rollback [name]`
  (first-class named snapshots over the known-good blob), `confirm`,
  `recovery <start|stop|extend|status>`, `update <feeds|dnsblock>`, and
  `ai <proposals|accept|reject|rollback>` — a real human-review loop for AI
  proposals (nothing auto-applies).
- **Real `bastion setup --bootstrap`** soft-recovery: re-detects from scratch and
  shows where the current config disagrees with the live system.
- Log rotation for the reconciler audit log and the AI proposals queue.

### Changed

- The setup wizard now honours an existing `machine.conf` on re-run (operator
  hand-edits survive), shows a final review/confirm screen before writing, treats
  the install as a transaction (auto-rollback if the core layer fails), and
  validates inputs at the prompt boundary.

### Fixed

- Atomic config writes (temp file + `os.replace`, secrets created `0600`).
- Reconciler audit ids are now collision-proof within a single second.
- `BACKEND_CMD` is parsed with `shlex` so quoted/spaced arguments work.
- A staged `--root` preview now reports an active host firewall (ufw/firewalld)
  instead of only failing at the real apply.
- Plain-language pass over the wizard prompts; clearer cross-distro messaging.

## [1.0.8] - 2026-06-15

### Added

- **The AI analysis cadence is now a first-class control knob.** `ai.timer_interval`
  (how often `edge-ai` runs — rendered into `edge-ai.timer`'s `OnUnitActiveSec`) was a
  silent 4h default. `bastion setup` now prompts for it and validates the value as a
  systemd time span (`4h`, `30min`, `90s`, `2h30m`, `1d`), re-asking on bad input and
  preserving an existing value on reinstall. It is also settable non-interactively with
  `--set timer_interval=...`, with the same validation — a bad value is a clean error,
  not a traceback. To change the cadence after install: edit `ai.timer_interval`, run
  `bastion generate`, then `bastion ai enable`.

### Fixed

- **Re-arming the AI now applies a changed interval.** `bastion ai enable`
  (`edge-ctl ai-enable`) previously ran a bare `systemctl enable --now`, so a regenerated
  `edge-ai.timer` with a new interval would not take effect while a timer was already
  running on the old cadence. It now `daemon-reload`s and restarts the timer, so
  re-running `bastion ai enable` after changing the interval is enough to apply it.

## [1.0.7] - 2026-06-15

A polish pass completing the deferred edge-resilience add-ons from the ES field
findings. Two needed work (both below); the third — the nft TCP-MSS clamp on
forwarded traffic — turned out to already be in the edge ruleset.

### Added

- **The host-resolver leak guard now runs continuously, not just at check-time.**
  `flowcheck`'s `resolv_leak` only fired when an operator ran a check, so a leak
  introduced *later* (a DHCP renew re-pointing `/etc/resolv.conf` at the ISP's public
  resolver, bypassing the hardened dnsmasq→unbound→VPS chain) stayed silent until the
  next manual check. `edge-watchdog`'s steady-state loop now carries `dns_leak_watch`:
  it alerts once and latches (clearing on recovery), exactly like the WAN-carrier guard,
  so the leak is surfaced in steady state and gets the generic no-arch-leak alert push.
  Alert-only — bastion never rewrites `resolv.conf` (the OS/operator's network config).
  Edge mode only, and only when a loopback stub chain is expected.

### Fixed

- **The resolver-leak guard could be fooled by systemd-resolved.** When
  `/etc/resolv.conf` points at the resolved stub (`127.0.0.53`), the check trusted it as
  "local" and stopped — but `resolved` itself may forward to the ISP's resolver, so the
  lookups still leaked. `flowcheck` (and the mirrored `edge-watchdog` probe) now parse
  `resolvectl` for resolved's effective upstreams and flag any non-local one, stripping
  the DNS-over-TLS `#servername` annotation so an address like `9.9.9.9#dns.quad9.net`
  still matches. Best-effort: with no systemd-resolved present, the deep check is a no-op.

## [1.0.6] - 2026-06-15

### Documentation

- **README: dedicated router / firewall-box use case.** Added an edge-mode appliance section
  with grounded minimum/recommended hardware specs (CPU, RAM, NICs, storage, uplink), modeled on
  OPNsense's published baselines and adjusted down because bastion's threat-intel layer (CrowdSec)
  is log-based rather than inline deep-packet inspection. Notes correct a common misconception:
  WireGuard uses ChaCha20-Poly1305 and does **not** require AES-NI.

## [1.0.5] - 2026-06-15

### Fixed

- **A rolled-back AI block could be silently re-applied.** `edge-ctl rollback`
  pruned the intent spool with `str.rstrip("/32")`, which strips any trailing run of
  the characters `/`, `3`, `2` rather than the literal `/32` suffix — so an address like
  `1.2.3.23/32` was mangled to `1.2.3.` and never matched the spooled intent. The intent
  survived, and the reconciler re-added the block on its next pass, undoing the operator's
  rollback. The prune now matches the address by exact and suffix-sliced forms.

## [1.0.4] - 2026-06-15

A second dogfooding/audit pass over the safety mechanisms and the layer
lifecycle, found while hardening the v1.0.3 endpoint work.

### Fixed

- **`bastion layer uninstall l0` could strip the firewall out from under the
  running stack.** Each layer declares `prerequisites`, but they were never enforced.
  Uninstalling L0 while L1–L6 were installed deleted the base nft table (taking the
  feed/crowdsec/AI sets with it) and removed `bastion-recovery` + the kill switch while
  those services kept running. `bastion layer install`/`uninstall` now enforce the
  dependency graph (install requires prerequisites present; uninstall refuses while a
  dependent layer is installed). `--force` overrides for a deliberate out-of-order teardown.
- **The AI signal collector was blind on endpoint nodes.** `edge-ai-collect`
  hardcoded the `inet edge` table (like the kill switch did before v1.0.3), so on an
  endpoint (`inet bastion`) it could never read the current `ai_*` set members and the
  analyzer lost its "already acted" feedback. It now reads `NFT_TABLE`, and its unit
  sources `machine.env`.
- **The AI kill switch could report success while doing nothing.** `edge-ctl panic`
  and `ai-disable` always exited 0 even when every `nft flush` failed (e.g. the managed
  table was gone). They now exit non-zero and print an honest "incomplete" headline when
  a flush fails; a clean node is unaffected.
- **`bastion-recovery` could leave a privileged backdoor user if interrupted.**
  `do_start` creates an ephemeral OTP user with NOPASSWD sudo before arming the
  self-destruct timer; an interruption in that window (start timeout, Ctrl-C, OOM) left
  the user and sudoers drop-in with nothing to remove them. A cleanup trap now tears the
  partial recovery surface down on signal, and is cleared only once the self-destruct is armed.

### Changed

- **Clarified Expert AI depth.** `ai.depth` controls how much config the AI is *shown*,
  not what it can apply: base/access changes (e.g. SSH port) are always routed to the
  human-review queue and never auto-applied at any depth. `expert_canary_seconds` /
  `expert_confidence_floor` are documented as reserved/inert placeholders for a future
  auto-apply path that does not exist yet.

## [1.0.3] - 2026-06-15

Endpoint-mode dogfooding pass: a live install on an ordinary laptop surfaced a
cluster of bugs where edge assumptions leaked into endpoint mode, plus a wizard
gap. None affect edge nodes; all were found and fixed against a real endpoint.

### Fixed

- **The AI kill switch was inert on endpoint nodes.** `edge-ctl panic`,
  `edge-ctl ai-disable`, and `edge-ctl rollback` hardcoded the `inet edge` table, so on
  an endpoint (whose table is `inet bastion`) they flushed a table that does not exist
  and **printed success while doing nothing**. `edge-ctl` now reads `NFT_TABLE` from the
  environment / `machine.env`. The human kill switch works in both modes.
- **The firewall did not survive a reboot.** `bastion layer install l0` loaded the
  ruleset with `nft -f` but never enabled `nftables.service`, so the firewall was gone
  after a reboot. L0 install now `systemctl enable --now nftables`; uninstall disables it.
- **`net-snapshot` / `net-rollback` hardcoded `inet edge`** when detecting the
  known-good firewall, the same class of bug as the kill switch. Both now honor
  `NFT_TABLE`.
- **Mode detection misread an endpoint as an edge node.** A Wi-Fi laptop was proposed
  as `edge` and offered an unplugged NIC and an example subnet. Detection now treats a
  Wi-Fi default route as endpoint, requires two **carrier-up** physical NICs for edge,
  and prefers an up, addressed interface for the endpoint LAN.
- **SSH-port detection missed `sshd_config.d/*.conf` drop-ins** during non-root setup,
  so a non-default SSH port could be lost. Detection now reads the drop-in directory.
- **Read-only health checks reported false failures.** nft table/set checks that need
  root now report `[????] needs root to verify` instead of `[FAIL]` when run unprivileged.
- **`flowcheck` mislabeled a loaded firewall as inactive.** `nftables.service` is a
  oneshot unit, so `is-active` reads `inactive` even when the ruleset is loaded.
  `flowcheck` now reports `is-enabled` (the truthful persistence signal).
- **`lan-verify` showed a misleading error on endpoints.** It now reports cleanly that
  LAN-client relay verification is not applicable to a non-routing endpoint.

### Added

- **`bastion setup --set KEY=VALUE`** (repeatable) — set any wizard answer
  non-interactively, so setup is fully scriptable. Previously a piped (non-TTY) run
  silently accepted all detected defaults with no way to override a value such as
  `trusted_hosts`. Unknown keys are rejected.

## [1.0.2] - 2026-06-14

### Fixed

- **Refuse to flush an active OS firewall.** bastion's nftables ruleset begins with
  `flush ruleset`, so installing the core firewall (via `bastion setup` or
  `bastion layer install l0`) while **ufw** or **firewalld** was active would have wiped
  that firewall's rules and left the two fighting. Setup and L0 install now detect an
  active ufw/firewalld and abort with instructions to disable it first. Override with
  `BASTION_ALLOW_FIREWALL_TAKEOVER=1` if you really want bastion to take over.

## [1.0.1] - 2026-06-14

### Fixed

- **Endpoint mode hardening.** `bastion setup` now blanks edge-only configuration
  (relay, WireGuard, gateway, DHCP, DNS upstream) when building an endpoint machine
  config, so endpoint nodes no longer inherit stale edge values from the example skeleton.
- `flowcheck` / `bastion check` is now mode-aware: an endpoint no longer reports false
  failures for edge-only flows (relay handshake, WireGuard server interface, local DNS
  listener, ISP-DNS-leak guard).
- `edge-watchdog` never rolls back on an endpoint: a sustained egress loss on a
  non-routing node is alert-only — it has no edge config to repair, and rolling back
  edge network state could disrupt an ordinary workstation.

## [1.0.0] - 2026-06-14

First public release.

### Added

- Seven composable layers (L0 core, L1 feeds, L2 crowdsec, L3 ai-analysis, L4 dns-dhcp,
  L5 vpn, L6 monitoring) for both edge and endpoint modes.
- Operator CLI: `setup`, `generate`, `status`, `layer`, `firewall`, `ai`, `check`.
- Intelligent setup wizard with topology detection, profile recommendation, package
  installation, config generation, and post-install verification.
- Provider-agnostic AI analysis backend (Claude / mock / local) that receives only
  sanitized topology signals.
- Reconciler as the sole writer to managed nftables sets, fed by threat feeds and CrowdSec.
- Resilience: standing watchdog with snapshot/rollback, always-installed recovery service,
  WAN-carrier-aware self-heal, and a human kill switch.
- WireGuard / ZeroTier setup with key generation and an optional interface MTU knob.
- DNS sinkhole (ads / trackers / malware) and host-resolver leak detection.
