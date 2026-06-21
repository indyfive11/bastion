# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

## [1.5.6] - 2026-06-21

Watchdog failover-resilience hardening, driven by a live incident: an upstream VPN far-end (an
edge node's relay tunnel) died and the **prototype** self-heal logic that bastion's `edge-watchdog`
descends from would have locked the LAN off the internet — the "heal" loop *was* the outage. bastion's
watchdog was already well ahead of that prototype (it has no conntrack-parse bug, preserves the
recovery table across a reload, is mode-aware, and treats ISP outages as alert-only), but it still
shared latent gaps on an edge node with a relay configured. Those are closed here, generically and
config-driven (no hardcoded topology). bastion deliberately does **not** implement forced-tunnel VPN
egress; this is purely about the watchdog never thrashing.

### Fixed

- **A down relay/tunnel interface is no longer treated as "our config broken."** A WireGuard tunnel is
  connectionless, so the interface vanishing means the far-end is gone — an upstream condition a local
  heal or rollback can never repair (re-asserting a dead-tunnel dependency is exactly what loops). The
  `relay-iface-down` fault was removed from `config_ok`; relay forward health stays evidence-based
  (active LAN flows with zero replies), and a dead relay with a working direct-WAN fallback is normal.
- **`heal_light` no longer flushes live state on a hot poll.** When bastion's table is present it now
  only refills the reconciler-managed sets (no ruleset reload); it recreates the table from the static
  config **only when the table is actually gone** (the preamble flush is then moot). Previously, in
  exclusive scope, a per-poll reload briefly dropped all NAT/conntrack.
- **Heals are cooldown-gated.** A new `HEAL_COOLDOWN` (default 900s) floor, stamped per incident (so a
  light→full escalation within one incident still runs), makes the watchdog structurally unable to
  re-heal in a tight loop when the cause is something a heal can't fix.

## [1.5.5] - 2026-06-21

The third VPS dogfood wave: an in-place 1.5.4 upgrade on the production box (fully armed cooperative,
proven across a reboot **and** an unclean host-side suspension) surfaced two operator-clarity bugs on
the *install/confirm* paths that the dry-run gate couldn't reach. Both fixed here.

### Fixed

- **F14 — false CrowdSec LAPI `:8080` collision warning on re-install/upgrade.** The L2 install path
  warned that `127.0.0.1:8080` was busy even when the listener was CrowdSec's *own* already-running
  LAPI (a self-collision). The address-specific check (F8) is correct; the gap was that an
  already-active crowdsec legitimately owns the socket. L2 now suppresses the warning when
  `crowdsec.service` is already active, so an upgrade no longer prints a spurious FATAL warning.
- **F15 — `bastion confirm` stopped the standing L6 watchdog.** `net-confirm` issued
  `systemctl stop edge-watchdog.service` — vestigial from before the transient cutover deadman
  existed. `edge-watchdog` is now the *standing* L6 self-heal (`Restart=always`), so confirming an
  apply silently left the box without ongoing self-heal until reboot. `net-confirm` no longer stops
  it; `bastion confirm` disarms only the transient `bastion-switch-deadman` timer (Python-side).

## [1.5.4] - 2026-06-20

The second wave of the VPS dogfood: live re-validation of 1.5.3 on the production box **confirmed
cooperative coexistence with UFW** (the WireGuard relay and every service stayed up while bastion's
table loaded alongside) and surfaced a tier of lifecycle/hygiene gaps, fixed here.

### Added

- **`bastion teardown`** — the clean counterpart to `bastion setup`: uninstalls every layer (restoring
  `nftables.service` to its pre-bastion state) and removes `/etc/bastion` + `/etc/edge-*`. The AUR
  package runs it from a `pre_remove` hook, so `pacman -R bastionfw` leaves no stale config or units
  behind. `--keep-config` removes layers/units but preserves `machine.conf`.

### Fixed

- **A named snapshot no longer destroys the rollback target.** `bastion snapshot --name X` used to
  refresh the auto slot and then copy it, so it overwrote the pre-install auto-snapshot that
  `bastion rollback` restores. Named snapshots now capture straight into their own slot; the auto slot
  is never touched. `bastion rollback current` (and `auto`) is accepted as the auto slot instead of
  erroring "no named snapshot".
- **`nftables.service` is restored to its pre-bastion state on uninstall.** L0 records whether the
  service was already enabled before it turned it on, and uninstall disables it *only* if bastion
  enabled it — a box that already used the nft loader is left as it was. On uninstall a foreign
  `/etc/nftables.conf` backed up at install (the v1.5.3 guard) is restored, and otherwise bastion's own
  file is removed — so a still-enabled `nftables.service` never fails at boot on a missing ruleset.

### Changed

- **`setup --stage-only` now points at `bastion setup` (not `bastion switch`) for the full apply.**
  `switch` reloads the firewall but does not install layers, so using it as a first apply left the
  layer daemons (feeds, watchdog) unstarted. The message and the README now make the distinction
  explicit: `--stage-only` previews; re-running `bastion setup` installs + arms everything behind the
  deadman; `switch` is for a later config change on an already-installed box.

## [1.5.3] - 2026-06-20

A dogfood-driven hardening release. Pointing `bastion setup` at a real, public, multi-service VPS
(WireGuard relay + mail + DNS behind an active UFW) and at a libvirt workstation surfaced a cluster of
safety and correctness gaps — all addressed here. Cooperative coexistence with UFW was validated live
on the production VPS (the relay and every service stayed up while bastion's table loaded alongside).

### Added

- **`bastion --version` / `-V`** prints the version and exits 0 (previously argparse errored).
- **`bastion setup --stage-only`** writes and generates the config but does *not* load the firewall or
  install layers — review the rendered ruleset, then apply it behind `bastion switch`'s deadman. The
  riskiest first-load never runs unattended.
- **Destination-pinned zones** — a zone may now express a destination: `name = <source> to <dest> ->
  <ports>` renders `ip saddr … ip daddr …`, so a policy like "from the WG subnet *to* this one local
  service IP" is expressible (it wasn't before). UFW synthesis emits these precisely.
- **`bastion setup --set firewall_scope=…`** — the ownership mode (the most safety-critical choice) is
  now pinnable non-interactively.

### Changed

- **`bastion setup` wraps its first live firewall-load in an auto-reverting deadman** (the same unit
  `bastion switch` uses, so `bastion confirm` keeps it; otherwise it rolls back). The guided install no
  longer loads a drop-policy ruleset on a remote box with no safety net.
- **Endpoint SSH-from-LAN auto-trust is now private-subnet only.** A public `lan_cidr` (a VPS whose
  "local /24" is shared datacenter space) is *not* auto-trusted for SSH — the rule is dropped and the
  wizard warns loudly to pin an explicit admin source. Previously a public /24 silently became an SSH
  accept for every neighbor on it.
- **`--no-ai` now actually excludes the L3 AI layer** (it was defined but inert — a silent no-op).
- **Zone synthesis no longer fabricates an over-broad `iface:NAME -> all`** from a *qualified* UFW rule.
  A bare `ufw allow in on wg0` still trusts the whole interface; `ufw allow in on wg0 to 10.0.0.1 port
  8080` now yields the precise `iface:wg0 to 10.0.0.1 -> 8080`. The wizard also flags any `-> all` zone
  that sits beside narrower ones.
- **`status` / `doctor` report `mode=unset` on a fresh box** instead of a misleading default of `edge`.
- The **setup dry-run** now lists *all* interfaces tagged by category (physical/overlay/bridge), and in
  cooperative mode names the co-resident nft tables (and their forwarding/NAT) it will leave intact.
- **`make test-deps`** installs the bench-suite dependency (pytest) the runtime package omits.

### Fixed

- **L0 backs up a foreign, actively-loaded `/etc/nftables.conf`** to `…pre-bastion` and warns before
  overwriting it (a hand-rolled nftables firewall is no longer silently replaced). Only fires on a
  genuinely non-bastion ruleset, so reinstalls and UFW-via-iptables hosts are unaffected.
- **The dry-run install preview no longer puts AUR-only `crowdsec` on the `pacman -S` line** (it would
  fail `target not found`); it is listed as a separate manual step, keeping the previewed command
  copy-pasteable.
- **The L2/CrowdSec `:8080` LAPI check is address-specific** — another service on a *different* address
  (e.g. `10.0.0.1:8080`) no longer false-warns against the LAPI's `127.0.0.1:8080`.

## [1.5.2] - 2026-06-19

### Fixed

- **The wheel now ships the `templates/logrotate/` files, so packaged `layer install l1`/`l3` no longer
  crash.** The package-data spec listed template subdirectories explicitly and never named
  `templates/logrotate/`, so those two extensionless files were absent from every wheel since v1.1.0 —
  a packaged install (`yay -S bastionfw`) hit `FileNotFoundError` in `install_logrotate`. Every live
  install to date was from the source tree or the pre-logrotate v1.0.0 wheel, so it stayed latent until
  a real packaged install on a host surfaced it. The spec now uses a recursive `templates/**/*` glob,
  and a new `test_packaging` regression guard asserts every file under `scripts/` + `templates/` is
  covered by the wheel's package-data.

## [1.5.1] - 2026-06-19

A polish release: more accurate L2/CrowdSec install reporting, a forward-looking detector for
Kubernetes and Tailscale, and a hardened nftables loader unit. Live-validated on a cooperative
libvirt host plus Arch and Debian VMs.

### Changed

- **Detection now names Kubernetes/CNI and Tailscale as self-managing firewalls.** Cooperative scope
  was already proposed for any box carrying a foreign nftables table, so these were covered once their
  rules loaded. They are now also recognized *forward-looking* by service presence (`kubelet`/`k3s`,
  `tailscaled`) — so a freshly-installed node agent or a tailscaled that hasn't programmed its table
  yet still proposes cooperative, and the manager is named in the wizard's scope prompt. The runtime
  foreign-table catch-all remains the backstop for anything unrecognized.

### Fixed

- **`layer install l2` no longer claims to have started crowdsec when the package is absent.** With
  no `crowdsec` package the service unit doesn't exist, yet the installer still printed
  "crowdsec.service enabled + started". It now skips the enable and says the package is absent, and
  reports a warning (instead of a success line) if `systemctl enable --now` fails.
- **`layer install l2` warns when CrowdSec's LAPI port is already taken.** CrowdSec's local API
  defaults to `127.0.0.1:8080`; on a box where `:8080` is in use the daemon FATALs "address already
  in use" on start while the enable appears to succeed. The installer now detects a busy `:8080` and
  points at the `listen_uri` / credentials move before starting the service.
- **The nftables loader drop-in re-asserts `Type=oneshot` + `RemainAfterExit=yes` and clears
  `ExecStop`.** RemainAfterExit makes `systemctl is-active nftables` report `active (exited)` after a
  successful load (not `inactive`) on any distro base unit, so the unit state truthfully reflects that
  the ruleset is loaded. Clearing `ExecStop` (some distros ship `nft flush ruleset` there) keeps a
  `restart`/`stop` from flushing every table — which, now that the unit stays active, would otherwise
  wipe a co-resident manager's table under cooperative scope. The service is a pure loader; tear-down
  stays bastion's scope-aware job.

## [1.5.0] - 2026-06-18

Bastion becomes a general firewall **detect → synthesize → apply engine**. It can now firewall the
full spectrum of hosts — a simple endpoint, an edge router, **and** a server that already runs
libvirt or Docker — by detecting what's on the box, proposing a configuration, and cutting over
behind an auto-reverting safety net. Validated live: edge-VM data plane, real **libvirt** coexistence
in a VM, the full zone matrix synthesized from a real box's existing firewall, and the deadman
cutover.

### Added

- **Zones — a unified `source → action` inbound policy.** A new `[zones]` section maps a source
  (`any`, an IP/CIDR, or a whole interface via `iface:NAME`) to an action (`all`, or a port list like
  `8096, 53/udp`), rendered as inline nftables accepts. Managed with `bastion zones <list|add|remove>`.
  It generalizes `trusted_hosts` (source → `all`) and `service_ports` (`any` → ports), which keep
  working. Inline CIDR rules also sidestep the named-set limitation that constrained `trusted_hosts`.
- **Ownership mode — coexist with libvirt/Docker.** A new `[machine] firewall_scope` chooses
  `exclusive` (default — bastion owns the whole ruleset, `flush ruleset`) or **`cooperative`** (manage
  only bastion's own table, leaving a hypervisor/container engine's NAT/forward tables intact). The
  rollback path is scope-aware: a cooperative rollback deletes only bastion's table.
- **`bastion switch` — deadman cutover.** Applies a firewall change behind an auto-reverting timer:
  it prints the manual rollback one-liner, snapshots, applies, then arms `net-rollback` to fire after
  `--minutes` (default 10) unless `bastion confirm` cancels it. Closes the lockout gap the egress-only
  watchdog can't cover. `--dry-run` previews.
- **Detection & synthesis in the wizard.** `bastion setup` now detects a co-resident self-managing
  firewall (libvirt/Docker/podman, by service or a co-resident nft table) and **proposes
  `cooperative`**, and synthesizes a starter `[zones]` policy from the box's existing intent — most
  usefully by parsing an existing (even *disabled*) `ufw` rule set. You confirm or decline; preview
  with `sudo bastion setup --dry-run`.

### Changed

- **`machine.conf` schema is now version 2.** `bastion migrate` carries an older config forward,
  adding `firewall_scope = exclusive` (the historical behavior) so existing installs are unaffected.
- **The firewall-conflict guard understands cooperative scope.** In `cooperative` mode an active
  `ufw`/`firewalld` is a warning (two input filters at one hook priority is ambiguous) rather than an
  abort — bastion no longer flushes their tables, so it can coexist.
- **`bastion confirm` also cancels a pending `switch` deadman** (in addition to disarming the
  watchdog), on a clean egress check.

### Safety

- **`exclusive` scope can no longer silently flush a co-resident manager's nftables tables.**
  `exclusive` begins with `flush ruleset`, which deletes every nft table on the box. Two guards now
  protect against wiping libvirt/Docker/Kubernetes-CNI/Tailscale/hand-written tables: (1) detection
  defaults to `cooperative` whenever **anything** else owns an nft table — the libvirt/Docker/podman
  services *plus a catch-all for any foreign table*; and (2) a **runtime hard-warning** fires before
  an `exclusive` `layer install l0` / `firewall reload` / `switch` that would flush a foreign table,
  naming the tables and how to switch to `cooperative`. Residual gap: a manager configured but with no
  table loaded at install time (and not libvirt/Docker/podman) — check `sudo nft list tables` first
  when unsure. See [docs/options/zones-and-ownership.md](docs/options/zones-and-ownership.md).

### Fixed

- **A loaded-but-disabled `ufw`/`firewalld` no longer falsely aborts an install.** The conflict guard
  treated a firewall whose systemd unit was merely *active* as enforcing — but `ufw`'s unit is a
  `RemainAfterExit` oneshot that stays active after `ufw disable`, owning no table. The guard now asks
  the tool itself (`ufw status` / `firewall-cmd --state`) and only blocks when it is genuinely
  enforcing (fail-soft: assume enforcing if the status can't be read). Surfaced dogfooding the
  cooperative install on a real libvirt host.

## [1.4.0] - 2026-06-17

A round of supply-chain and egress hardening, a managed control surface for the IP
threat feeds, and machine-readable output across the read commands — so automation
and a future GUI can consume the same world-state the CLI renders. Validated live on
the edge VM and the endpoint laptop.

### Added

- **`bastion feeds <list|add|remove>` — manage the IP-blocklist feeds.** The threat-feed
  URLs `edge-feed-fetch` pulls were hardcoded; they are now a managed `machine.conf`
  setting (`monitoring.feed_sources`) editable at runtime through the same validated,
  scoped-reload engine as the DNS blocklists, with the built-in defaults used when blank.
- **`--json` on `status`, `verify`, and `doctor`.** The read commands now emit the
  machine-readable projections a GUI or automation consumes — `status` renders from the
  canonical world-state document, `verify` emits the structured drift report, and
  `doctor` the structured triage report.

### Changed

- **One firewall verdict across every surface.** Whether the managed base table is loaded
  is now a single tri-state (loaded / not loaded / **unknown**), with *unknown* reported
  explicitly when a non-root probe can't tell an absent table from a permission-denied
  query. `state`, `status`, `doctor`, and the TUI all read this one verdict and render
  each layer from one shared world-state row, so no two surfaces can disagree.

### Security

- **The IP feeds can no longer lock the box out of its own management plane.** The
  reconciler folds the operator's trusted hosts, the VPN relay, and the gateway into the
  never-block allowlist, and `edge-feed-fetch` refuses a feed that suddenly collapses or
  implausibly explodes in size (supply-chain sanity caps) — so a poisoned or truncated
  feed cannot blocklist a critical host.
- **The sole nftables writer and the standing self-heal tool are systemd-confined.** The
  reconciler runs under strict filesystem/syscall/capability confinement (it is the only
  process that writes the firewall sets); the watchdog takes the capability and
  address-family ceiling appropriate to a tool that must still shell out to heal.
- **The AI signal collector is fail-closed against architecture leaks.** End-to-end
  scrubbing plus a serialized-output tripwire ensure only public source IPs and event
  counts ever reach the AI backend — never an internal address or hostname.

## [1.3.0] - 2026-06-16

A post-install configuration control surface — change settings from the CLI/TUI
instead of hand-editing config files and re-running the wizard — on top of a round
of safety hardening and a single canonical world-state document that the CLI, TUI,
and a future GUI all read from. Validated live on the edge VM and the endpoint laptop.

### Added

- **A post-install configuration control surface: `bastion config`.** Settings that
  previously could only be set by the install wizard (or by hand-editing
  `machine.conf`) are now changeable at runtime, with validation and the right —
  and only the right — service reload. `config list` / `get` / `set` / `describe`
  cover the full `machine.conf` surface, each setting classified **Everyday** or
  **Advanced**. Advanced changes (topology, interfaces, AI backend) are **gated**:
  the CLI requires `--advanced` and the TUI requires a typed confirmation, so an
  operator knows when they are entering dangerous waters. Every write is validated
  (field + whole-config) before it lands, staged atomically, and followed by a
  scoped reload — a DNS change never reloads the firewall.
- **Ergonomic verbs over the same engine.** `bastion allow`/`deny <ip|cidr>` (trusted
  management hosts), `bastion dns upstream`, `bastion dnsblock <list|add|remove>`,
  `bastion ai set-interval`/`set-depth`, and `bastion layer enable`/`disable` — all
  thin wrappers that inherit the same validation, gating, and scoped reload. A
  **Configure** group appears in the `bastion tui` command palette automatically.
- **`bastion state [--json]` — one canonical, versioned world-state document.** Layer
  health, nftables set counts, AI/recovery state and config drift now come from a
  single source the `status`/`doctor`/TUI surfaces (and a future GUI) all read from,
  so they can never disagree.
- **`bastion migrate` and a config schema version.** `machine.conf` now carries a
  schema version; `migrate [--check]` reports and applies forward migrations so an
  older config upgrades cleanly.
- **The DNS sinkhole accepts more list formats.** `edge-dnsblock-update` now reads
  plain-domain and adblock (`||domain^`) lists in addition to `0.0.0.0` hosts files,
  so most public blocklists (OISD, HaGeZi, AdGuard) drop in unchanged.
- **A never-sink allowlist for the DNS sinkhole.** A poisoned or over-aggressive
  blocklist can no longer NXDOMAIN the box's own update path, the AI API, distro
  mirrors, or operator-critical domains (allowlisted domains and their subdomains
  are never sinkholed), with supply-chain sanity caps that refuse a sudden collapse
  or implausible explosion in the domain count.

### Changed

- The TUI command surface now runs actions off the UI event loop so the dashboard
  stays responsive during a long-running operation, and the root-privilege check is
  unified across the CLI.

### Fixed

- **The firewall ruleset is now written atomically** (`/etc/nftables.conf` via a temp
  file + rename), so a crash mid-write can never leave a half-written ruleset.
- **The reconciler and `edge-ctl` now share a lock**, so a manual operation and the
  reconciler can no longer race on the nftables sets.
- **A watchdog light-heal preserves the recovery table** and kicks the reconciler,
  instead of briefly dropping the rescue path during a self-heal.
- **Orphaned recovery rescue users are reaped** (account expiry + a reaper unit), so
  a crashed recovery session cannot leave a lingering privileged account.
- **The hard-bootstrap recovery path is more robust:** it punches its accept rule into
  the live main table, guards against a double-start race, and never emits the OTP to
  the system journal (console only).
- Scoped, rate-limited ICMPv6 in the edge/endpoint rulesets (neighbor discovery and
  MLD from link-local only) instead of a blanket allow.
- AI analysis runs with a minimal environment and strips control characters from
  collected signals; the signals file is group-readable by the AI user only.
- `bastion generate` now validates the rendered ruleset (`nft -c`) before it can be
  loaded, and reports artifact drift (a generated file changed out from under the
  config).

## [1.2.0] - 2026-06-15

Multi-distro support: Fedora/RHEL (`dnf`) is now driven, and the Debian/Ubuntu
(`apt`) path is validated on real hardware alongside Arch. Two cross-distro
firewall/install defects found during live validation are fixed, plus operational
robustness in the shell scripts and the setup wizard. Validated live on Arch,
Debian 12, and Fedora 42.

### Added

- **Fedora/RHEL-family (`dnf`) is now a driven package manager**, joining `pacman`
  and `apt`. Package-name differences across distros are handled automatically
  (e.g. `python` → `python3`, `openssh` → `openssh-server`, and on Debian
  `conntrack-tools` → `conntrack`) via a per-manager translation map. A package
  that lives only in a third-party repository (CrowdSec on Debian/Fedora, AUR on
  Arch) is reported with an install hint instead of being installed for you.
- **Up-front missing-dependency preflight in the operational scripts.** The
  `edge-*`/`net-*`/`flowcheck`/`bastion-recovery` scripts now name any required
  command that is missing and exit cleanly, instead of failing obscurely partway
  through.
- **Earlier CrowdSec prerequisite notice.** When a profile includes the CrowdSec
  layer on a distro where it is not in the standard repositories, setup says so at
  profile selection rather than at install time.

### Fixed

- **The firewall ruleset now loads on Fedora/RHEL.** Their `nftables.service`
  loads `/etc/sysconfig/nftables.conf`, not `/etc/nftables.conf`, so enabling the
  stock service silently failed to load bastion's ruleset. A systemd drop-in now
  pins the loader to the file bastion writes, on every distro and across reboots.
- **Package installation no longer fails on Debian/Ubuntu.** Because bastion writes
  `/etc/nftables.conf` before the `nftables` package installs, the package's
  post-install step raised a configuration-file prompt that an unattended `apt`
  run could not answer, aborting the install. The install now runs non-interactively
  and keeps bastion's configuration file.

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
