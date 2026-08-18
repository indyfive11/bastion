# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

## [1.5.17] - 2026-08-17

Closes a false-green in `bastion doctor`: it (and `bastion verify`) compared the rendered config to
disk but never to the **loaded kernel ruleset**, so a `bastion generate` without a following `bastion
firewall reload` left the kernel behind while every health signal stayed green — a firewall that is
live but stale read as fully healthy. Found on a live endpoint where a WireGuard accept present in
`/etc/nftables.conf` was absent from the kernel and silently dropped the tunnel. Live-verified.

### Added

- **`doctor` "ruleset current" check.** `bastion doctor` now reports whether the live kernel ruleset
  matches `/etc/nftables.conf`, catching a `generate` that was never reloaded. It detects this by
  *differential canonicalization* — the on-disk file is loaded into a throwaway network namespace so
  the same `nft` binary canonicalizes it exactly as the real load did, then each managed table (the
  endpoint `inet bastion`, or the edge `inet edge` + `ip edge_nat`) is diffed against the live dump,
  after normalizing away the parts that legitimately differ on a synced box: reconciler-filled set
  elements, per-packet counters, and the transient `bastion-recovery` accept. It is a **WARN** (an
  operator can legitimately be mid-change) and is gated exactly like the base-table probe — it needs a
  live system, root, the base table loaded, and a working namespace; otherwise it reports "unknown",
  never a false "stale".

### Changed

- **`verify` no longer over-promises.** Its "no drift" success message now states it checks config
  *files*, not the loaded ruleset, and points at `bastion doctor` for the kernel-sync check.

## [1.5.16] - 2026-08-17

Adds first-class firewall support for hosting a WireGuard **server** on an endpoint (e.g. a VPS that
remote peers dial into). Previously the endpoint ruleset opened no inbound WireGuard port, so a WG
server configured on an endpoint had its listen port silently firewalled shut — peers could never
complete a handshake. Live-verified on a KVM VM.

### Added

- **Endpoint WireGuard-server listen-port accept.** When `interfaces.wg_server_iface` is set on an
  endpoint, the firewall now opens the WireGuard listen port with an any-source `udp dport <port>
  accept` (WireGuard's own cryptography drops every unauthenticated packet, so an open UDP port
  exposes no surface beyond the protocol). The port comes from a new `[network] wg_server_listen_port`
  (defaulting to WireGuard's `51820` when a server interface is set) — so a non-default `ListenPort`
  is honoured instead of being firewalled shut. The accept sits after the block-list drops (a
  blocklisted source is still dropped first) and renders nothing on a client endpoint (which stays
  fully locked down). The edge WireGuard-server accept is unchanged — it keeps its interface-scoped
  form. A reachability **caution** is emitted at validate time when a WG server is configured on an
  endpoint (keep an SSH path independent of the tunnel, or a lockout is console-only to recover), and
  the new port is range-validated.

### Tests

- 665 passing (+2: the endpoint WG-accept render / `nft -c` / false-green cases, and the validate
  caution + port range-check). Live-verified on the KVM VM — an arbitrary-source UDP datagram reaches
  the WireGuard listen port through the endpoint's `policy drop` input, and is dropped when the accept
  is removed (false-red guarded).

## [1.5.15] - 2026-08-15

A hardening + cross-distro-robustness release. Ten fixes across the edge data plane, the setup wizard,
the AI collector, and the L4 resolver, validated live on a full-edge install across Ubuntu, Debian, and
Rocky 9 (the last under SELinux **enforcing**) via a new isolated-LAN KVM harness that drives a real
install through the firewall. No config migration required; new behavior is opt-in or fail-safe by
default.

### Security

- **M2 — edge router source-address hardening.** Set the anti-spoof / anti-redirect sysctls on an edge
  box (`rp_filter`, `accept_source_route=0`, `accept_redirects=0`, `send_redirects=0`, `secure_redirects=0`)
  so a router-role host can't be steered by forged ICMP redirects or source-routed packets.

- **M3 — scope ZeroTier/WireGuard control-port accepts to non-WAN interfaces.** The `:9993` (ZT) and
  `:51820` (WG-server) input accepts are now positively bound to the box's own internal interfaces
  instead of relying on the `iifname wan drop` firing first. A mis-detected or renamed WAN can no longer
  leak these control ports to the internet. Each rule vanishes when its service interface is unconfigured.

- **M3b / M2b — edge anti-spoof teeth.** Input chain now fails **closed**: everything not arriving on one
  of the box's own internal interfaces is dropped (replacing a WAN-name-dependent drop), so a
  mis-detected WAN can't expose the any-source service accepts. Plus a new opt-in `[network] anti_spoof`
  knob (`off` default / `on` = BCP38 egress drop over the box's declared CIDRs / `strict` = + an IPv6
  reverse-path drop). Default `off` preserves existing forwarding for cascaded downstream subnets.

### Added

- **M12 — endpoint `prefer_ipv4`.** Optional endpoint knob to prefer IPv4 in `getaddrinfo` (gai.conf)
  with an optional `disable_ipv6`, for endpoints on broken/partial v6 networks.

- **M5b — skip wholly binary-less layers at setup.** The wizard now skips a layer only when **every**
  package it requires (config-aware) is missing after the install step, degrading cleanly instead of
  failing; L0 and L6 are never skipped. A partially-provisioned layer (e.g. L5 with WireGuard present but
  ZeroTier absent) still installs and self-degrades rather than being dropped wholesale.

### Fixed

- **M13 — blank-safe edge forward/NAT rules.** A WG/ZT-less edge previously rendered nftables that
  wouldn't load (empty interface expansions); the forward/NAT rules now render safely when those
  interfaces are unconfigured.

- **M5a — honest binary-less-layer reporting.** After the package-install step, the wizard reports which
  layers remain binary-less (config-aware `required_packages`), splitting genuinely-skipped from degraded.

- **M9 — audit-log robustness.** Serialize the audit-log append and tolerate a corrupt JSONL line rather
  than aborting the read.

- **M7 — bound the AI backend read.** Cap the analyzer's read of the AI backend's output so a runaway or
  misbehaving backend can't OOM the analyzer.

- **L4 / SELinux — unbound `:5335` bind under enforcing.** On RHEL/Rocky/Fedora with SELinux enforcing,
  unbound (`named_t`) was denied `name_bind` on `:5335` (labelled `howl_port_t`), leaving the resolver
  dead. L4 now relabels the port to `dns_port_t` (`semanage port -a`/`-m` for tcp+udp) before starting
  unbound — best-effort and idempotent, with a hint if `semanage` is absent.

## [1.5.14] - 2026-08-11

Two safety/hardening fixes on the AI and secret-writing paths. Normal-path runtime behavior is
unchanged on a healthy box; both close a fail-silent failure mode that only shows up under load or a
crash.

### Fixed

- **H5 — cap the AI collector's observation payload (cost/latency guard).** `edge-ai-collect` built an
  unbounded `observations` list (one row per distinct public attacker over a 24h window) and piped it
  verbatim to the paid AI backend every analyzer cycle — a heavily-scanned box burned cost and latency
  on a multi-hundred-KB payload in normal operation (the backend caps its *output* at 32 intents, but
  nothing bounded the *input*). Cap at the top `MAX_OBSERVATIONS=200`, applied after the no-arch-leak
  scrub and before the serialized-bytes tripwire (truncation is removal-only, so it can never introduce
  a leak). Rank by a composite key `(crowdsec-active-decision, total_events, ip)`, all descending, so
  the cap keeps confirmed-malicious IPs (which carry no in-window events and would otherwise sort to the
  bottom and be dropped first) and is deterministic run-to-run (a stable `ip` tiebreak, without which
  PYTHONHASHSEED-randomized set iteration would emit a different top-N each run). The cap is never
  silent: `observations_total` (the full pre-cap count) and `capped` are reported in the doc and the
  stdout summary, the ranking is explained in the doc `note`, and the fail-closed tripwire branch zeros
  both count fields.

- **M1 — atomic 0600 writes for the three secret files.** `write_env_file` (edge-ai API-key
  EnvironmentFile), `apply_alerts` (notify-alert.conf) and `write_wg_conf` (wireguard `<iface>.conf`)
  each did `os.open(final, O_TRUNC, 0o600)` straight to the destination, so a crash / EIO / ENOSPC
  mid-write left the final file truncated but present — the consumer then silently read a keyless or
  partial config (edge-ai starts with no API key, alert sinks disabled, VPN interface broken). The
  in-place idiom also had a real exposure window: `O_TRUNC` on a pre-existing 0644 file writes the
  secret into a still-0644 file and only chmods 600 a syscall later. New shared helper
  `state.atomic_write_private(out, text)` (0600-from-creation temp → fsync → `os.replace`) routes all
  three writers through an atomic swap: the destination is now either the old or the new complete
  contents, never truncated, and inherits the temp's fresh 0600 inode (the post-write chmod and its
  window are gone).

### Tests

- 615 passing (+16: 7 for the observation cap's ranking/determinism/honesty, 9 for the atomic
  secret-writer's crash-safety, perms, and per-site delegation).

## [1.5.13] - 2026-08-11

A cross-distro install-guidance fix: on Debian/Ubuntu and Fedora/RHEL, `full-edge` pulls packages that
live only in a vendor repository, and the installer now names them up front with the exact command to get
them instead of a generic "install manually." No change to the install's success path (unresolvable
packages were already split off so the batch never hard-failed) — this is about telling the operator how.

### Fixed

- **M4 — multi-distro package gaps: actionable vendor hints + up-front warning.** `full-edge` installs
  crowdsec (L2) and wireguard-tools + zerotier-one (L5). Only pacman declared which of these are outside
  its stock repos, so apt/dnf operators got no layer-selection warning and only a bare "install manually"
  hint at install time. Verified the real gaps (apt live on Ubuntu 24.04; dnf via official/vendor docs):
  `zerotier-one` is vendor-repo-only across apt/dnf; `crowdsec` is in Debian/Ubuntu stock (older) but
  vendor-only on Fedora/RHEL; `wireguard-tools` is in stock everywhere including Rocky AppStream (not EPEL).
  So `Apt` now flags `zerotier-one` and `Dnf` flags `crowdsec`+`zerotier-one`, each with a per-package
  vendor one-liner (ZeroTier install script, CrowdSec packagecloud) — bastion adds no vendor repo itself.
  No EPEL handling or per-distro branching is needed (Fedora and Rocky share the same gap set).

### Tests

- 599 passing (+1 for the per-manager repo_unavailable facts and the vendor-hint output).

## [1.5.12] - 2026-08-11

Three HIGH-priority safety fixes: the recovery net's honesty and completeness, plus an install-time
SSH-detection lockout guard. No change to normal-path runtime behavior on a correctly-detected box.

### Fixed

- **H1 — socket-activated SSH port detection (install-time lockout guard).** `bastion setup` derived the
  SSH port from `sshd -T`/`sshd_config` then defaulted to 22, with no cross-check against the live
  listener. On socket-activated sshd (Ubuntu/Debian `ssh.socket`, where the port lives in the socket
  unit's `ListenStream`, not `sshd_config`) that returns 22 while the box actually listens elsewhere, so
  the generated firewall opens the wrong port and drops real SSH — operator lockout, worst on the
  non-interactive path that ships the detected port with no human to catch it. Detection now reads the
  ssh socket unit authoritatively (`systemctl show <unit> -p Listen`, effective/merged; gated on the
  socket being ACTIVE so a stale socket can't override a real traditional sshd; tries both `ssh.socket`
  and `sshd.socket`), correcting `[ports] ssh` at the source so both edge and endpoint are covered. The
  `ss` listener set carries no process identity, so it is only a disagreement tripwire that WARNS — it
  never auto-selects a port. Falls back to the prior behavior on a normally configured box.

- **H2 — net-snapshot content-completeness gate.** The known-good snapshot is stamped only after the
  restore-relevant captures actually landed, so a disk-pressure/EIO failure that still lets the tiny
  `taken-at` witness write through can no longer swap in a content-incomplete slot that `net-rollback`
  would later restore. Each check skips cleanly when its source is legitimately absent (NM-less endpoint,
  no resolver) so a sparse host never false-fails and self-disables its own safety net.

- **H3 — recovery self-destruct arms honestly.** `bastion-recovery` no longer announces a false
  "auto-stop in Ns" when the self-destruct timer failed to arm. Preflight fails CLOSED (requires
  `systemctl`/`systemd-run` before building any recovery surface); at runtime an arm failure fails OPEN —
  the last-resort session stays up (the kill switch is always present) but announces "NOT ARMED — manual
  stop required". Both transient units are stopped + `reset-failed` before arming, so a stale failed unit
  can't strand every future session un-timed.

### Tests

- 598 passing (+6 for H1 socket-port detection: pure `parse_socket_listen_ports`/`reconcile_ssh_port`
  plus `detect()` integration; H2's completeness suite and H3's arm-rc suite added earlier in the cycle).

## [1.5.11] - 2026-08-10

Two scripts-layer robustness fixes. The edge watchdog's known-good snapshot auto-refresh — advertised
but never actually running — is activated and guarded so it can't capture a leaked DNS state; and the
default egress/liveness probe becomes a neutral, vendor-agnostic host. No change to normal-path runtime
behavior.

### Changed

- **N2 — the known-good snapshot auto-refresh now runs (edge-watchdog).** `maybe_refresh` invoked a
  `net-snapshot.service` unit that does not exist, so the "self-refreshing known-good snapshot" was a
  silent no-op — the watchdog's rollback target never refreshed. It now calls `net-snapshot` directly
  (the idiom every other caller uses). The refresh is held while a host-resolver DNS leak is detected
  (edge mode + a loopback stub chain), so a leaked `/etc/resolv.conf` can't be baked into the known-good
  slot and later restored by `net-rollback`; the hold notice latches once per episode.
- **N1 — neutral default egress probe.** The default egress/liveness probe changes from
  `https://api.anthropic.com` to `https://example.com` (IANA/RFC-2606 reserved) across `net-confirm`,
  `flowcheck`, the watchdog's `EXT_HTTPS` liveness list, `machine.conf.example`, and the DNS never-sink
  allowlist. example.com returns a clean HTTP 200 for flowcheck's `[200|404]` gate and has no datacenter
  bot-challenge, so it doesn't false-fail on VPS egress; flowcheck's independent cross-check stays a
  different host (cloudflare). A general firewall framework shouldn't hard-default its liveness canary to
  one SaaS API — an operator can still set `[monitoring] egress_probe` to any host.

### Tests

- `tests/test_edge_watchdog_refresh.py` (10) and `tests/test_egress_probe_defaults.py` (5); 577 total.

## [1.5.10] - 2026-08-10

A safety-and-robustness release for the recovery path. `bastion confirm` gains a present-operator
override so a confirmed change is never force-reverted when egress is down for a reason unrelated to
the change; `net-snapshot` now captures atomically, so a failed capture can no longer destroy the
known-good snapshot it was refreshing. Also ships B9 (combined interface + source-network zones). No
change to normal-path runtime behavior.

### Added

- **B9 — a zone can pin an interface AND a source network (`iface:NAME+<CIDR>`).** The combined zone
  source renders `iifname "NAME" ip[6] saddr <CIDR>`, restricting a zone-opened port to a given source
  network arriving on one interface (anti-spoof for that port). An `iface:` source now always emits
  its `iifname` clause, so a malformed source fails **closed** (`iifname ""`, which nft rejects)
  instead of a bare accept-all. Detection preserves the pairing when synthesising a zone from a `ufw`
  `in on IFACE … from CIDR` rule. The guarantee is narrow and documented: it narrows an accept, it is
  not a standalone anti-spoof drop, and zones render last so it cannot retro-harden an already-open port.
- **`bastion confirm --force` — present-operator override.** The default `confirm` gates the deadman
  disarm on a stable-egress probe (`net-confirm`) — the safe default, since a cutover that broke egress
  *should* revert. But a present operator whose egress is down for an **unrelated** reason (a fresh
  install before egress is up, an ISP/probe-host outage) would otherwise be forced into an auto-revert
  of a config they want. `--force` disarms the deadman on the operator's explicit assertion **without**
  running the 45 s probe (so the deadman cannot fire mid-probe), and verifies the timer is actually
  stopped before reporting success. Egress is not verified under `--force` — the command says so and
  journals the override. When a default `confirm` fails because egress is down, it now prints how to
  override.

### Changed

- **`net-snapshot` captures atomically (temp-dir swap).** Each capture is built in a hidden sibling
  temp dir and swapped into the live slot only once its `taken-at` completion witness is written. A
  failed or truncated capture (e.g. a full disk) now leaves the **prior** known-good slot untouched —
  a complete-but-stale snapshot beats a torn-fresh one — and a reader (`net-rollback`, the watchdog)
  never observes a half-written slot. The swap uses `mv -T` so a rare concurrent capture cannot
  nest-corrupt the slot, and moves the prior slot aside so a crash mid-swap is recoverable:
  `net-snapshot` and `net-rollback` both promote the aside copy if the slot is found missing. The
  captured slot is now mode `0700` (it holds NetworkManager secrets); `bastion snapshots` skips the
  swap temps. Builds on C7 (which made a torn capture *detectable*); this makes a failed refresh
  *non-destructive*.

### Tests

- 562 passing. New `bastion confirm --force` cases (disarm-without-probe, verified-stop, root gate,
  egress-down hint), `net-snapshot` swap / keep-prior / reconcile cases, and a `snapshots`-lister
  filter case. Both features were live-validated on the edge KVM VM (swap slot mode `0700`, no temp
  leftovers, `.prev` reconcile; `--force` disarm; egress-down hint).

## [1.5.9] - 2026-07-06

A robustness-and-docs release. Two operational scripts stop *misreporting* when a conditional
tool is missing or a snapshot is partial, and the `docs/` tree is built out to the reference set
the project promised — an architecture overview, a per-layer reference, end-to-end use-case
recipes, and an FAQ. No change to normal-path runtime behavior.

### Fixed

- **B4 — name missing conditional tools instead of misreporting.** On a `ufw`-governed box that
  lacks `iptables`, `edge-watchdog`'s `config_ok` masq check could not be verified and was read as
  "config broken" → heal/rollback churn and false manual-intervention alerts. It now warns **once**
  (via a `$RUN/iptables-missing-warned` sentinel, the same persistent-daemon idiom as `conntrack`),
  skips the unverifiable check, and does **not** flag the config broken — forward health is still
  judged evidence-based. `flowcheck` likewise now emits `SKIP … <bin> not installed` (counting
  neither pass nor fail) for its `wg`/`ss` checks when those tools are absent, instead of a
  misleading `FAIL`. The pre-existing hard `need <bin>` preflight in the other scripts is unchanged.
- **C7 — flag a partial network snapshot instead of restoring it as known-good.** An empty or
  interrupted capture was indistinguishable from a good one, so `net-rollback` would no-op and log
  "restore complete" — a false success. `net-snapshot` now clears its `taken-at` completion marker
  at the start of a capture and rewrites it as its final act (after every restore-relevant file), so
  a torn or in-flight capture is detectable; `net-rollback` treats a slot with no `taken-at` as
  incomplete — it still restores best-effort but **exits 1** and logs the restore as unverified,
  never a clean rollback. A firewall-less box (which legitimately writes no firewall marker) is not
  affected; the gate keys only on `taken-at`.

### Documentation

- **C4 — `docs/` buildout.** New `docs/architecture.md` (the render spine, the sole-writer
  reconciler, the safety-net triad, ownership modes, and the privacy/security model),
  `docs/layers.md` (per-layer packages/units/scripts/dependencies/health + the profile map),
  `docs/use-cases.md` (ten end-to-end recipes — edge router, endpoint, LAN-only zones, libvirt
  coexistence, safe cutover, lockout recovery, feeds, AI, preview, teardown), `docs/faq.md`, and a
  `docs/README.md` index. The command reference gains the `bastion config list/get/describe/set`
  verbs, and the README + command reference cross-link the new pages.

### Tests

- 549 passing. B4 adds a `config_ok` case in `test_edge_watchdog_failover.py` (hermetic
  missing-binary fake via a `command` builtin override) and a new `test_flowcheck_optional_tools.py`;
  C7 adds `test_net_rollback_completeness.py` (five cases, including a mid-script probe stub proving
  `taken-at` is cleared first and rewritten last). Both were live-validated on the edge KVM VM.

## [1.5.8] - 2026-07-05

A testability release for `edge-watchdog`, closing a live-coverage gap found during VPS
validation: the documented `edge-watchdog once` testing entrypoint short-circuits on the
egress-OK green path on a healthy host, so it never exercised the self-heal branch — the exact
code path a failover test needs to walk. There is no change to the daemon's runtime behavior; this
adds a self-contained way to drive the heal path deterministically, plus first-class help.

### Added

- **`SIMULATE=<scenario>` seam on `edge-watchdog`.** Seeds the matching `$RUN/simulate-<scenario>`
  test hook for a single invocation and auto-clears it on exit (`trap … EXIT`), so
  `SIMULATE=egress-dead MODE=edge EGRESS_FAIL_TRIPS=1 edge-watchdog once` walks the heal branch
  end-to-end with no manual touch/rm of magic files and no risk of a stray seam outliving the run.
  Valid scenarios: `egress-dead isp-down config-broken lan-broken wan-carrier-down`; an unknown name
  fails fast (exit 2) rather than silently creating a no-op file.
- **`edge-watchdog -h|--help` usage.** Dispatched right after `set -u`, ahead of the dependency and
  root preflight, so it prints and exits 0 on any box. Documents the run modes, env knobs, the
  `SIMULATE` seam, and the pause files.

### Tests

- Three unit tests (`test_edge_watchdog_failover.py`) cover the seam walking the edge heal branch and
  self-cleaning, the fail-fast reject on an unknown scenario, and the dependency-free help dispatch.
- The VM integration harness (`vm_edge_integration.sh`) now walks the edge HEAL branch via
  `SIMULATE=egress-dead` under `DRYRUN`, asserting the seam auto-clears and the nft table survives.

## [1.5.7] - 2026-06-21

A one-finding follow-up to the 1.5.6 watchdog hardening, surfaced while validating those changes
live on an endpoint box: a deliberate operator or test-harness environment override of a
`machine.env`-backed variable (`MODE`, `RELAY_IF`, …) was silently lost, because `edge-watchdog`
sourced `/etc/bastion/machine.env` *after* applying its `${VAR:-default}` fallbacks — so the source
overwrote the incoming env. This made `edge-watchdog`'s documented edge-path test seams inert on an
endpoint host (`MODE` was always forced back to `endpoint`) and would have quietly dropped any
intentional operator override. No topology values are hardcoded; the fix is generic.

### Fixed

- **Operator/test env overrides now win over `machine.env` in `edge-watchdog`.** Each
  `machine.env`-backed variable is cached *before* the source and preferred *after*
  (`VAR=${_OV_VAR:-${VAR:-default}}`), so an explicit `MODE=edge RELAY_IF=… edge-watchdog` override
  takes effect while an un-overridden variable still takes its `machine.env` value. Variables that
  `machine.env` never sets (`DRYRUN`, `EGRESS_FAIL_TRIPS`, …) were already safe. Scope is limited to
  `edge-watchdog`, the only script with an operator-override contract.

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
