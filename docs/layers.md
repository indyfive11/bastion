# Layers reference

Bastion's capabilities are seven independent layers. A **profile** is just a named set of
them (see the table at the bottom), and `bastion layer <install|uninstall|status> <id>`
manages one at a time. Everything requires **L0**; **L2** and **L3** additionally require
**L1** (they feed its reconciler). `bastion layer uninstall` refuses to remove a layer that
a still-installed layer depends on.

Each layer installs its own packages (resolvable ones only — a package that lives in a
third-party repo, e.g. CrowdSec on Arch/Debian, is *named with a hint* rather than
installed), renders its templates, drops its operational scripts into
`/usr/local/sbin/`, and installs its systemd units. `bastion status --health` reports each
layer's checks.

See **[architecture.md](architecture.md)** for how the pieces fit; **[commands.md](commands.md)**
for the CLI.

---

## L0 — `core`

**nftables base ruleset + never-block allowlist + the `bastion` CLI + the kill switch +
the always-installed recovery service.** The foundation every other layer builds on.

- **Packages:** `nftables`, `openssh`
- **Scripts:** `bastion-recovery`
- **Units:** `bastion-recovery.service`, `bastion-recovery-reap.service` (both installed
  **disabled** — recovery is a console-started lifeline, not a running daemon)
- **Requires:** nothing
- **Modes:** both (renders the mode-appropriate base ruleset — `inet edge` on an edge box,
  `inet bastion` on an endpoint)

L0 renders and loads `/etc/nftables.conf`, enables `nftables.service` for reboot
persistence (with a drop-in that pins the loader to bastion's file and makes a loaded
oneshot report `active (exited)`), applies the never-block allowlist, and installs
`bastion-recovery` — your out-of-band lifeline if you lock yourself out. The recovery
service and a human kill switch are non-negotiable; L0 is the layer that guarantees them.

## L1 — `feeds`

**Public IP blocklist feeds + the reconciler — the single writer of every managed nft set.**

- **Packages:** `nftables`, `curl`
- **Scripts:** `edge-reconciler`, `edge-feed-fetch`
- **Units:** `edge-reconciler.service` + `edge-reconciler.timer`, `edge-feed.service` +
  `edge-feed.timer`
- **Requires:** L0

`edge-feed-fetch` pulls the configured blocklist URLs (`bastion feeds …` manages them;
blank = built-in defaults) and the reconciler validates every candidate against the
never-block allowlist and per-source CIDR-width floors, then reconciles the live
`blk_feed`/`blk_feed6` sets. Because the reconciler is the **only** process that mutates the
managed sets, L2 and L3 don't touch nftables at all — they hand desired elements to L1. See
**[options/blocklist-options.md](options/blocklist-options.md)** for choosing feeds.

## L2 — `crowdsec`

**The CrowdSec detection agent, feeding the `cs_block` set through the L1 reconciler.**

- **Packages:** `crowdsec` (the daemon + `cscli`; **not** installed for you on Arch — it's
  AUR-only there — nor on Debian/Fedora, where it ships from CrowdSec's own repo)
- **Scripts:** none — the L1 reconciler *is* the bouncer
- **Units:** none bastion-owned (`crowdsec.service` is package-provided)
- **Requires:** L0, L1

CrowdSec does log-based behavioural detection (not inline DPI, so it's light on CPU/RAM).
Its decisions are ingested into `cs_block`/`cs_block6` by the reconciler. If the `crowdsec`
package isn't present, L2 reports `installed: no` and the reconciler simply has no CrowdSec
decisions to ingest — every other layer is unaffected. Install crowdsec out of band, then
`bastion layer install l2`.

## L3 — `ai-analysis`

**A sanitized collect → analyze → intents pipeline with a provider-agnostic backend, plus
the `edge-ctl` kill switch. Opt-in.**

- **Packages:** `python`, `curl` (the analyzer is stdlib-only; curl is for the Claude backend)
- **Scripts:** `edge-ai-collect`, `edge-ai-analyze`, `edge-ai-backend-claude`,
  `edge-ai-backend-mock`, `edge-ctl`
- **Units:** `edge-ai-collect.service`, `edge-ai.service`, `edge-ai.timer`
- **Requires:** L0, L1

**The timer installs DISABLED** and is armed only with `bastion ai enable` — reinstalling L3
disables it again. `edge-ai-collect` gathers *sanitized* signals (interface types, detected
services, sshd auth failures — never your IPs/MACs/keys), `edge-ai-analyze` runs them
through the configured backend into firewall *intents*, and the L1 reconciler applies the
block intents to `ai_block`/`ai_ratelimit`/`ai_tarpit`. Anything touching base/access config
(e.g. an SSH port) goes to a **human-review queue** instead (`bastion ai proposals`) and
never auto-applies. `bastion ai panic` flushes the `ai_*` sets instantly. Cadence and depth
are tuned via `[ai] timer_interval` / `depth` — see the README "Tuning the AI layer" section.

## L4 — `dns-dhcp` (edge mode only)

**dnsmasq DHCP/DNS + an unbound validating resolver + a DNS sinkhole (ad/tracker/malware
domain blocking).**

- **Packages:** `dnsmasq`, `unbound`
- **Scripts:** `edge-dnsblock-update`
- **Units:** `edge-dnsblock.service` + `edge-dnsblock.timer`
- **Requires:** L0
- **Modes:** **edge only** — an endpoint relies on the upstream router for DHCP/DNS, so L4 is
  skipped in endpoint mode

dnsmasq serves LAN DHCP + DNS and forwards to a local unbound doing recursive,
DNSSEC-validating resolution; `edge-dnsblock-update` renders a sinkhole zone from the
configured domain blocklists (with a never-sink allowlist). **The LAN interface must already
have its IP before you install L4** or dnsmasq/unbound won't bind — see the README pain
points. Resolver choices are catalogued in
**[options/dns-options.md](options/dns-options.md)**; DHCP reservations go in a local
`/etc/dnsmasq.d/*.conf` drop-in.

## L5 — `vpn`

**WireGuard + ZeroTier interface lifecycle.**

- **Packages:** `wireguard-tools`, `zerotier-one`
- **Scripts:** none — `wg-quick@<iface>` and `zerotier-one` are package-provided
- **Units:** none bastion-owned (`wg-quick@<iface>.service` is a packaged template unit)
- **Requires:** L0

L5 installs the tooling and brings up ZeroTier, but **skips any WireGuard interface that has
no config** — it never invents a key. `bastion setup` generates the keypair and writes
`/etc/wireguard/<iface>.conf` (chmod 600); existing confs are never overwritten. Drop in your
own conf, or run the wizard, before expecting `wg` interfaces to come up.

## L6 — `monitoring`

**The watchdog + snapshot/rollback + flow & LAN-client checks + the canary confirm + the
no-arch-leak alerter.** The resilience layer.

- **Packages:** `curl`, `conntrack-tools`
- **Scripts:** `edge-watchdog`, `net-snapshot`, `net-rollback`, `flowcheck`, `lan-verify`,
  `net-confirm`, `notify-alert`, `notify-failure`
- **Units:** `edge-watchdog.service`, `notify-failure@.service`
- **Requires:** L0

`edge-watchdog` heals *egress* failures evidence-based, with a cooldown so it never thrashes,
and deliberately won't fight an upstream outage a local heal can't fix. `net-snapshot` /
`net-rollback` are the known-good safety net (`bastion snapshot` / `rollback` / `snapshots`).
`net-confirm` (`bastion confirm`) verifies stable egress then disarms the watchdog (and any
`bastion switch` deadman). `flowcheck` / `lan-verify` back `bastion check`. Alerts go to the
local journal in full; anything leaving the host is sanitized of topology.

---

## Profiles

| Profile | Layers | For |
|---|---|---|
| `full-edge` | L0 L1 L2 L3 L4 L5 L6 | a full router/firewall box |
| `basic-edge` | L0 L1 L2 L4 L6 | an edge box without the AI or VPN layers |
| `full-endpoint` | L0 L1 L2 L3 L6 | a hardened workstation/server |
| `minimal-endpoint` | L0 L1 L6 | a lean endpoint: firewall + feeds + watchdog |
| `custom` | you choose | any combination |

Pick a profile with `bastion setup --profile <p>`, or set `[machine] layers` in
`machine.conf` directly. The wizard defaults to `full-edge` for a detected edge topology and
`full-endpoint` for an endpoint.
