# Architecture

How bastion is built, so you can reason about what it will and won't do to your box.
This is the mental model behind the [command reference](commands.md) and the
[layers reference](layers.md).

Bastion is a **detect → synthesize → apply engine**, not a firewall of its own. It
orchestrates standard tools — nftables, systemd, dnsmasq/unbound, WireGuard/ZeroTier,
CrowdSec — from a single per-machine description. A specific host (an edge router, a
laptop, a libvirt server) is just a set of values in `machine.conf`; no host is hardcoded
into the tool.

---

## The render spine

Everything bastion writes flows through one pipeline:

```
machine.conf   →   bastion generate   →   /etc/bastion/machine.env   +   rendered configs
   (INI)                                   (flat shell vars)              (/etc/nftables.conf, …)
```

- **`machine.conf`** (INI, at `/etc/bastion/machine.conf`) is your real topology —
  interfaces, subnets, ports, zones, backend choice. It is created by the wizard and
  never committed anywhere; an annotated template ships at `bastion/machine.conf.example`.
- **`bastion generate`** renders every *active* layer's templates. Templates use pure
  `{{ section.key }}` substitution (no logic in the template) — a small set of *derived*
  strings is computed in Python first (e.g. the zones accept-block, the firewall preamble,
  per-family set elements) and substituted like any other placeholder. `generate --check`
  proves every placeholder resolves without writing anything.
- **`/etc/bastion/machine.env`** is a flat `KEY=value` projection of the same config that
  the operational shell scripts source at runtime. So the Python layer and the shell scripts
  share one source of truth; the scripts carry only generic fallbacks, never real topology.

`nft -c` (a syntax check) gates the rendered ruleset before `nft -f` loads it. Every code
path that (re)loads the firewall — L0 install, `bastion firewall reload`, `net-rollback`,
the watchdog's heal — replays the same rendered `/etc/nftables.conf`, so a decision baked
into the rendered file is inherited everywhere for free.

## Layers

Capabilities are seven independent layers, L0–L6. You install only the ones your profile
selects, and one layer degrading never takes the others down. See **[layers.md](layers.md)**
for each layer's packages, units, scripts, and dependencies.

| Layer | Name | Role |
|---|---|---|
| L0 | core | nftables base ruleset + allowlist + CLI + kill switch + always-installed recovery |
| L1 | feeds | IP blocklist feeds + the reconciler (the sole nft-set writer) |
| L2 | crowdsec | CrowdSec agent → decisions ingested into the block set via L1 |
| L3 | ai-analysis | sanitized collect → analyze → intents, provider-agnostic backend (opt-in) |
| L4 | dns-dhcp | dnsmasq + unbound + LAN DNS/DHCP + DNS sinkhole (edge only) |
| L5 | vpn | WireGuard / ZeroTier interface lifecycle |
| L6 | monitoring | watchdog + snapshot/rollback + flow/LAN checks + canary confirm + alerting |

The dependency graph is shallow: everything requires **L0**; L2 and L3 additionally require
**L1** (they feed its reconciler). `bastion layer uninstall` refuses to remove a layer that
a still-installed layer depends on — so you can never orphan the kill switch.

**Profiles** are just named layer sets:

| Profile | Layers | For |
|---|---|---|
| `full-edge` | L0–L6 | a full router/firewall box |
| `basic-edge` | L0, L1, L2, L4, L6 | an edge box without the AI or VPN layers |
| `full-endpoint` | L0, L1, L2, L3, L6 | a hardened workstation/server |
| `minimal-endpoint` | L0, L1, L6 | a lean endpoint: firewall + feeds + watchdog |
| `custom` | you pick | anything |

## The one nft writer

Exactly one process mutates the managed nftables *sets* (the block / rate-limit / tarpit
sets): the **reconciler** (`edge-reconciler`, installed by L1). Feeds (L1), CrowdSec (L2),
and the AI layer (L3) all produce *desired* elements; the reconciler validates them against
a never-block allowlist and per-source CIDR-width floors, then reconciles the live sets to
match. Nothing else adds set elements.

This is why bastion is safe to layer intelligence onto: a bad feed URL, a noisy CrowdSec
scenario, or an AI intent can only ever *propose* — the reconciler is the choke point that
re-validates every element and can be emptied instantly (`bastion ai panic` flushes the
`ai_*` sets; the reconciler refills only what still validates).

The base ruleset itself (chains, policies, the WAN drop, forwarding) is rendered from
templates and loaded by L0 — the reconciler only owns the dynamic set *contents*.

## Dual-stack

Every managed set has an IPv4 and an IPv6 sibling (`blk_feed`/`blk_feed6`,
`cs_block`/`cs_block6`, `ai_block`/`ai_block6`, and the rate-limit/tarpit pairs). The
reconciler routes each blocked source to the family-matched set, so a host attacking over
IPv6 is filtered exactly as over IPv4. `trusted_hosts` and zones accept IPv6 sources too.
On a v4-only edge you can set `[network] ipv6_forward = no`; the v6 rules stay loaded but
inert.

## Ownership modes — coexist, don't conquer

`[machine] firewall_scope` decides how much of the kernel ruleset bastion claims:

- **`exclusive`** (default) — bastion owns the whole ruleset; the rendered file begins with
  `flush ruleset`. Correct for a dedicated firewall box.
- **`cooperative`** — bastion resets only its own table (an idempotent
  add-then-delete-then-redefine in one atomic `nft -f`), leaving co-resident tables
  (libvirt, Docker, a CNI) intact. Correct for a server that also runs a hypervisor or
  containers.

`bastion setup` proposes `cooperative` automatically when it detects a self-managing
firewall (libvirt/Docker/podman/Kubernetes/Tailscale, or *any* foreign nft table), and a
runtime hard-warning fires before an `exclusive` apply would flush a foreign table. Full
detail in **[options/zones-and-ownership.md](options/zones-and-ownership.md)**.

## The safety-net triad

Three independent mechanisms make bastion safe to apply on a box you can't easily walk over
to (all in L6, plus the always-present L0 recovery service):

1. **Snapshot / rollback** (`net-snapshot` / `net-rollback`). A known-good capture of the
   lifeline state — LAN address, firewall, upstream relay, default route, DNS. `net-rollback`
   is a gentle, idempotent restore that's safe to run when state already matches. Named
   snapshots layer over the auto slot. A snapshot records a completion marker as its final
   act; a rollback from a torn/partial capture restores best-effort but reports failure
   rather than a false "restore complete".
2. **The watchdog** (`edge-watchdog`). A standing service that heals *egress* failures
   evidence-based, with a cooldown so it never thrashes — and deliberately does **not** try
   to "fix" an upstream/ISP outage a local heal can't repair.
3. **`bastion switch`** — the deadman cutover. Because the watchdog only heals egress, a
   change that keeps the box online but locks *you* out would never trigger it. `switch`
   snapshots, applies, and arms an auto-revert timer that runs `net-rollback` unless
   `bastion confirm` cancels it within the window.

On top of these, **`bastion-recovery`** (installed by L0, disabled by default) is the hard
lifeline: started from a local console, it stands up an ephemeral rescue sshd on a free port
with a one-time password and self-destructs after its window. A human kill switch and the
recovery service are non-negotiable — they are always installed.

## Privacy & security model

- **No topology in the repo or on the wire.** No real IPs, MACs, hostnames, or keys live in
  the project; templates use `{{ }}` placeholders and the scripts read real values at runtime
  from `machine.env`. External alerts are deliberately generic (full detail goes only to the
  local journal), so the network is never described to a third party.
- **The AI layer only ever sees sanitized signals** — interface *types*, which services were
  detected, your wizard answers — never your addresses, MACs, or credentials. It is entirely
  optional; bastion is fully usable with rule-based detection and no API key.
- **Nothing the AI proposes for base/access config auto-applies.** A change like an SSH port
  goes to a human-review queue (`bastion ai proposals` / `accept` / `reject`); only the
  dynamic block sets are ever applied automatically, and only through the re-validating
  reconciler.
- **Secrets never enter `machine.conf`.** API keys live in a locked-down `EnvironmentFile`
  (chmod 600); alert-sink config is separate; a ZeroTier network ID is joined directly and
  never stored.

## Idempotent by construction

Every installer action is safe to re-run; `setup` and `generate` apply only the difference
between current and desired state. Your whole firewall is reproducible from one `machine.conf`
— which is what makes rebuilding a machine, or previewing a change with
`bastion setup --dry-run`, low-risk.
