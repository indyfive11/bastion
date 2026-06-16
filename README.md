# Bastion (`bastionfw`)

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

A modular, layered Linux firewall framework with an operator CLI, an optional AI-driven
analysis layer, and an intelligent setup wizard. Use it to turn a spare mini-PC or SBC into a
defense-in-depth **router/firewall box** (a scriptable alternative to consumer-router firmware),
or to harden a single **endpoint** workstation or server. It installs from scratch on a fresh
system.

> **What it is NOT:** a general-purpose firewall GUI, a replacement for nftables, a cloud
> service, or a configuration-management system. It is a focused defense-in-depth tool built
> on nftables.

## Highlights

- **Seven composable layers** (L0–L6) — install only what you need.
- **Two modes** — `edge` (routing firewall / gateway) and `endpoint` (defense-in-depth on a workstation or server).
- **Guided setup** — `bastion setup` detects your topology, recommends a profile, renders configs, installs packages, and verifies the result.
- **A single nft writer** — the reconciler is the only process that mutates managed nftables sets; everything else feeds it.
- **Optional AI analysis** — a provider-agnostic backend turns sanitized signals into firewall intents; **only sanitized topology ever leaves the host**.
- **Resilience built in** — a standing watchdog with snapshot/rollback, an always-present recovery service, and a human kill switch.

## Layers

| Layer | Name | What it does |
|---|---|---|
| L0 | `core` | nftables base ruleset + allowlist + `bastion` CLI + kill-switch + always-installed recovery service |
| L1 | `feeds` | IP blocklist management + reconciler + feed fetcher |
| L2 | `crowdsec` | CrowdSec agent + block-set integration |
| L3 | `ai-analysis` | Sanitized collect → analyze → reconciler intents, with a provider-agnostic backend |
| L4 | `dns-dhcp` | dnsmasq + unbound + LAN DNS/DHCP + DNS sinkhole (ad/tracker/malware blocking) (edge mode only) |
| L5 | `vpn` | WireGuard / ZeroTier interfaces + policy routing |
| L6 | `monitoring` | watchdog + snapshot/rollback + flow & LAN-client checks + canary confirm + no-arch-leak alerting |

## Profiles

`full-edge` · `basic-edge` · `full-endpoint` · `minimal-endpoint` · `custom`

## Modes

- **edge** — the machine routes/firewalls a LAN behind it (a gateway/router). Uses L4 DNS/DHCP and,
  optionally, L5 VPN routing. **You must give the LAN interface an IP yourself** (see pain points).
- **endpoint** — defense-in-depth on a single host (workstation/server). No LAN routing, no DHCP;
  L4 is skipped.

## Use case: a dedicated router / firewall box

In **edge** mode, bastion turns a small spare machine into a router/firewall appliance. It sits
between your modem/ISP uplink (WAN) and your LAN and provides stateful firewalling, threat-feed +
CrowdSec blocking, LAN DNS/DHCP with an ad/tracker/malware sinkhole, and optional WireGuard /
ZeroTier remote access — a scriptable, defense-in-depth alternative to a consumer router's
firmware, built on plain nftables.

Use the **`full-edge`** profile (or **`basic-edge`** to skip DNS/DHCP and the AI layer). Edge mode
requires **at least two network interfaces** — one WAN, one LAN (or a single NIC split into VLANs
on a managed switch).

The threat-intel sets are **dual-stack**: every managed set (threat-feed, CrowdSec, and AI block /
rate-limit / tarpit) has an IPv4 and an IPv6 variant, and the reconciler routes each blocked
source to the family-matched set — so a host attacking over IPv6 is filtered the same as over IPv4.
`trusted_hosts` may likewise contain IPv6 addresses.

### Suggested hardware

bastion's data path is plain in-kernel nftables, and its threat-intel layer (CrowdSec) is
**log-based, not inline deep-packet inspection** — so it needs noticeably less CPU and RAM than a
firewall running an inline IDS like Suricata. The figures below track the published OPNsense
baselines, adjusted down for that lighter footprint.

| | Minimum (~1 Gbps line) | Recommended (1–2.5 Gbps, VPN, headroom) |
|---|---|---|
| **CPU** | dual-core x86-64 ≥ 1.5 GHz, or ARM64 (AES-NI **not** required) | quad-core x86-64 ~3 GHz (e.g. Intel N100 / N150) |
| **RAM** | 2 GB | 4 GB (8 GB with a large DNS sinkhole, heavy VPN, or many CrowdSec collections) |
| **NICs** | 2× 1GbE, Intel chipset preferred | 2–4× Intel 2.5GbE (e.g. i226-V) |
| **Storage** | 8 GB | 32 GB+ SSD (CrowdSec DB + journald + feed lists) |
| **Uplink** | 1 GbE | 2.5GbE+ if your WAN exceeds 1 Gbps |

Notes:

- **Routing is cheap; the userspace services set the floor.** NATed forwarding at 1 Gbps uses well
  under 10% of one modern core, so an N100-class quad-core sits near line rate even at 2.5 Gbps with
  filtering. RAM is driven by CrowdSec (~100–300 MB), unbound's cache, and the DNS sinkhole list —
  not by the firewall itself. The reference build is validated on a 2-core / 2 GB VM.
- **WireGuard does not need AES-NI.** It uses ChaCha20-Poly1305, which is fast on any CPU (vector
  instructions match or beat AES-NI); ~1 Gbps of tunnel traffic uses 1–2 cores. AES-NI still helps
  ZeroTier (AES) and TLS, so it's nice to have, not a requirement.
- **Two NICs is the hard requirement** for edge mode — one WAN, one LAN (or a single NIC split into
  VLANs on a managed switch). A single-NIC box can still run **endpoint** mode but cannot route a LAN.
- **ARM64 works** (an SBC with two NICs, or one NIC + a USB-3 gigabit adapter) — bastion is portable
  Python + nftables — but on Arch ARM you build CrowdSec from the AUR yourself (as on any Arch
  system; see the pain points).
- **Keep an out-of-band console** (serial / IPMI / a keyboard + monitor) for first setup and for the
  `bastion-recovery` lifeline. A misconfigured firewall on a headless router is otherwise hard to
  recover.

## Requirements

- Linux with **nftables**
- **Python ≥ 3.11**
- **`pacman`, `apt`, or `dnf`** (used to install layer packages during setup)
- **root** for any live install (loading nft rules, installing systemd units, installing packages)

> **Distro support.** Arch (and Arch-based) is the **primary, regularly-tested** target.
> **Debian/Ubuntu (`apt`) and Fedora/RHEL-family (`dnf`) are supported and have been
> install-validated live** (Debian 12, Fedora 42) — Arch still sees the most use, so report any
> rough edges. Package-name differences across distros are handled automatically (e.g. `python` →
> `python3`, `openssh` → `openssh-server`, and on Debian `conntrack-tools` → `conntrack`). A package
> only in a third-party repo (e.g. CrowdSec on Debian/Fedora, or AUR on Arch) is reported with an
> install hint rather than installed for you. Another manager (e.g. openSUSE's `zypper`) is detected
> and named, but setup will list its packages to install by hand. systemd is assumed throughout.

## Install

**Arch (AUR):**

```sh
paru -S bastionfw      # or: yay -S bastionfw
```

**From source** (the path on Debian/Ubuntu and Fedora/RHEL — there is no native package there yet):

```sh
git clone https://github.com/indyfive11/bastion
cd bastion
pipx install .         # provides the `bastion` CLI
```

## First-time setup (recommended path)

Run the guided wizard as root. It is the intended way to install — it detects your topology,
writes `/etc/bastion/machine.conf`, generates all configs, installs packages, brings the layers
up, and verifies the result:

```sh
sudo bastion setup                 # interactive: detect → profile → configure → install → verify
sudo bastion setup --dry-run       # offline preview; writes nothing, makes no network calls
sudo bastion setup --profile full-edge   # seed a profile up front
```

The wizard asks for the values it can't reliably detect (interfaces, LAN subnet, gateway, SSH
port, trusted management hosts), and — for profiles that include L3/L6 — the AI backend choice
and alert sinks. It never writes secrets to `machine.conf`.

> **Prefer the wizard over installing layers by hand.** A hand-copied `machine.conf` that doesn't
> match your real interfaces/subnet will install cleanly but mis-bind services (e.g. dnsmasq
> listening on an address that isn't on your LAN interface).

## Per-machine configuration

Machine-specific values live in **`/etc/bastion/machine.conf`** (created by the wizard; never
committed — it's your real topology). `bastion generate` renders it into the layer configs and a
flat `/etc/bastion/machine.env` that the operational scripts read. An annotated template ships at
`bastion/machine.conf.example`.

Key sections you provide:

| Section | What you set |
|---|---|
| `[machine]` | `mode` (edge/endpoint), `profile`, active `layers`, `distro` |
| `[interfaces]` | `lan`, `wan` (edge), optional `wg_server_iface` / `wg_vps_iface` / `zt_iface` |
| `[network]` | `lan_cidr`, `lan_ip`, `gateway`, `dns_upstream`, DHCP pool, `trusted_hosts` |
| `[ports]` | `ssh` listen port (detected from running sshd; confirm before locking down) |
| `[ai]` | backend command, model, analysis `depth` (regular/advanced/expert) |
| `[recovery]` | `bastion-recovery` knobs (self-destruct window, fallback ports) |
| `[monitoring]` | egress probe URL, relay far-end, NM connection, blocklist sources |

**Secrets are kept out of `machine.conf`.** API keys go in `secrets.conf` / a systemd
`EnvironmentFile` (`/etc/edge-ai/claude.env`, chmod 600); alert sinks go in
`/etc/bastion/notify-alert.conf`; a ZeroTier network ID is joined directly and never stored in
config. See `secrets.conf.example`.

## Manual steps & known pain points

These are the things `bastion` deliberately does **not** do for you, and the rough edges to know
about before you start:

1. **The LAN interface IP is the OS's job, not bastion's (edge mode).** Bastion configures the
   firewall, DNS, and DHCP — it does **not** assign your LAN interface address. Bring the LAN
   interface up with its static IP **before** installing L4, or dnsmasq/unbound won't bind:

   ```sh
   ip addr add 192.168.1.1/24 dev <lan-iface>
   ip link set <lan-iface> up
   ```

   That command is **not persistent across reboots** — configure the address permanently with
   systemd-networkd, NetworkManager, or your distro's network tooling. The `lan_ip`/`lan_cidr` in
   `machine.conf` must match the address actually on that interface.

2. **CrowdSec (L2) is AUR-only on Arch.** Bastion never builds AUR packages itself. On Arch,
   install crowdsec first, then (re-)run the layer:

   ```sh
   paru -S crowdsec               # or makepkg
   sudo bastion layer install l2
   ```

   Until then, L2 reports `installed: no` and the reconciler simply has no CrowdSec decisions to
   ingest — every other layer is unaffected. On Debian/Ubuntu, crowdsec installs from its APT repo.

3. **WireGuard keys come from the wizard, not `layer install`.** `bastion layer install l5`
   installs the tools and brings up ZeroTier, but **skips any WireGuard interface that has no
   config** — it will not invent a key. `bastion setup` generates the keypair and writes
   `/etc/wireguard/<iface>.conf` (chmod 600). Run the wizard, or drop in your own conf, before
   expecting `wg` interfaces to come up. Existing confs are never overwritten.

4. **bastion manages dnsmasq/unbound configs.** Installing those packages may leave
   `/etc/dnsmasq.conf.pacnew` / `/etc/unbound/unbound.conf.pacnew` — that's normal; bastion renders
   its own configs to those paths from your `machine.conf`.

5. **Lock the SSH port down carefully.** Expert depth and tight rulesets can change the SSH port.
   The always-installed **`bastion-recovery`** service (disabled by default) is your console-only
   lifeline if you lock yourself out — it auto-detects live sshd ports and opens a time-boxed
   rescue path. Start it **from a local console / IPMI**, read back the port + one-time password it
   prints, SSH in, fix the config, then stop it:

   ```sh
   sudo systemctl start bastion-recovery     # opens a time-boxed rescue sshd (auto-detected ports)
   sudo journalctl -u bastion-recovery -n 20 # reads back: bound port(s), reachable IP(s), OTP
   sudo bastion-recovery extend              # (over the rescue session) extend the window if needed
   sudo systemctl stop bastion-recovery      # tears it all down; the main firewall is untouched
   ```

   It self-destructs after `[recovery] window_seconds` (default 1800). Test it once before you need
   it — start it, confirm you can reach the announced port, then stop it.

## Operating it

```sh
bastion status --health        # per-layer install / active / health
bastion check --full           # read-only flow + LAN-client verification
bastion firewall reload        # reconcile the nft ruleset
bastion ai enable | panic      # arm the AI layer / kill switch (instant disarm)
```

### Tuning the AI layer (L3)

The AI layer is opt-in and provider-agnostic. Two knobs in `machine.conf [ai]` shape how it runs:

- **`timer_interval`** — how often the collect → analyze → reconcile cycle runs, as a systemd time
  span (`4h`, `30min`, `90s`, `2h30m`, `1d`; **case-sensitive**: `m` = minutes, `M` = months). To
  change the cadence after install, edit `timer_interval`, then:

  ```sh
  bastion generate          # re-render edge-ai.timer
  bastion ai enable         # daemon-reload + restart so the new interval takes effect
  ```

- **`depth`** — `regular` (default) / `advanced` / `expert`: how much config the AI is *shown*.
  It controls breadth of context, **not** authority — base/access changes (e.g. the SSH port) are
  always routed to a human-review queue and never auto-applied at any depth.

### DNS-leak guard (edge mode)

When the hardened local resolver chain is expected (a loopback `dns_upstream`), the L6 watchdog
and `bastion check` actively flag a `/etc/resolv.conf` (or systemd-resolved upstream) that points
at a public/ISP resolver — e.g. after a DHCP renew silently re-points it. It **alerts only**;
bastion never rewrites your resolver config.

## CLI

| Command | Purpose |
|---|---|
| `bastion setup` | guided install / configure / verify wizard |
| `bastion generate` | render templates → configs + `machine.env` |
| `bastion status [--health]` | per-layer install / active / health |
| `bastion tui` | live dashboard (layer health, set counts, AI state, audit tail) + a command palette for every operation, with confirmation gating — a single confirm for state changes and a typed confirmation for destructive ones (layer teardown, firewall reload, network rollback) |
| `bastion layer <install\|uninstall\|status> <id>` | manage a single layer |
| `bastion firewall <reload\|status>` | reconcile / inspect the nft ruleset |
| `bastion ai <enable\|disable\|panic\|status>` | control the optional AI layer (kill switch) |
| `bastion ai proposals \| accept <id> \| reject <id>` | review the AI human-review queue and record a decision (nothing auto-applies) |
| `bastion ai rollback <id>` | undo the elements one audit record applied |
| `bastion verify` | check live configs still match what `generate` would produce (drift detection) |
| `bastion doctor` | one-shot triage: binaries, drift, firewall persistence, recovery, AI |
| `bastion snapshot [--name N] \| snapshots \| rollback [N] \| confirm` | capture (optionally named) / list / restore known-good network state; confirm egress then disarm the watchdog |
| `bastion setup --bootstrap` | soft recovery: re-detect from scratch and show where the current config disagrees with the live system |
| `bastion recovery <start\|stop\|extend\|status>` | operate the out-of-band rescue service |
| `bastion update <feeds\|dnsblock>` | refresh threat feeds / DNS blocklist now (don't wait for the timer) |
| `bastion check [--full\|--lan]` | read-only flow & LAN verification |

Full per-command reference: **[docs/commands.md](docs/commands.md)**. When something goes wrong:
**[docs/troubleshooting.md](docs/troubleshooting.md)**.

## Design principles

- No real IPs, hostnames, MACs, or keys in the repository — templates use `{{ }}` placeholders.
- No-arch-leak: the AI wizard sends only sanitized topology signals to any external API.
- No hard service dependencies on external or boot-path units.
- Idempotent: every install action is safe to re-run.
- Narrowest scope; a human kill switch and an always-installed recovery service are mandatory.

## Development

```sh
make leak-check        # leak gate (must pass before every commit)
make generate-check   # all templates resolve against bastion/machine.conf.example
python -m pytest -q   # test suite
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

## License

[MIT](LICENSE).
