# Bastion (`bastionfw`)

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

A modular, layered Linux firewall framework with an operator CLI, an optional AI-driven
analysis layer, and an intelligent setup wizard. It targets both **edge** routing machines
and ordinary **endpoint** computers, and installs from scratch on a fresh system.

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

## Requirements

- Linux with **nftables**
- **Python ≥ 3.11**
- **`pacman` or `apt`** (used to install layer packages during setup)
- **root** for any live install (loading nft rules, installing systemd units, installing packages)

## Install

**Arch (AUR):**

```sh
paru -S bastionfw      # or: yay -S bastionfw
```

**From source:**

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
   rescue path. Know it's there before you tighten access.

## Operating it

```sh
bastion status --health        # per-layer install / active / health
bastion check --full           # read-only flow + LAN-client verification
bastion firewall reload        # reconcile the nft ruleset
bastion ai enable | panic      # arm the AI layer / kill switch (instant disarm)
```

## CLI

| Command | Purpose |
|---|---|
| `bastion setup` | guided install / configure / verify wizard |
| `bastion generate` | render templates → configs + `machine.env` |
| `bastion status [--health]` | per-layer install / active / health |
| `bastion layer <install\|uninstall\|status> <id>` | manage a single layer |
| `bastion firewall <reload\|status>` | reconcile / inspect the nft ruleset |
| `bastion ai <enable\|disable\|panic\|status>` | control the optional AI layer (kill switch) |
| `bastion check [--full\|--lan]` | read-only flow & LAN verification |

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
