# Getting started

The 5-minute path from a fresh box to a working bastion firewall. Deeper docs are linked at
each step — come back here when you just want to *get running*.

## 1. Is this for me?

Bastion firewalls one Linux box, in one of two modes:

- **endpoint** — hardens a single workstation, laptop, or server (no routing). Works on **one NIC**.
- **edge** — turns a machine into a routing firewall / gateway for a LAN behind it. Needs **two NICs**
  (one WAN, one LAN) and an out-of-band console for first setup.

If you want a scriptable, defense-in-depth alternative to consumer-router firmware, or hardening for
a server you already run, it fits. If you want a firewall GUI or a cloud service, it doesn't.

## 2. Install

**Arch (AUR):**

```sh
paru -S bastionfw          # or: yay -S bastionfw
```

**Debian/Ubuntu, Fedora/RHEL, or from source:**

```sh
git clone https://github.com/indyfive11/bastion
cd bastion
pipx install .             # provides the `bastion` CLI
```

You need Linux with **nftables**, **Python ≥ 3.11**, and `pacman`/`apt`/`dnf`. Any live install needs
**root**. Full requirements + distro notes: [README](../README.md#requirements).

## 3. Set it up (the wizard does the work)

Run the guided wizard as root. It detects your topology, asks only what it can't infer, writes
`/etc/bastion/machine.conf`, generates every config, installs the layers behind an auto-reverting
safety net, and verifies the result:

```sh
sudo bastion setup                 # interactive: detect → profile → configure → install → verify
sudo bastion setup --dry-run       # offline preview — writes nothing, makes no network calls
```

Pick a **profile** when it asks:

| Profile | For |
|---|---|
| `full-endpoint` | a workstation/server with threat feeds + monitoring |
| `minimal-endpoint` | just the firewall, feeds, and watchdog |
| `full-edge` | a router/firewall box with DNS/DHCP, VPN, and the AI layer |
| `basic-edge` | an edge box without the AI and VPN layers |

> **Edge only:** give the LAN interface its IP *yourself* before setup — bastion configures the
> firewall, not the interface address. See [use cases §1](use-cases.md#1-stand-up-an-edge-router--firewall-box).

Prefer the wizard over installing layers by hand — a hand-written `machine.conf` that doesn't match
your real interfaces installs cleanly but mis-binds services.

## 4. Check it's healthy

```sh
bastion status --health    # every layer installed / active / healthy?
bastion check              # egress + flow checks (add --full for the LAN forward path)
bastion doctor             # one-shot triage: binaries, drift, persistence, recovery, AI
```

## 5. Open a port (zones)

Inbound access is one rule per `source → action`. Open a port to a source with a single command —
it previews the exact rule, then applies:

```sh
bastion zones add lan 192.168.1.0/24 8096 8989   # LAN reaches those tcp ports (not SSH)
bastion zones add wg  10.0.0.0/24 22             # a WireGuard subnet reaches SSH
bastion zones add wg  10.0.0.0/24 22 --dry-run   # preview the exact +/- rule, apply nothing
bastion zones list
bastion zones remove lan
```

Bare port = **tcp**; add `/udp` for udp. Pick the narrowest source (a `/32`, not the whole subnet). A
zone that would open SSH to a public range is flagged before it applies. Full semantics:
[zones & ownership](options/zones-and-ownership.md).

## 6. Change a live firewall safely

A wrong rule can lock you out. For any risky cutover, apply it behind an auto-reverting deadman:

```sh
sudo bastion switch --minutes 10   # snapshot → apply → arm a 10-min auto-revert
bastion confirm                    # still have access? lock it in (cancels the revert)
# ...do nothing and it rolls back to the previous firewall on its own
```

Locked out anyway? From a local console: `sudo bastion recovery start` opens a time-boxed rescue SSH
path and prints the port + one-time password. See [recover from a lockout](use-cases.md#6-recover-from-a-lockout).

## Where to go next

- **[Use cases & recipes](use-cases.md)** — end-to-end: stand up an edge router, coexist with
  libvirt/Docker, turn on the AI layer, remove bastion cleanly.
- **[Command reference](commands.md)** — every subcommand and flag. Also `man bastion`, or
  `bastion <command> --help`.
- **[Troubleshooting](troubleshooting.md)** — symptom → cause → fix.
- **[FAQ](faq.md)** · **[Architecture](architecture.md)** · **[Layers](layers.md)**
