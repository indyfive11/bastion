# FAQ

Short answers to the questions that come up first. For depth, follow the links into the
[architecture](architecture.md), [layers](layers.md), [use-cases](use-cases.md), and
[troubleshooting](troubleshooting.md) docs.

## General

**What is bastion, in one sentence?**
A modular, layered Linux firewall framework — an operator CLI, an optional AI analysis layer,
and a guided setup wizard — that turns a spare machine into a defense-in-depth router/firewall
or hardens a single endpoint, built on plain nftables.

**Is it a replacement for nftables / a firewall GUI / a cloud service?**
No. It *orchestrates* nftables (plus systemd, dnsmasq/unbound, WireGuard/ZeroTier, CrowdSec)
from one per-machine config. There's no GUI, no required cloud, and no account. The data path
is in-kernel nftables you can inspect directly.

**What distros does it run on?**
Arch (and Arch-based) is the primary, regularly-tested target. Debian/Ubuntu (`apt`) and
Fedora/RHEL-family (`dnf`) are supported and install-validated. Another manager (e.g.
openSUSE's `zypper`) is detected and named, but you install its packages by hand. systemd is
assumed throughout. Python ≥ 3.11.

**Do I need the AI layer / an API key?**
No. Bastion is fully usable with rule-based detection and no key. The AI layer (L3) is opt-in,
provider-agnostic, and off until you `bastion ai enable` it.

**Edge vs endpoint — which do I want?**
**edge** if the machine routes/firewalls a LAN behind it (a gateway/router — needs two NICs,
uses L4 DNS/DHCP). **endpoint** for defense-in-depth on a single workstation/server (one NIC
is fine, no routing, L4 skipped). The wizard detects and proposes one; you confirm.

## Setup & config

**Where does my configuration live?**
`/etc/bastion/machine.conf` (INI, your real topology — created by the wizard, never
committed). `bastion generate` renders it into the layer configs and a flat
`/etc/bastion/machine.env` the scripts read. An annotated template is at
`bastion/machine.conf.example`.

**Can I change a setting after install without re-running the wizard?**
Yes — `bastion config` is the control room:
```sh
bastion config list [--advanced]        # settings + current values
bastion config describe machine.firewall_scope
bastion config set network.dns_upstream 127.0.0.1#5335   # validate → write → scoped reload
```
Or edit `machine.conf` directly and run `bastion generate` (plus `bastion firewall reload` for
ruleset changes). Advanced/dangerous settings require `--advanced` to acknowledge.

**Will installing wipe an existing firewall or my libvirt/Docker networking?**
Only in the default `exclusive` scope, which runs `flush ruleset`. On a box already running a
self-managing firewall the wizard proposes **`cooperative`** scope automatically (it manages
only bastion's own table), and a runtime warning fires before an `exclusive` apply would flush
a foreign table. See [use-cases §4](use-cases.md#4-coexist-with-libvirt-or-docker-cooperative-mode).

**Can I see exactly what it would do before it touches anything?**
```sh
sudo bastion setup --dry-run     # walk the wizard, print what it would write/install — no network calls
```
Nothing is written and no API is called. `--stage-only` writes config but loads no rules.

**Does it assign my LAN interface's IP (edge mode)?**
No — that's the OS's job. Bring the LAN interface up with its static IP (via
systemd-networkd/NetworkManager) **before** installing L4, and make sure `machine.conf`'s
`lan_ip`/`lan_cidr` match it.

## Safety & lockout

**What stops me from locking myself out?**
Three things: a **snapshot/rollback** safety net, a **watchdog** that heals egress failures,
and **`bastion switch`** — a deadman cutover that auto-reverts a change unless you
`bastion confirm` you still have access. On top of that, **`bastion-recovery`** (always
installed, disabled by default) is a console-started ephemeral rescue sshd. See
[architecture — the safety-net triad](architecture.md#the-safety-net-triad).

**I locked myself out anyway. Now what?**
From a local console: `sudo bastion recovery start`, read the announced port + one-time
password from `journalctl -u bastion-recovery`, SSH in, fix it, `sudo bastion recovery stop`.
If the config itself is wrong, `sudo bastion setup --bootstrap` re-detects and shows the diff.
Full recipe: [use-cases §6](use-cases.md#6-recover-from-a-lockout).

**Is it safe to re-run setup / install a layer twice?**
Yes. Every action is idempotent — it applies only the difference between current and desired
state. Existing WireGuard confs and hand-authored DHCP reservations are never overwritten.

## The AI layer

**What can the AI actually change?**
Only the dynamic block sets, and only through the re-validating reconciler. Anything touching
base/access config (e.g. an SSH port) goes to a **human-review queue**
(`bastion ai proposals` → `accept`/`reject`) and never auto-applies at any depth.

**What does the AI see about my network?**
Only sanitized signals — interface *types*, which services were detected, your wizard answers,
sshd auth-failure counts. Never your IPs, MACs, hostnames, or keys. `depth`
(regular/advanced/expert) changes how much config it's *shown*, not its authority.

**How do I turn it off right now?**
`sudo bastion ai panic` flushes everything the AI added instantly; `sudo bastion ai disable`
disarms the timer.

## Firewall specifics

**How do I let only the LAN reach a service?**
Zones: `bastion zones add lan 192.168.1.0/24 8096 8989` accepts those ports from that source
and nothing else. Source can be `any`, an IP/CIDR, or `iface:NAME`. See
[use-cases §3](use-cases.md#3-expose-a-service-to-just-the-lan-zones).

**Is IPv6 filtered too?**
Yes — every managed set has a v6 sibling and the reconciler routes each blocked source to the
family-matched set. `trusted_hosts` and zones accept v6 sources. A v4-only edge can set
`[network] ipv6_forward = no`.

**Who writes the nftables sets?**
Exactly one process: the reconciler (`edge-reconciler`, from L1). Feeds, CrowdSec, and the AI
layer all hand it *desired* elements; it validates and applies. That single choke point is
what makes layering intelligence on top safe.

**`systemctl is-active nftables` says inactive but my rules are loaded — bug?**
No. `nftables.service` is a oneshot loader. bastion ships a drop-in so a loaded firewall
reports `active (exited)`, but the real source of truth is `nft list tables` / `bastion doctor`,
not the unit's active state. See
[troubleshooting](troubleshooting.md#systemctl-is-active-nftables-says-inactive-but-the-rules-are-loaded).

## When something's wrong

**First move?**
```sh
bastion doctor     # binaries, drift, reboot persistence, recovery readiness, AI state
bastion verify     # do live configs still match `bastion generate`?
bastion check      # egress / DNS / firewall flow checks
```
Then the [troubleshooting guide](troubleshooting.md). Operational detail is in the local
journal: `journalctl -t edge-watchdog -t edge-reconciler -t bastion-recovery`.

**How do I report a bug without leaking my network?**
`bastion doctor` output contains no real IPs/hostnames/keys — it's safe to attach to an issue.
