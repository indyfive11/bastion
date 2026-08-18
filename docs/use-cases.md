# Use cases & recipes

End-to-end walkthroughs for the things people actually set bastion up to do. Each recipe is
self-contained; commands that change a live system need **root**. The example addresses
below (`192.168.1.0/24`, `10.0.0.0/24`, …) are placeholders — substitute your own.

Jump to:

- [Stand up an edge router / firewall box](#1-stand-up-an-edge-router--firewall-box)
- [Harden a laptop or server endpoint](#2-harden-a-laptop-or-server-endpoint)
- [Expose a service to just the LAN (zones)](#3-expose-a-service-to-just-the-lan-zones)
- [Coexist with libvirt or Docker (cooperative mode)](#4-coexist-with-libvirt-or-docker-cooperative-mode)
- [Cut over a live firewall safely](#5-cut-over-a-live-firewall-safely)
- [Recover from a lockout](#6-recover-from-a-lockout)
- [Add / change threat-intel feeds](#7-add--change-threat-intel-feeds)
- [Turn on the AI layer](#8-turn-on-the-ai-layer)
- [Preview everything before you commit](#9-preview-everything-before-you-commit)
- [Cleanly remove bastion](#10-cleanly-remove-bastion)

---

## 1. Stand up an edge router / firewall box

Turn a spare two-NIC machine into a routing firewall with LAN DHCP/DNS, threat-feed +
CrowdSec blocking, and optional VPN.

**Before you start:** you need **two interfaces** (one WAN, one LAN) and an out-of-band
console (serial / IPMI / keyboard+monitor) for first setup. Give the LAN interface its IP
*yourself* — bastion configures the firewall, not the interface address:

```sh
sudo ip addr add 192.168.1.1/24 dev <lan-iface>
sudo ip link set <lan-iface> up
# then make it persistent with systemd-networkd / NetworkManager — the ip command above is not
```

Run the guided wizard and pick `full-edge` (or `basic-edge` to skip the AI and VPN layers):

```sh
sudo bastion setup --profile full-edge
```

It detects your interfaces, asks for the values it can't infer (LAN subnet, gateway, SSH
port, trusted hosts, AI backend), writes `/etc/bastion/machine.conf`, generates all configs,
installs packages, brings the layers up behind an auto-reverting deadman, and verifies. Then:

```sh
bastion status --health     # every layer install / active / healthy?
bastion check --full        # egress, DNS, and the LAN forward path
```

**Notes.** CrowdSec (L2) is AUR-only on Arch — install it first (`paru -S crowdsec`) then
`sudo bastion layer install l2`; every other layer works without it. WireGuard keys come
from the wizard, not `layer install l5`. If LAN clients get an address but no internet,
IP-forwarding didn't apply — see [troubleshooting](troubleshooting.md#lan-clients-get-an-address-but-cant-reach-the-internet-edge).

## 2. Harden a laptop or server endpoint

Defense-in-depth on a single host — no routing, no DHCP. A single-NIC box can do this even
though it can't be an edge router.

```sh
sudo bastion setup --profile full-endpoint     # or minimal-endpoint for firewall+feeds+watchdog only
```

Endpoint mode skips L4 (DNS/DHCP) and the edge-only flow checks, and relies on your upstream
router for DHCP and default routing. The firewall is interface- and IP-agnostic, so it keeps
working as the laptop roams between networks — it doesn't react to a network change, it just
filters. Verify with `bastion status --health` and `bastion check`.

**Hosting a WireGuard server on an endpoint** (e.g. a VPS relay peers dial into): configure the
WireGuard server the usual way (L5 + `/etc/wireguard/<iface>.conf`), then set
`interfaces.wg_server_iface` (and `network.wg_server_listen_port` for a non-default port) — the
firewall then opens the WireGuard listen port to any source so peers can handshake. Keep an SSH path
independent of the tunnel (LAN or a trusted IP), so a tunnel that can't come up doesn't lock you out.

## 3. Expose a service to just the LAN (zones)

**Zones** are bastion's unified inbound policy: one rule per `source → action`, where the
source is `any`, an IP/CIDR, or a whole interface (`iface:NAME`), and the action is `all` or
a port list. They render as inline nftables accepts.

```sh
bastion zones list
bastion zones add lan 192.168.1.0/24 8096 8989    # LAN reaches media ports — but NOT SSH
bastion zones add wg  10.0.0.0/24 22              # a WireGuard subnet reaches SSH
bastion zones add vms iface:virbr0 all            # trust a whole bridge
bastion zones remove lan
```

Each `add`/`remove` regenerates and reloads the firewall. Ports can carry a transport
(`53/udp`); tcp and udp render as separate lines automatically. On an edge box the WAN drop
fires first, so zones govern LAN/overlay traffic. Full semantics:
**[options/zones-and-ownership.md](options/zones-and-ownership.md)**.

> For a *risky* zones change (e.g. one that could drop your own access), apply it behind the
> deadman — see recipe 5.

## 4. Coexist with libvirt or Docker (cooperative mode)

By default bastion runs in `exclusive` scope — its ruleset starts with `flush ruleset`, which
deletes **every** nftables table on the box, including a hypervisor's or container engine's.
On a server that also runs libvirt/Docker, use `cooperative` scope, which resets only
bastion's own table and leaves the rest intact.

`bastion setup` detects a self-managing firewall (libvirt, Docker/podman, a Kubernetes node
agent, Tailscale, or *any* foreign nft table) and **proposes `cooperative` automatically**,
and synthesizes a starter `[zones]` policy from your existing (even disabled) `ufw` rules —
preview it with `sudo bastion setup --dry-run`. To set it by hand:

```sh
sudo nft list tables                                         # see what's already there
bastion config set machine.firewall_scope cooperative --advanced
```

A runtime hard-warning also fires before an `exclusive` apply would flush a foreign table.
When in doubt, check `nft list tables` and choose `cooperative` if you see any non-bastion
table.

## 5. Cut over a live firewall safely

Changing a live firewall can lock you out, and the watchdog only heals *egress* failures —
not "I can't reach the box anymore". `bastion switch` applies a change behind an
auto-reverting deadman.

```sh
sudo bastion switch --minutes 10   # print the manual-rollback line → snapshot → apply → arm timer
bastion confirm                    # still have access? lock it in (cancels the deadman)
# If egress is down for a reason unrelated to your change (fresh install, ISP outage) but you
# ARE present, `bastion confirm --force` disarms anyway — egress is not verified.
# ...do nothing and the timer runs net-rollback at the deadline, restoring the previous firewall
```

Use it for any risky cutover: turning a box into an edge router, applying synthesized zones,
flipping ownership mode. `--dry-run` previews without applying or arming anything.

> `switch` reloads the firewall; it does **not** install layers. For a *first install* use
> `bastion setup` — it installs and arms every layer behind the same deadman. Reaching for
> `switch` as the first apply would load the base ruleset but leave the layer daemons
> unstarted.

## 6. Recover from a lockout

**You changed the SSH port / a rule and can't get back in.** From a local console
(serial/IPMI/physical):

```sh
sudo bastion recovery start                 # ephemeral rescue sshd on a free port + one-time password
sudo journalctl -u bastion-recovery -n 20   # reads back: bound port(s), reachable IP(s), the OTP
# SSH in on the announced port, fix the config, then:
sudo bastion recovery stop
```

It self-destructs after its window (default 1800 s; `bastion-recovery extend` over the rescue
session extends it) and never touches the main firewall or sshd. **Test it once before you
need it.**

**The `machine.conf` itself has the wrong values** (stale SSH port, wrong interface):

```sh
sudo bastion setup --bootstrap    # re-detect from the live system; refuse to trust the stale conf; show the diff
```

**The network broke after a change** — get back to the last known-good state:

```sh
sudo bastion rollback             # restore the auto snapshot (net-rollback)
sudo bastion snapshots            # list auto + named snapshots
sudo bastion rollback <name>      # …or restore a named one
```

## 7. Add / change threat-intel feeds

L1 populates `blk_feed` from public IP blocklists; L4's sinkhole blocks domains.

```sh
bastion feeds list
bastion feeds add https://example.com/some-blocklist.txt   # blank list = built-in defaults
bastion feeds remove https://example.com/some-blocklist.txt
bastion update feeds        # refresh now instead of waiting for the timer

bastion dnsblock list       # the DNS-sinkhole domain lists (L4)
bastion update dnsblock     # rebuild the sinkhole now
```

The reconciler re-validates every feed entry against the never-block allowlist and per-source
CIDR-width floors, so a bad or over-broad feed can't take your network down. Choose feeds by
false-positive tolerance — **[options/blocklist-options.md](options/blocklist-options.md)**.

## 8. Turn on the AI layer

L3 is opt-in — its timer ships **disabled**.

```sh
sudo bastion ai enable        # arm the collect → analyze → reconcile timer
bastion ai status             # timer state, last run, counts, pending proposals
bastion ai proposals          # the human-review queue (base/access changes never auto-apply)
sudo bastion ai accept <id>   # or: reject <id>
sudo bastion ai panic         # instant kill switch: flush everything the AI added
```

Tune cadence and depth in `machine.conf [ai]` (`timer_interval`, `depth`), then
`bastion generate && bastion ai enable`. Only sanitized signals ever leave the host, and the
AI can only *propose* base/access changes — the reconciler is the choke point for what
actually gets applied.

## 9. Preview everything before you commit

Nothing here changes your system:

```sh
sudo bastion setup --dry-run     # walk the whole wizard, print what it WOULD write/install — no network calls
bastion generate --check         # prove every template placeholder resolves
bastion verify                   # do the live configs still match what generate would produce? (drift)
bastion doctor                   # one-shot triage: binaries, drift, persistence, recovery, AI
```

To review the rendered ruleset before the *first* apply: `sudo bastion setup --stage-only`
writes and generates config but loads nothing; re-run `sudo bastion setup` (without
`--stage-only`) to apply.

## 10. Cleanly remove bastion

```sh
sudo bastion teardown                 # uninstall every layer, restore nftables.service, remove /etc/bastion + /etc/edge-*
sudo bastion teardown --keep-config   # …but keep your machine.conf
```

`teardown` is the counterpart to `setup`; the AUR package runs it on `pacman -R`, so removal
leaves no stale config or units behind.
