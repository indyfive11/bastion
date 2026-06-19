# Firewall zones, ownership mode & safe cutover

Three capabilities that let bastion firewall the full spectrum of hosts — a simple endpoint, an
edge router, **and** a server that already runs another firewall manager (libvirt, Docker) — and
cut over to it without risking a lockout.

1. **[Zones](#zones)** — a unified `source → action` inbound-access policy.
2. **[Ownership mode](#ownership-mode)** — whether bastion owns the *whole* nftables ruleset or
   only its own table (coexisting with libvirt/Docker).
3. **[`bastion switch`](#safe-cutover-bastion-switch)** — an auto-reverting cutover so a change that
   locks you out rolls itself back.

The setup wizard **detects and proposes** all three from what's already on the box; you confirm or
override. Nothing here is mandatory — a plain endpoint never needs a single zone, stays `exclusive`,
and never has to use `switch`.

---

## Zones

A **zone** is one inbound-access rule:

```
<name> = <source> -> <action>
```

| Field | Values |
|---|---|
| `source` | `any` · an IP or CIDR (`192.168.1.0/24`, `10.0.0.5`, `fd00::/8`) · `iface:NAME` (a whole interface, e.g. `iface:virbr0`) |
| `action` | `all` (full inbound access from that source) · a port list (`8096`, `8096, 8989`, `53/udp`, `22/tcp 9993/udp`) |

Zones live in a `[zones]` section of `machine.conf` and render as **inline nftables accept rules**
in the input chain — so a CIDR source needs no named set (and sidesteps the named-set CIDR
limitation that affects `trusted_hosts`). `tcp` and `udp` ports become separate rules automatically;
`all` emits a source-only accept.

### Example

```ini
[zones]
lan      = 192.168.1.0/24 -> 8096, 8989, 7878
ztmedia  = 192.168.192.0/24 -> 8096, 1111
wg       = 10.0.0.0/24 -> 22
vms      = iface:virbr0 -> all
ztctl    = any -> 9993
```

This says: the LAN reaches the media ports but **not** SSH; a ZeroTier subnet reaches media + SSH on
1111; a WireGuard subnet reaches SSH on 22; anything on the `virbr0` bridge is fully trusted; and
ZeroTier's control port 9993 is open to any source.

### Managing zones

Edit `[zones]` by hand and run `bastion generate` (+ `bastion firewall reload`), or use the verb —
which validates, writes `machine.conf`, regenerates, and reloads in one step:

```sh
bastion zones list                                  # show current zones
bastion zones add lan 192.168.1.0/24 8096 8989      # source then ports (space-separated)
bastion zones add vms iface:virbr0 all              # trust a whole interface
bastion zones add ztctl any 9993                    # any-source port
bastion zones remove lan                            # drop a zone
```

On an **edge** box the WAN-facing drop fires first, so zones apply to LAN/overlay traffic only. A bad
zone (malformed source, out-of-range port) is rejected before anything is written.

### Relationship to `trusted_hosts` and `service_ports`

`network.trusted_hosts` (a source → `all`) and `network.service_ports` (`any` → ports) are the two
special cases zones generalize. They keep working unchanged; zones are additive. New configurations
should prefer zones for anything beyond those two simple cases.

---

## Ownership mode

`[machine] firewall_scope` controls how much of the kernel ruleset bastion claims:

| Value | Behavior | Use when |
|---|---|---|
| `exclusive` *(default)* | bastion owns the entire ruleset — its rendered file begins with `flush ruleset`. | A dedicated firewall box, a laptop/endpoint, a VPS — bastion is the only firewall. |
| `cooperative` | bastion manages **only its own table**; the rendered file resets just that table (and, on edge, the NAT table) and leaves co-resident tables intact. | A host that also runs **libvirt** or **Docker**, whose own NAT/forward tables (`ip libvirt_network`, Docker's chains) must survive. |

In `cooperative` mode, `flush ruleset` is never issued — so a libvirt/Docker host keeps its VM/
container networking while bastion adds its filtering. The rollback path (`net-rollback`) is
scope-aware too: a cooperative rollback deletes only bastion's table, never the whole ruleset.

```sh
# inspect / change (ADVANCED setting — the flag acknowledges the blast radius)
bastion config get machine.firewall_scope
bastion config set machine.firewall_scope cooperative --advanced
```

> ### ⚠️ Safety: `exclusive` flushes the **entire** nftables ruleset
>
> `exclusive` mode begins its ruleset with `flush ruleset`, which deletes **every** nftables table on
> the box — not just bastion's, and not just other *firewalls'*. **Any** tool that manages its own
> nftables tables (libvirt, Docker, Kubernetes/CNI, Tailscale, a hand-written table) loses them the
> moment an `exclusive` ruleset loads. Two safety nets guard against this:
>
> 1. **Detection defaults to `cooperative` whenever anything else owns nft state.** The wizard
>    proposes `cooperative` if it finds a libvirt/Docker/podman *service* **or — the catch-all —**
>    **any** co-resident nft table that isn't bastion's. So k8s/CNI, Tailscale, and hand-written
>    tables are covered as long as their table is present when you run setup.
> 2. **A runtime hard-warning** fires before any `exclusive` apply/reload (`layer install l0`,
>    `firewall reload`, `switch`) that would flush a foreign table, naming the tables that would be
>    deleted and how to switch to `cooperative`.
>
> **The residual gap to mind:** if a manager is configured but has **no table loaded at the moment you
> install** (e.g. Docker installed with no containers, a CNI that's down) *and* it isn't libvirt/
> Docker/podman, detection can't see it — and a later `exclusive` reload would flush it once it comes
> up. When in doubt, run `sudo nft list tables` first: if you see **any** table that isn't bastion's
> (`inet edge` / `inet bastion` / `ip edge_nat` / `inet bastion_recovery`), use `cooperative`:
>
> ```sh
> bastion config set machine.firewall_scope cooperative --advanced
> # ...or set `firewall_scope = cooperative` in machine.conf directly.
> ```
>
> *(Naming more managers explicitly — k8s/Tailscale — for clearer messaging is a tracked roadmap item;
> the catch-all already protects them.)*

> **Note:** `cooperative` is about coexisting with NAT/forward managers (libvirt/Docker/k8s/mesh). It
> is **not** for running beside a second *input-filter* firewall — bastion still warns if `ufw`/
> `firewalld` is active, because two input filters at the same hook priority is ambiguous. The
> difference is that in `cooperative` mode it warns and proceeds instead of refusing.

### What the wizard proposes

`bastion setup` reads the box's live state and **proposes** a scope:

- It finds a libvirt/Docker/podman **service**, **or — the catch-all — any** co-resident nft table
  that isn't bastion's (Kubernetes/CNI, Tailscale, a hand-written table, …) → proposes
  **`cooperative`**.
- Only when nothing else owns nft state → **`exclusive`**.

Always review the proposed scope (`sudo bastion setup --dry-run`) before a live apply. See the safety
warning above for the one residual gap (a manager with no table loaded at install time).

It also **synthesizes a `[zones]` policy** from the box's existing intent — most usefully by parsing
an existing (even *disabled*) `ufw` rule set (`ufw show added`) into zones. You see the proposal and
accept or decline; declining keeps `exclusive` with no synthesized zones. Preview it without
touching anything:

```sh
sudo bastion setup --dry-run          # detect + propose scope/zones; writes nothing
```

---

## Safe cutover (`bastion switch`)

Switching a live box onto a new firewall risks locking yourself out (a wrong SSH source, a dropped
management subnet). The standing watchdog only heals **egress** failures — it can't tell that *you*
lost access while the box itself is still online. `bastion switch` closes that gap with a deadman:

```sh
sudo bastion switch --minutes 10
```

It will, in order:

1. **Print the manual rollback one-liner first** (scope/mode-aware), so you have it even if
   everything else fails.
2. **Snapshot** the known-good state (`net-snapshot`).
3. **Apply** the new firewall (`generate` + `firewall reload`).
4. **Arm a timer** that runs `net-rollback` after `--minutes` (default 10).
5. Tell you to confirm.

If you still have access, lock the change in **before the timer fires**:

```sh
bastion confirm        # egress check passes -> cancels the deadman, keeps the new config
```

If you *don't* confirm (because you got locked out, or egress is down), the timer fires and
`net-rollback` restores the snapshot — the box returns to its previous known-good firewall on its
own. Preview without applying or arming anything:

```sh
bastion switch --dry-run
```

Use this for any risky cutover: turning a box into an edge router, applying a freshly-synthesized
zone policy, or flipping ownership mode on a production host.
