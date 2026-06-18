# Troubleshooting

Symptom → cause → fix for the failure modes that actually come up. Start with the two read-only
triage commands — they pinpoint most problems without changing anything:

```sh
bastion doctor          # binaries, config drift, persistence, recovery readiness, AI state
bastion verify          # do the live configs still match `bastion generate`?
bastion check           # egress / DNS / firewall flow checks
```

---

## Setup & install

### Setup aborts: "ufw/firewalld is active — it would be flushed"
**Cause.** bastion's ruleset begins with `flush ruleset`; loading it while another firewall manages
nftables would wipe that firewall's rules and the two would fight. bastion refuses by design.
**Fix.** Disable the other firewall first, then re-run:
```sh
sudo systemctl disable --now ufw          # or firewalld
sudo bastion setup
```
To deliberately let bastion take over (it becomes the only firewall): set
`BASTION_ALLOW_FIREWALL_TAKEOVER=1` in the environment for the install.

### A package install fails / a layer can't find its binary
**Cause.** A required package isn't installed, or lives in a third-party repo bastion won't touch.
**Fix.** bastion installs resolvable packages itself and **names** the rest with an install hint:
- **CrowdSec (L2)** is AUR-only on Arch and ships from CrowdSec's own repo on Debian/Fedora. Install
  it out of band (`paru -S crowdsec` on Arch; add CrowdSec's APT/DNF repo elsewhere), then re-run.
- Setup now warns about this at **profile selection**, not just at install time.
- Every other layer works without CrowdSec — it's only a detection *source*.

### "missing required command(s): …"
**Cause.** An operational script (e.g. `flowcheck`, `edge-watchdog`) needs a binary that isn't
installed — it now says so up front instead of failing obscurely.
**Fix.** Install the named command and re-run. Common ones: `curl`, `conntrack`/`conntrack-tools`
(L6 LAN-client checks), a DNS tool (`dig`/`drill`/`kdig`) for the local-stub probe.

### Unsupported package manager
**Cause.** bastion drives `pacman`, `apt`, and `dnf`. Another manager (e.g. openSUSE's `zypper`,
Alpine's `apk`) is detected and named, but not driven.
**Fix.** Install the layer packages by hand (setup lists them), then continue.

---

## Firewall & networking

### The ruleset didn't load after install (especially Fedora/RHEL)
**Symptom.** `nft list tables` is empty even though `bastion layer install l0` reported success.
**Cause (historical, now auto-fixed).** Fedora/RHEL's stock `nftables.service` loads
`/etc/sysconfig/nftables.conf`, not the `/etc/nftables.conf` bastion writes. Current versions install
a systemd drop-in that pins the loader to bastion's file on every distro.
**Fix.** Reinstall L0 to pick up the drop-in, then confirm:
```sh
sudo bastion layer install l0
systemctl cat nftables.service | grep ExecStart   # -> nft -f /etc/nftables.conf
nft list tables                                   # -> table inet bastion (or inet edge)
```

### The ruleset is gone after a reboot
**Cause.** `nftables.service` wasn't enabled, so nothing reloads the rules at boot.
**Fix.** `bastion layer install l0` enables it. Check with `systemctl is-enabled nftables` (should be
`enabled`) and `bastion doctor` (reports persistence).

### LAN clients get an address but can't reach the internet (edge)
**Cause.** A router passes traffic between networks only when the kernel's IP-forwarding switch is on.
bastion enables it for edge mode via `/etc/sysctl.d/99-bastion-forward.conf` (rendered by `generate`,
applied on `layer install l0`). If that file is missing or wasn't applied, the forward chain is inert
and forwarded packets are dropped before the rules run.
**Fix.** Reinstall L0 (re-applies the sysctl), then confirm:
```sh
sudo bastion layer install l0
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding   # edge: 1 / 1 (or 1 / 0 if ipv6_forward=no)
```
IPv6 routing is controlled by `[network] ipv6_forward` in `machine.conf` (default `yes`; set `no` for a
v4-only edge — the v6 firewall rules stay loaded but inert). Endpoints never forward.

### DHCP clients need fixed addresses (reservations)
**Cause.** Reservations pin a host's MAC to a stable IP. MACs are installation-specific, so bastion does
**not** ship them in the managed `dnsmasq.conf`.
**Fix.** `dnsmasq.conf` reads `/etc/dnsmasq.d/*.conf`; add reservations in a local drop-in that never
enters the repo:
```sh
# one line per host: dhcp-host=<MAC>,<IP>,<name>
sudoedit /etc/dnsmasq.d/reservations.conf
sudo systemctl reload dnsmasq
```

### `bastion check` shows failures on a healthy box
**Cause.** Several `flowcheck` lines are **edge-only** (local DNS stub, the `LAN_IP:53` dnsmasq
listener, the relay handshake, the WireGuard server iface). On an **endpoint**, or on an edge box
where you didn't install L4 (DNS) / L5 (VPN), those legitimately can't pass.
**Fix.** This is expected — judge the checks against the layers you installed. Endpoint mode already
skips the edge-only flows; the remaining failures map to uninstalled layers, not a broken firewall.

### Egress keeps flapping / the watchdog rolls back repeatedly
**Cause.** An upstream/ISP outage or a physically-down WAN carrier — a rollback can't fix either, and
bastion is built **not** to churn on them (it alerts and backs off). If you *do* see rollback churn,
it's usually a stale known-good snapshot.
**Fix.** Once egress is genuinely stable, accept it as the new baseline:
```sh
sudo bastion confirm      # verifies ~45s of stable egress, then disarms the watchdog
```

### DNS resolves but a leak is reported (`host resolver leak …`)
**Cause.** The host's `/etc/resolv.conf` points at a public/ISP resolver (often after a DHCP renew),
bypassing the hardened local DNS chain (dnsmasq → unbound). bastion **alerts only** — it never
rewrites your `resolv.conf`.
**Fix.** Point the host at the local chain (loopback stub or this node's `LAN_IP`) via your network
manager (systemd-resolved / NetworkManager / networkd). On an endpoint or with an external upstream
this check doesn't apply.

---

## Lockout & recovery

### I changed the SSH port / a rule and locked myself out
**From the console** (serial/IPMI/physical):
```sh
sudo bastion recovery start
```
This stands up a second SSH on a free port with an ephemeral user + one-time password, prints exactly
how to connect, and self-destructs after the window (extend with `bastion recovery extend`, end with
`bastion recovery stop`). It never touches the main firewall or sshd.

### The machine.conf has the wrong values (e.g. stale SSH port)
```sh
sudo bastion setup --bootstrap
```
Re-detects everything from the live system, refuses to trust the existing `machine.conf` for detected
values, and prints exactly where the current config disagrees (the usual lockout culprit).

### Network is broken after a change — get back to known-good
```sh
sudo bastion rollback                 # restore the auto known-good snapshot (net-rollback)
sudo bastion rollback <name>          # …or a named one (see `bastion snapshots`)
```
`net-rollback` is a gentle, idempotent restore (LAN addr, firewall, route, DNS) and is safe to run
when state already matches.

---

## AI layer (L3)

### The AI analysis isn't running
**Cause.** L3 is opt-in: the timer ships **disabled**, and reinstalling L3 disables it again.
**Fix.** `sudo bastion ai enable`, then `bastion ai status`. After an upgrade that reinstalls L3,
re-arm it.

### The AI proposed a change but nothing happened
**By design.** Base/access changes (e.g. SSH port) never auto-apply — they go to a review queue:
```sh
bastion ai proposals
sudo bastion ai accept <id>      # or: reject <id>
```
To drop everything the AI added to the firewall right now: `sudo bastion ai panic`.

---

## Still stuck?

- `bastion status --health` — per-layer health detail.
- `journalctl -t edge-watchdog -t edge-reconciler -t bastion-recovery` — the operational scripts log
  full detail to the local journal (external alerts are deliberately generic — no topology on the wire).
- File an issue with `bastion doctor` output (it contains no real IPs/hostnames/keys).
