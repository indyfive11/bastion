# Live integration tests (VM only)

The mocked-`System` pytest suite never executes the operational scripts that actually run the
firewall (`edge-reconciler`, `edge-watchdog`, `net-snapshot`/`net-rollback`, `flowcheck`, the
`edge-ai` pipeline). `vm_edge_integration.sh` closes that gap: it drives a real
`setup -> layer install -> running firewall` on an EDGE node and asserts the live result —
nft tables/sets, reconciled set sizes, systemd unit state, the self-heal round-trip, and the
mock AI pipeline.

**It is destructive** (loads `table inet edge`, enables `nftables.service`, installs units). Run it
**only inside the disposable `bastion-test` KVM guest** — never on a real host. These scripts are not
collected by `pytest` (no `test_*.py`); they are a separate live tier that gates a release.

## Run it on the VM

The guest reaches the dev host (EM) at the slirp gateway `10.0.2.2`, so serve the working tree on
EM's loopback and pull it in (ships untracked-but-not-ignored files too, so brand-new code is
included):

```sh
# On EM (host):
git ls-files -z --cached --others --exclude-standard \
  | tar --null -czf /tmp/bastion.tar.gz --transform='s,^,bastion/,' -T -
python -m http.server 8731 --bind 127.0.0.1 --directory /tmp     # loopback only

# In the guest (as arch), pull straight into tar — never `curl -o` (slirp curl: (23) truncation):
cd /home/arch && rm -rf bastion && curl -sS http://10.0.2.2:8731/bastion.tar.gz | tar xz && cd bastion

# Run detached + poll the log over the serial console (more reliable than per-command console driving):
sudo setsid bash -c 'REPO=/home/arch/bastion bash tests/integration/vm_edge_integration.sh \
  > /tmp/integration.log 2>&1' < /dev/null
# then poll: tail -n 40 /tmp/integration.log ; grep -E "INTEGRATION:|\[FAIL\]" /tmp/integration.log
```

Exit status: `0` = `INTEGRATION: GREEN`, `1` = at least one `[FAIL]`.

## Tunables (env vars)

`REPO` (checkout dir) · `PYBIN` (default `python3`) · `LAYERS` (default `l0 l1 l3 l6`) ·
`LAN_IFACE`/`WAN_IFACE` (default `eth1`/`eth0`) · `LAN_CIDR`/`LAN_IP`/`GATEWAY`
(default `192.168.50.0/24` / `192.168.50.1` / `10.0.2.2` — the VM's values).

`l2` (CrowdSec, AUR-only — build it first per the harness notes), `l4` (dnsmasq) and `l5` (vpn)
are opt-in: add them to `LAYERS` once their prerequisites are staged.

Full VM lifecycle, snapshots, and gotchas live in the `reference-vm-test-harness` memory.
Start from the `edge-v105-validated` snapshot (eth1 up, edge-ready) for the fastest clean run.
