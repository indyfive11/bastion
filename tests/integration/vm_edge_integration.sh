#!/usr/bin/env bash
# vm_edge_integration.sh — full setup -> running-firewall integration test for an EDGE node.
#
# This is the single live test that exercises the OPERATIONAL scripts the firewall actually
# runs (edge-reconciler / edge-watchdog / net-snapshot / net-rollback / flowcheck / the edge-ai
# mock pipeline) end to end — none of which the mocked-System pytest suite can touch. It is the
# capstone that should gate a v2.0 release.
#
# IT IS DESTRUCTIVE: it loads a real `table inet edge`, enables nftables.service, and installs
# systemd units. Run it ONLY inside the throwaway `bastion-test` KVM guest (see the harness notes
# in tests/integration/README.md and the reference-vm-test-harness memory) — NEVER on a real host.
#
# Usage (as root, from the repo checkout, e.g. /home/arch/bastion):
#     sudo REPO=/home/arch/bastion bash tests/integration/vm_edge_integration.sh
# It prints a [PASS]/[FAIL]/[NOTE] line per check and exits non-zero if any hard check failed.
#
# Tunables (env): REPO, PYBIN, LAYERS, LAN_IFACE, WAN_IFACE, LAN_CIDR, LAN_IP, GATEWAY.
set -u

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
PYBIN="${PYBIN:-python3}"
BASTION="$PYBIN -m bastion"
LAYERS="${LAYERS:-l0 l1 l3 l6}"        # l2 (crowdsec/AUR), l4 (dnsmasq), l5 (vpn) are opt-in extras
LAN_IFACE="${LAN_IFACE:-eth1}"         # qemu cloud image: net.ifnames=0 -> eth0/eth1
WAN_IFACE="${WAN_IFACE:-eth0}"
LAN_CIDR="${LAN_CIDR:-192.168.50.0/24}"
LAN_IP="${LAN_IP:-192.168.50.1}"
GATEWAY="${GATEWAY:-10.0.2.2}"         # qemu slirp gateway
FAM=inet TABLE=edge                    # edge-mode nft table is `inet edge`

PASS=0 FAIL=0
pass() { printf '[PASS] %s\n'  "$*"; PASS=$((PASS+1)); }
fail() { printf '[FAIL] %s\n'  "$*"; FAIL=$((FAIL+1)); }
note() { printf '[NOTE] %s\n'  "$*"; }
phase() { printf '\n========== %s ==========\n' "$*"; }

# pass/fail on an exit code
check_rc() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d (rc=$?)"; fi; }
# pass when $2 (a string) contains needle $3
check_has() { if printf '%s' "$2" | grep -qF -- "$3"; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

# Reliable nft set element count — newer nft emits compact single-line JSON, so `grep -c elem`
# is WRONG (counts lines = 1). Parse the JSON.
nft_count() { # family table set -> count, or -1 if absent/unparseable
  nft -j list set "$1" "$2" "$3" 2>/dev/null | "$PYBIN" -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(-1); sys.exit()
n=-1
for o in d.get("nftables",[]):
    s=o.get("set")
    if s is not None: n=len(s.get("elem",[]))
print(n)'
}
# Last desired_count the reconciler audited for a set (the authoritative reconciled size).
audit_desired() { # setname -> desired_count or -1
  "$PYBIN" -c '
import json,sys
want=sys.argv[1]; val=-1
try: lines=open("/var/log/edge-reconciler/audit.jsonl")
except Exception: print(-1); sys.exit()
for line in lines:
    line=line.strip()
    if not line: continue
    try: r=json.loads(line)
    except Exception: continue
    if r.get("set")==want and "desired_count" in r: val=r["desired_count"]
print(val)' "$1"
}
unit_enabled() { systemctl is-enabled "$1" 2>/dev/null | grep -qx enabled; }
unit_active()  { systemctl is-active  "$1" 2>/dev/null | grep -qx active; }

cd "$REPO" || { echo "REPO not found: $REPO" >&2; exit 2; }

# ---------------------------------------------------------------------------
phase "0 — preflight"
[ "$(id -u)" -eq 0 ] && pass "running as root" || fail "must run as root"
check_rc "nft present" command -v nft
check_rc "bastion package importable" $BASTION --help
# Edge-mode detection needs a 2nd phys NIC with carrier; bring the LAN iface up first.
ip addr add "$LAN_IP/${LAN_CIDR##*/}" dev "$LAN_IFACE" 2>/dev/null
ip link set "$LAN_IFACE" up 2>/dev/null
ip -br addr show "$LAN_IFACE" | grep -q UP && pass "$LAN_IFACE up ($LAN_IP)" || note "$LAN_IFACE not up — edge detection may misfire"

# ---------------------------------------------------------------------------
phase "1 — setup (non-interactive, writes machine.conf + machine.env)"
# The v1.0.3 --set flags make setup scriptable: no console prompt-feeding needed.
set_layers="${LAYERS// /,}"
$BASTION setup --profile full-edge --no-ai \
  --set "layers=$set_layers" \
  --set "lan_iface=$LAN_IFACE" --set "wan_iface=$WAN_IFACE" \
  --set "lan_cidr=$LAN_CIDR" --set "lan_ip=$LAN_IP" --set "gateway=$GATEWAY" </dev/null
rc=$?
[ $rc -eq 0 ] && pass "bastion setup completed" || fail "bastion setup (rc=$rc)"
check_rc "machine.conf written" test -r /etc/bastion/machine.conf
check_rc "machine.env written"  test -r /etc/bastion/machine.env
env_txt="$(cat /etc/bastion/machine.env 2>/dev/null)"
check_has "machine.env MODE=edge"            "$env_txt" "MODE=edge"
check_has "machine.env NFT_TABLE=inet edge"  "$env_txt" "NFT_TABLE=inet edge"
# Secrets/keys must never land in machine.conf.
if grep -qiE 'sk-ant|api[_-]?key' /etc/bastion/machine.conf 2>/dev/null; then
  fail "no secret leaked into machine.conf"; else pass "no secret in machine.conf"; fi

# ---------------------------------------------------------------------------
phase "2 — L0 core (drop-policy base + kill switch + persistence)"
$BASTION layer install l0 </dev/null; rc=$?
[ $rc -eq 0 ] && pass "layer install l0" || fail "layer install l0 (rc=$rc)"
check_rc "table $FAM $TABLE loaded" nft list table $FAM $TABLE
# Commandment: bastion-recovery always installed in L0, and DISABLED by default (kill switch present,
# not armed). An armed rescue path at install time would itself be the hole.
check_rc "bastion-recovery script installed" test -x /usr/local/sbin/bastion-recovery
if unit_enabled bastion-recovery; then fail "bastion-recovery must be DISABLED by default"; else pass "bastion-recovery present + disabled"; fi
# Dogfood reboot bug (Key #19): nftables.service must be enabled or the ruleset doesn't survive reboot.
if unit_enabled nftables; then pass "nftables.service enabled (reboot persistence)"; else fail "nftables.service NOT enabled — ruleset won't persist"; fi

# ---------------------------------------------------------------------------
phase "3 — L1 feeds + the reconciler (sole nft writer)"
if printf '%s' "$LAYERS" | grep -qw l1; then
  $BASTION layer install l1 </dev/null && pass "layer install l1" || fail "layer install l1"
  check_rc "edge-reconciler.timer enabled" unit_enabled edge-reconciler.timer
  check_rc "edge-feed.timer enabled"       unit_enabled edge-feed.timer
  # Pull the feed then reconcile — the operational path with ZERO unit-test coverage.
  note "fetching threat feed (network) ..."
  systemctl start edge-feed.service 2>/dev/null
  /usr/local/sbin/edge-reconciler >/tmp/reconcile.out 2>&1 && pass "edge-reconciler pass (rc0)" || fail "edge-reconciler pass"
  check_rc "blk_feed set present" nft list set $FAM $TABLE blk_feed
  live=$(nft_count $FAM $TABLE blk_feed); want=$(audit_desired blk_feed)
  if [ "$live" -ge 0 ] && [ "$live" = "$want" ]; then
    pass "blk_feed reconciled: nft count ($live) == audit desired_count ($want)"
  else
    fail "blk_feed count mismatch: nft=$live audit=$want"
  fi
  [ "$live" -gt 0 ] && pass "blk_feed non-empty ($live elements)" || note "blk_feed empty — feed fetch may have no network"
  # --dry-run must compute + audit but NOT change the live set.
  before=$(nft_count $FAM $TABLE blk_feed)
  /usr/local/sbin/edge-reconciler --dry-run >/dev/null 2>&1
  after=$(nft_count $FAM $TABLE blk_feed)
  [ "$before" = "$after" ] && pass "reconciler --dry-run does not mutate nft" || fail "--dry-run mutated blk_feed ($before -> $after)"
else
  note "L1 not in LAYERS — skipping feed/reconciler checks"
fi

# ---------------------------------------------------------------------------
phase "4 — L3 AI layer (opt-in disabled; mock-backend pipeline)"
if printf '%s' "$LAYERS" | grep -qw l3; then
  $BASTION layer install l3 </dev/null && pass "layer install l3" || fail "layer install l3"
  for s in ai_block ai_ratelimit ai_tarpit; do check_rc "$s set present" nft list set $FAM $TABLE $s; done
  check_rc "edge-ctl installed" test -x /usr/local/sbin/edge-ctl
  # L3 is opt-in: the analysis timer must be installed but DISABLED until `bastion ai enable`.
  if unit_enabled edge-ai.timer; then fail "edge-ai.timer must be DISABLED until ai enable"; else pass "edge-ai.timer present + disabled (opt-in)"; fi
  # Exercise the full sanitize->analyze->reconcile pipeline with the MOCK backend (no API, no key).
  note "running mock AI pipeline (collect -> analyze -> reconcile) ..."
  /usr/local/sbin/edge-ai-collect >/tmp/collect.out 2>&1 && pass "edge-ai-collect (root sanitizer) rc0" || note "edge-ai-collect rc!=0 (may need cscli/journal)"
  check_rc "sanitized signals.json written" test -r /var/lib/edge-ai/signals.json
  if [ -r /var/lib/edge-ai/signals.json ]; then
    # Sanitization boundary: no RFC1918 / loopback addresses may reach the backend.
    if grep -qE '(^|[^0-9])(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' /var/lib/edge-ai/signals.json; then
      fail "signals.json leaked a private/loopback address"; else pass "signals.json carries no private addresses"; fi
  fi
  BACKEND_CMD=/usr/local/sbin/edge-ai-backend-mock runuser -u edge-ai -- /usr/local/sbin/edge-ai-analyze >/tmp/analyze.out 2>&1 \
    && pass "edge-ai-analyze (mock backend, unprivileged) rc0" || note "edge-ai-analyze rc!=0 (check /tmp/analyze.out)"
  check_rc "intents.json produced" test -r /var/lib/edge-ai/intents.json
  # Kill switch: edge-ctl ai-disable must flush the ai_* sets and exit 0.
  check_rc "edge-ctl ai-disable (kill switch) rc0" /usr/local/sbin/edge-ctl ai-disable
else
  note "L3 not in LAYERS — skipping AI-layer checks"
fi

# ---------------------------------------------------------------------------
phase "5 — L6 monitoring + the self-heal operational scripts"
if printf '%s' "$LAYERS" | grep -qw l6; then
  $BASTION layer install l6 </dev/null && pass "layer install l6" || fail "layer install l6"
  check_rc "edge-watchdog.service active" unit_active edge-watchdog.service
  check_rc "edge-watchdog.service enabled" unit_enabled edge-watchdog.service
  for s in net-snapshot net-rollback flowcheck lan-verify net-confirm; do
    check_rc "$s installed" test -x /usr/local/sbin/$s
  done

  # net-snapshot -> net-rollback round-trip (idempotent gentle restore must be a safe no-op).
  /usr/local/sbin/net-snapshot >/tmp/snap.out 2>&1 && pass "net-snapshot rc0" || fail "net-snapshot"
  check_rc "canonical snapshot written" test -f /var/lib/net-safe/snapshot/taken-at
  /usr/local/sbin/net-rollback integration-test >/tmp/rollback.out 2>&1 && pass "net-rollback (no-op restore) rc0" || fail "net-rollback"
  check_rc "table $FAM $TABLE still loaded after rollback" nft list table $FAM $TABLE

  # edge-watchdog single evaluation in DRYRUN — must report, and (no real outage) NOT roll back / churn.
  DRYRUN=1 timeout 30 /usr/local/sbin/edge-watchdog once >/tmp/watchdog.out 2>&1
  rc=$?; [ $rc -eq 0 ] && pass "edge-watchdog once (dry) rc0" || note "edge-watchdog once rc=$rc (see /tmp/watchdog.out)"
  if grep -qiE 'roll.?back|net-rollback' /tmp/watchdog.out; then
    fail "watchdog tried to roll back a healthy node (churn)"; else pass "watchdog did not churn on a healthy node"; fi

  # flowcheck — informational: egress probe to api.anthropic.com may fail behind slirp, so don't hard-fail.
  /usr/local/sbin/flowcheck >/tmp/flowcheck.out 2>&1; rc=$?
  note "flowcheck rc=$rc (output in /tmp/flowcheck.out)"
  if grep -qiE 'FAIL.*(relay|wireguard|local.?dns).*endpoint' /tmp/flowcheck.out; then
    fail "flowcheck ran edge-only probes in a way that false-fails"; else pass "flowcheck mode-gating sane"; fi
else
  note "L6 not in LAYERS — skipping monitoring/self-heal checks"
fi

# ---------------------------------------------------------------------------
phase "6 — whole-node verification (verify / doctor / check)"
$BASTION verify </dev/null && pass "bastion verify: no config drift" || fail "bastion verify reported drift"
$BASTION doctor </dev/null && pass "bastion doctor: no FAILs" || fail "bastion doctor found a FAIL"
$BASTION check  </dev/null; note "bastion check rc=$? (read-only health wrapper)"

# ---------------------------------------------------------------------------
phase "summary"
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "INTEGRATION: GREEN"; exit 0; } || { echo "INTEGRATION: RED"; exit 1; }
