"""Failover-lockout hardening (the 2026-06-21 class). Three watchdog invariants, driven via the
project's bash-script-test idiom (sed the function out, source it in a child bash with externals
redefined as shell functions):

  * desired-state: a DOWN relay/tunnel interface is NOT "our config broken" — config_ok must stay
    intact so the dead tunnel never triggers a heal/rollback it can't fix.
  * cooldown: heal_allowed enforces a hard floor between heals so a heal that didn't fix the cause
    can't thrash.

(heal_light's no-flush invariant is guarded separately in test_edge_watchdog_heal.py.)
"""
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-watchdog"


def _func(name: str) -> str:
    out = subprocess.run(["sed", "-n", f"/^{name}()/,/^}}/p", str(SCRIPT)],
                         capture_output=True, text=True, check=True).stdout
    assert f"{name}()" in out, f"could not extract {name} from edge-watchdog"
    return out


def test_config_ok_intact_when_only_relay_iface_is_down(tmp_path):
    # The relay/tunnel iface is DOWN (far-end VPS gone) but the edge table + relay masq + default
    # route are all present. config_ok must report INTACT (rc 0) — a dead tunnel is upstream, not a
    # local config fault, so it must not drive the self-heal path (the lockout root cause).
    run = tmp_path / "run"
    driver = textwrap.dedent(f"""
        set -u
        RUN="{run}"; mkdir -p "$RUN"
        RELAY_IF="wg_vps"; LAN_NET="192.168.1.0/24"
        systemctl(){{ return 0; }}
        iptables(){{ return 0; }}
        nft(){{
          case "$*" in
            "list table inet edge") return 0 ;;                         # table present -> fw=edge
            "list table ip edge_nat") echo 'ip saddr 192.168.1.0/24 oifname "wg_vps" masquerade'; return 0 ;;
            *) return 0 ;;
          esac
        }}
        ip(){{
          case "$1 $2" in
            "link show")  return 1 ;;                                   # RELAY_IF iface is DOWN
            "route show") echo "default via 1.2.3.4 dev wan" ;;
            *) return 0 ;;
          esac
        }}
    """) + _func("config_ok") + '\nif config_ok; then echo "RESULT=intact"; else echo "RESULT=broken:$(config_ok)"; fi\n'
    r = subprocess.run(["bash", "-c", driver], capture_output=True, text=True, check=True)
    assert "RESULT=intact" in r.stdout
    assert "relay-iface-down" not in r.stdout


def test_heal_allowed_enforces_cooldown(tmp_path):
    # A fresh node (no prior heal) may heal; immediately after a heal it is within the cooldown and
    # must be blocked — this is the anti-thrash floor that stops a dead-upstream heal loop.
    run = tmp_path / "run"
    driver = textwrap.dedent(f"""
        set -u
        RUN="{run}"; mkdir -p "$RUN"
        HEAL_COOLDOWN=900
    """) + _func("heal_allowed") + _func("mark_healed") + textwrap.dedent("""
        heal_allowed && echo "fresh=allowed" || echo "fresh=blocked"
        mark_healed
        heal_allowed && echo "after=allowed" || echo "after=blocked"
    """)
    r = subprocess.run(["bash", "-c", driver], capture_output=True, text=True, check=True)
    assert "fresh=allowed" in r.stdout      # no prior heal -> permitted
    assert "after=blocked" in r.stdout      # just healed -> within cooldown -> refused
