"""Failover-lockout hardening (the 2026-06-21 class). Three watchdog invariants, driven via the
project's bash-script-test idiom (sed the function out, source it in a child bash with externals
redefined as shell functions):

  * desired-state: a DOWN relay/tunnel interface is NOT "our config broken" — config_ok must stay
    intact so the dead tunnel never triggers a heal/rollback it can't fix.
  * cooldown: heal_allowed enforces a hard floor between heals so a heal that didn't fix the cause
    can't thrash.

(heal_light's no-flush invariant is guarded separately in test_edge_watchdog_heal.py.)
"""
import os
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-watchdog"


def _func(name: str) -> str:
    out = subprocess.run(["sed", "-n", f"/^{name}()/,/^}}/p", str(SCRIPT)],
                         capture_output=True, text=True, check=True).stdout
    assert f"{name}()" in out, f"could not extract {name} from edge-watchdog"
    return out


def _vars_block(machine_env: Path) -> str:
    # Extract the F16 cache->source->restore preamble (the `_OV_*` lines through the MODE= line)
    # and point its hardcoded source at our temp machine.env so the precedence can be exercised
    # off-host.
    block = subprocess.run(["sed", "-n", "/^_OV_WAN_IF=/,/^MODE=/p", str(SCRIPT)],
                           capture_output=True, text=True, check=True).stdout
    assert "_OV_MODE" in block and "MODE=" in block, "could not extract F16 vars preamble"
    return block.replace("/etc/bastion/machine.env", str(machine_env))


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


def test_operator_env_override_wins_over_machine_env(tmp_path):
    # F16: a deliberate operator/test override (MODE=edge RELAY_IF=…) must survive the machine.env
    # source. machine.env says endpoint/empty-relay; the operator overrides MODE+RELAY_IF on the
    # command line and leaves WAN_IF to machine.env. After the preamble the overrides must WIN and
    # the un-overridden var must still take its machine.env value.
    env_file = tmp_path / "machine.env"
    env_file.write_text("MODE='endpoint'\nRELAY_IF=''\nWAN_IF='enp0'\n")
    driver = "set -u\n" + _vars_block(env_file) + '\necho "MODE=$MODE RELAY_IF=$RELAY_IF WAN_IF=$WAN_IF"\n'
    r = subprocess.run(["bash", "-c", driver],
                       env={**os.environ, "MODE": "edge", "RELAY_IF": "wg_test"},
                       capture_output=True, text=True, check=True)
    assert "MODE=edge" in r.stdout          # override beats machine.env's endpoint (the test seam works)
    assert "RELAY_IF=wg_test" in r.stdout   # ditto, even though machine.env set it empty
    assert "WAN_IF=enp0" in r.stdout        # no override -> machine.env value still used


def test_machine_env_used_when_no_operator_override(tmp_path):
    # No operator override -> the machine.env values must be honored (no regression: the preamble
    # must not force defaults over a sourced value).
    env_file = tmp_path / "machine.env"
    env_file.write_text("MODE='endpoint'\nRELAY_IF='wg_vps'\n")
    driver = "set -u\n" + _vars_block(env_file) + '\necho "MODE=$MODE RELAY_IF=$RELAY_IF"\n'
    clean = {k: v for k, v in os.environ.items() if k not in ("MODE", "RELAY_IF")}
    r = subprocess.run(["bash", "-c", driver], env=clean, capture_output=True, text=True, check=True)
    assert "MODE=endpoint" in r.stdout      # sourced value wins when no override present
    assert "RELAY_IF=wg_vps" in r.stdout
