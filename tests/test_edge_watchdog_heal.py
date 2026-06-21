"""0.2 — edge-watchdog heal_light invariants. It is a bash function, so we extract it (per the
project's script-test idiom: sed the function out, source it in a child bash with external commands
redefined as shell functions) and drive it with a stubbed nft/systemctl, asserting on what it pipes
to `nft -f -`.

Two invariants are guarded here:
  * NO FLUSH IN A HOT PATH — when bastion's table is PRESENT, heal_light must NOT reload $NFT_CONF
    (whose preamble flushes live NAT/conntrack); it only refills the reconciler-managed sets.
  * RECREATE WHEN GONE — when the table is MISSING it reloads from the static config, and must fold
    the live recovery table into the same transaction so the reload can't strand emergency SSH.
"""
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-watchdog"


def _run_heal(tmp_path, *, table_present: bool, recovery_active: bool):
    out = tmp_path / "out"
    out.mkdir()
    nft_conf = tmp_path / "nftables.conf"
    nft_conf.write_text("flush ruleset\ntable inet edge { chain c { } }\n# MARKER_STATIC\n")
    recovery_run = tmp_path / "bastion-recovery"
    if recovery_active:
        recovery_run.mkdir()
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "fw-nftables-active").write_text("")   # we govern via nftables (reload path eligible)

    # Pull just the heal_light function out of the real script.
    func = subprocess.run(["sed", "-n", "/^heal_light()/,/^}/p", str(SCRIPT)],
                          capture_output=True, text=True, check=True).stdout
    assert "heal_light()" in func

    table_rc = 0 if table_present else 1
    driver = textwrap.dedent(f"""
        set -u
        OUT="{out}"
        NFT_CONF="{nft_conf}"
        RECOVERY_RUN="{recovery_run}"
        SNAP="{snap}"
        log(){{ echo "$*" >> "$OUT/log"; }}
        # nft stub: -f reads stdin (record it); -s dumps a fake recovery table; `list table inet edge`
        # → the presence probe (rc {table_rc}); anything else → ok.
        nft(){{
          if [ "${{1:-}}" = "-f" ]; then cat > "$OUT/nft-stdin"; return 0; fi
          if [ "${{1:-}}" = "-s" ]; then
            echo "table inet bastion_recovery {{"
            echo "  chain input {{ type filter hook input priority -50; policy accept; tcp dport {{ 2222 }} accept }}"
            echo "}}"
            return 0
          fi
          if [ "${{1:-}}" = "list" ]; then return {table_rc}; fi
          return 0
        }}
        systemctl(){{ echo "$*" >> "$OUT/systemctl"; return 0; }}
    """) + func + "\nheal_light\n"

    subprocess.run(["bash", "-c", driver], check=True)
    stdin = (out / "nft-stdin").read_text() if (out / "nft-stdin").exists() else ""
    sysctl = (out / "systemctl").read_text() if (out / "systemctl").exists() else ""
    log = (out / "log").read_text() if (out / "log").exists() else ""
    return stdin, sysctl, log


def test_heal_light_present_table_refills_without_flushing(tmp_path):
    # Table is LIVE → must NOT reload the static ruleset (no `nft -f -` at all), only refill via the
    # reconciler. This is the anti-flush invariant: a present table's NAT/conntrack must survive a heal.
    stdin, sysctl, log = _run_heal(tmp_path, table_present=True, recovery_active=False)
    assert stdin == ""                                    # no reload => no flush of live state
    assert "start edge-reconciler.service" in sysctl       # sets refilled instead
    assert "no flush" in log


def test_heal_light_missing_table_recreates_from_static(tmp_path):
    # Table is GONE → recreate from the static config (the preamble flush is moot — nothing live to
    # drop). It reloads via `nft -f -` carrying the static ruleset and kicks the reconciler.
    stdin, sysctl, _log = _run_heal(tmp_path, table_present=False, recovery_active=False)
    assert "MARKER_STATIC" in stdin
    assert "start edge-reconciler.service" in sysctl
    assert "bastion_recovery" not in stdin                 # no recovery active → nothing to fold in


def test_heal_light_missing_table_preserves_active_recovery(tmp_path):
    # Table GONE + a recovery window open → the live recovery table is folded into the SAME
    # transaction so the recreate can't sever emergency SSH.
    stdin, _sysctl, _log = _run_heal(tmp_path, table_present=False, recovery_active=True)
    assert "MARKER_STATIC" in stdin
    assert "table inet bastion_recovery" in stdin
