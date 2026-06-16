"""0.2 — edge-watchdog heal_light must NOT `flush ruleset` away the live recovery table or the
managed blocklist sets. It is a bash function, so we extract it (per the project's script-test
idiom: sed the function out, source it in a child bash with external commands redefined as shell
functions) and drive it with stubbed nft/systemctl, asserting on what it pipes to `nft -f -`.
"""
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-watchdog"


def _run_heal(tmp_path, *, recovery_active: bool):
    out = tmp_path / "out"
    out.mkdir()
    nft_conf = tmp_path / "nftables.conf"
    nft_conf.write_text("flush ruleset\ntable inet edge { chain c { } }\n# MARKER_STATIC\n")
    recovery_run = tmp_path / "bastion-recovery"
    if recovery_active:
        recovery_run.mkdir()

    # Pull just the heal_light function out of the real script.
    func = subprocess.run(["sed", "-n", "/^heal_light()/,/^}/p", str(SCRIPT)],
                          capture_output=True, text=True, check=True).stdout
    assert "heal_light()" in func

    driver = textwrap.dedent(f"""
        set -u
        OUT="{out}"
        NFT_CONF="{nft_conf}"
        RECOVERY_RUN="{recovery_run}"
        SNAP="{tmp_path}/snap"
        log(){{ echo "$*" >> "$OUT/log"; }}
        # nft stub: -f reads stdin (record it); -s dumps a fake recovery table; list-table → ok.
        nft(){{
          if [ "${{1:-}}" = "-f" ]; then cat > "$OUT/nft-stdin"; return 0; fi
          if [ "${{1:-}}" = "-s" ]; then
            echo "table inet bastion_recovery {{"
            echo "  chain input {{ type filter hook input priority -50; policy accept; tcp dport {{ 2222 }} accept }}"
            echo "}}"
            return 0
          fi
          return 0          # `nft list table inet edge` → success (enter the edge branch)
        }}
        systemctl(){{ echo "$*" >> "$OUT/systemctl"; return 0; }}
    """) + func + "\nheal_light\n"

    subprocess.run(["bash", "-c", driver], check=True)
    stdin = (out / "nft-stdin").read_text() if (out / "nft-stdin").exists() else ""
    sysctl = (out / "systemctl").read_text() if (out / "systemctl").exists() else ""
    return stdin, sysctl


def test_heal_light_reloads_statics_and_kicks_reconciler(tmp_path):
    stdin, sysctl = _run_heal(tmp_path, recovery_active=False)
    # It reloads via `nft -f -` (stdin), carrying the static ruleset — never a bare file reload
    # that would also strand the recovery table.
    assert "MARKER_STATIC" in stdin
    # managed sets are repopulated immediately, not left empty until the next timer tick.
    assert "start edge-reconciler.service" in sysctl
    # no recovery active → nothing to fold in.
    assert "bastion_recovery" not in stdin


def test_heal_light_preserves_active_recovery_table(tmp_path):
    stdin, _sysctl = _run_heal(tmp_path, recovery_active=True)
    # the live recovery table is folded into the SAME transaction so the flush can't sever it.
    assert "MARKER_STATIC" in stdin
    assert "table inet bastion_recovery" in stdin
