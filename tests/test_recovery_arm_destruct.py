"""H3 (audit-F7) — the self-destruct arm must fail HONESTLY, not silently. `arm_destruct` now returns a
real rc; `do_start` keeps the live session but announces "NOT ARMED" instead of the old false
"auto-stop in Ns" promise (fail-OPEN per §15c — never deny a locked-out operator, but never lie about
an un-timed session); `do_extend` honors the rc the same way; and both transient units are cleared +
reset-failed before arming so a stale FAILED unit can't strand every future session un-timed. Preflight
adds systemctl/systemd-run (fail-CLOSED before any surface exists).

arm_destruct's rc contract is tested by extracting the real function (the project bash idiom); the
start/extend hand-off is asserted on the script text (per the false-green caution: stubbing the whole
do_start — useradd/chpasswd/nft/sshd/... — would test the stubs, not the logic).
"""
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "bastion-recovery"


def _run_arm(tmp_path, *, systemd_run_rc):
    out = tmp_path / "out"; out.mkdir()
    func = subprocess.run(["sed", "-n", "/^arm_destruct()/,/^}/p", str(SCRIPT)],
                          capture_output=True, text=True, check=True).stdout
    assert "arm_destruct()" in func
    driver = textwrap.dedent(f"""
        set -u
        DESTRUCT_UNIT=bastion-recovery-destruct
        WINDOW_SECONDS=1800
        OUT="{out}"
        log(){{ echo "$*" >> "$OUT/log"; }}
        systemctl(){{ echo "systemctl $*" >> "$OUT/systemctl"; return 0; }}
        systemd-run(){{ echo "systemd-run $*" >> "$OUT/systemdrun"; return {systemd_run_rc}; }}
    """) + func + '\narm_destruct; echo "rc=$?" > "$OUT/rc"\n'
    subprocess.run(["bash", "-c", driver], check=True)
    sc = (out / "systemctl").read_text() if (out / "systemctl").exists() else ""
    return (out / "rc").read_text().strip(), sc


# ---------- arm_destruct rc contract ----------

def test_arm_destruct_returns_failure_when_timer_cannot_arm(tmp_path):
    rc, _ = _run_arm(tmp_path, systemd_run_rc=1)
    assert rc == "rc=1"     # the failure now propagates to the caller instead of being swallowed


def test_arm_destruct_returns_success_when_armed(tmp_path):
    rc, _ = _run_arm(tmp_path, systemd_run_rc=0)
    assert rc == "rc=0"


def test_arm_destruct_clears_stale_units_before_arming(tmp_path):
    """Both .timer AND .service are stopped + reset-failed so a lingering FAILED unit can't block re-arm
    (which, once arm-failure is honored, would strand every session un-timed)."""
    _, sc = _run_arm(tmp_path, systemd_run_rc=0)
    assert "stop bastion-recovery-destruct.timer bastion-recovery-destruct.service" in sc
    assert "reset-failed bastion-recovery-destruct.timer bastion-recovery-destruct.service" in sc


# ---------- start / extend honor the rc (static structure — false-green-safe) ----------

def test_start_captures_arm_result_and_announces_honestly():
    body = SCRIPT.read_text()
    assert "local armed=1; arm_destruct || armed=0" in body          # rc captured, not swallowed
    assert 'if [ "$armed" = 1 ]; then' in body                       # auto-stop promise is conditional
    assert "NOT ARMED" in body                                       # honest branch exists
    # the auto-stop promise appears exactly once AND only inside the armed branch — semantic, not
    # whitespace-based, so an unconditional re-add at ANY indent is caught and reformatting won't false-fail.
    assert body.count("auto-stop in") == 1
    i_if = body.index('if [ "$armed" = 1 ]; then')
    i_else = body.index("else", i_if)
    assert i_if < body.index("auto-stop in") < i_else


def test_extend_honors_arm_result():
    body = SCRIPT.read_text()
    assert "if arm_destruct; then" in body                           # extend no longer ignores the rc
    # anchor to the extend function body so this can't be satisfied by do_start's UN-TIMED copy
    ext = body[body.index("do_extend()"):body.index("do_status()")]
    assert "UN-TIMED" in ext                                         # honest warning on re-arm failure


def test_preflight_requires_systemd():
    body = SCRIPT.read_text()
    assert "need sshd useradd chpasswd nft ss flock systemctl systemd-run" in body
