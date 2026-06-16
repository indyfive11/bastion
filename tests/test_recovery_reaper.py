"""0.1 — bastion-recovery boot reaper. The self-destruct timer + ExecStop tear down the rescue
surface on a clean stop, but an unclean reboot mid-window leaves the rescue user + NOPASSWD
sudoers orphaned (the tmpfs runtime dir is gone, the on-disk surface is not). do_reap detects
exactly that and tears it down. Driven via the project's bash script-test idiom (extract the
function, source it in a child bash, redefine externals as shell functions).
"""
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "bastion-recovery"


def _run_reap(tmp_path, *, run_dir_present: bool, user_exists: bool):
    out = tmp_path / "out"
    out.mkdir()
    run_dir = tmp_path / "run-bastion-recovery"
    if run_dir_present:
        run_dir.mkdir()

    func = subprocess.run(["sed", "-n", "/^do_reap()/,/^}/p", str(SCRIPT)],
                          capture_output=True, text=True, check=True).stdout
    assert "do_reap()" in func

    driver = textwrap.dedent(f"""
        set -u
        OUT="{out}"
        RUN="{run_dir}"
        RECOVERY_USER=bastion-rescue
        log(){{ echo "$*" >> "$OUT/log"; }}
        # do_stop is the teardown; record that (and how) it was called instead of running it.
        do_stop(){{ echo "do_stop $*" >> "$OUT/teardown"; }}
        # `id -u` → root (0); `id <user>` → exists per the scenario.
        id(){{ if [ "${{1:-}}" = "-u" ]; then echo 0; return 0; fi; return {0 if user_exists else 1}; }}
    """) + func + "\ndo_reap\n"

    subprocess.run(["bash", "-c", driver], check=True)
    teardown = (out / "teardown").read_text() if (out / "teardown").exists() else ""
    return teardown


def test_reaps_orphan_when_user_exists_but_runtime_gone(tmp_path):
    # unclean-reboot signature: runtime dir absent, rescue user still on disk → tear down.
    teardown = _run_reap(tmp_path, run_dir_present=False, user_exists=True)
    assert "do_stop quiet" in teardown


def test_noop_on_clean_boot(tmp_path):
    # nothing orphaned (no runtime dir, no rescue user, no sudoers) → do nothing.
    teardown = _run_reap(tmp_path, run_dir_present=False, user_exists=False)
    assert teardown == ""


def test_noop_while_recovery_active(tmp_path):
    # runtime dir present = recovery legitimately running → never tear it down.
    teardown = _run_reap(tmp_path, run_dir_present=True, user_exists=True)
    assert teardown == ""


def test_script_dispatches_reap_subcommand():
    body = SCRIPT.read_text()
    assert "reap)   do_reap ;;" in body
    assert "{start|stop|extend|status|reap}" in body
