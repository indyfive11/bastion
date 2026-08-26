"""notify-alert delivery-failure + unreadable-conf reporting (H19).

Driven via the project's bash-script-test idiom: a whole-script copy with CONF redirected into the
tmp tree and the external commands (logger/curl/mail) redefined as shell functions injected right
after `set -u`. The logger stub appends to $LOGFILE so we can assert on the on-box journal record.

Two findings under test:
  * F1 — a sink whose delivery FAILED (curl/mail nonzero) must leave a distinct on-box journal
    record `SINK <label> FAILED rc=N`, while the script still exits 0 (a notifier hiccup must never
    cascade). The success case must NOT emit a failure line.
  * F2 — a conf that EXISTS but is UNREADABLE (mode 000 to a non-root caller — how popper-boot.sh
    invokes it) must emit a loud journal line, distinct from the silent "no conf at all" no-op.
"""
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "notify-alert"

# logger -> a file we can read; curl/mail -> a caller-chosen rc. `command -v logger|mail` finds
# these because a shell function is resolvable by `command -v`.
_STUBS = (
    'logger(){ printf "%s\\n" "$*" >> "$LOGFILE"; }\n'
    'curl(){ return "${CURL_RC:-0}"; }\n'
    'mail(){ return "${MAIL_RC:-0}"; }\n'
)


def _script_copy(tmp_path: Path, conf: Path) -> Path:
    src = SCRIPT.read_text()
    assert "CONF=/etc/bastion/notify-alert.conf" in src, "CONF anchor moved"
    src = src.replace("CONF=/etc/bastion/notify-alert.conf", f"CONF={conf}", 1)
    src = src.replace("set -u\n", "set -u\n" + _STUBS, 1)
    dst = tmp_path / "notify-alert"
    dst.write_text(src)
    return dst


def _run(script: Path, logfile: Path, env_extra=None):
    env = dict(os.environ, LOGFILE=str(logfile))
    if env_extra:
        env.update(env_extra)
    logfile.touch()
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)


def test_f1_ntfy_delivery_failure_is_recorded_and_exit0(tmp_path):
    conf = tmp_path / "conf"
    conf.write_text("NTFY_TOPIC=testtopic\n")
    proc = _run(_script_copy(tmp_path, conf), tmp_path / "log", {"CURL_RC": "6"})
    assert proc.returncode == 0, proc.stderr          # never cascade
    assert "SINK ntfy FAILED rc=6" in (tmp_path / "log").read_text()


def test_f1_ntfy_success_leaves_no_failure_line(tmp_path):
    conf = tmp_path / "conf"
    conf.write_text("NTFY_TOPIC=testtopic\n")
    proc = _run(_script_copy(tmp_path, conf), tmp_path / "log", {"CURL_RC": "0"})
    assert proc.returncode == 0, proc.stderr
    assert "FAILED" not in (tmp_path / "log").read_text()


def test_f1_internal_ntfy_delivery_failure_is_recorded(tmp_path):
    conf = tmp_path / "conf"
    conf.write_text("INTERNAL_NTFY_URL=http://internal.example.test/topic\n")
    proc = _run(_script_copy(tmp_path, conf), tmp_path / "log", {"CURL_RC": "7"})
    assert proc.returncode == 0, proc.stderr
    assert "SINK internal-ntfy FAILED rc=7" in (tmp_path / "log").read_text()


def test_f1_mail_delivery_failure_is_recorded(tmp_path):
    conf = tmp_path / "conf"
    conf.write_text("ALERT_EMAIL=ops@example.test\n")
    proc = _run(_script_copy(tmp_path, conf), tmp_path / "log", {"MAIL_RC": "1"})
    assert proc.returncode == 0, proc.stderr
    assert "SINK mail FAILED rc=1" in (tmp_path / "log").read_text()


def test_f2_unreadable_conf_emits_loud_line(tmp_path):
    # root bypasses the read bit, so `-r` stays true and the branch never fires — the case is only
    # observable as a non-root caller (which is exactly popper-boot.sh's situation).
    if os.geteuid() == 0:
        pytest.skip("F2 unreadable branch requires non-root (root bypasses the read bit)")
    conf = tmp_path / "conf"
    conf.write_text("NTFY_TOPIC=x\n")
    conf.chmod(0o000)
    proc = _run(_script_copy(tmp_path, conf), tmp_path / "log")
    out = (tmp_path / "log").read_text()
    assert proc.returncode == 0, proc.stderr
    assert "exists but is unreadable" in out          # F2 loud line present
    assert "SINK ntfy" not in out                     # conf never sourced -> sink stayed unset


def test_f2_absent_conf_stays_a_silent_noop(tmp_path):
    conf = tmp_path / "conf"                           # deliberately never created
    proc = _run(_script_copy(tmp_path, conf), tmp_path / "log")
    assert proc.returncode == 0, proc.stderr
    assert "unreadable" not in (tmp_path / "log").read_text()
