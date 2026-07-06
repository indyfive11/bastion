"""B4 — flowcheck conditional-tool checks emit SKIP (not a misleading FAIL) when a tool bastion does
not install itself is absent. wg (relay/WG-server checks) and ss (local-DNS listener) are optional on
a given box; without them the old code printed `FAIL relay handshake fresh` / `FAIL local DNS
listening`, reading as "broken" when the truth is "not installed / not checked".

Idiom: a whole-script copy with the machine.env source line REPLACED by stub functions (dropping the
source keeps the host's own /etc/bastion/machine.env — this box may be a live bastion node — from
forcing MODE/relay vars), plus a `command` builtin override that reports ONLY wg+ss as absent (so the
real host's ss/wg don't mask the SKIP path). Hermetic, no network, no root, no mutation.
"""
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "flowcheck"

# Injected right after flowcheck sources machine.env. curl/getent/systemctl are stubbed so `need curl`
# passes and the egress/DNS probes don't touch the network; wg/ss are reported absent via `command`.
_STUBS = (
    'command(){ if [ "$1" = -v ] && { [ "$2" = wg ] || [ "$2" = ss ]; }; then return 1; fi; '
    'builtin command "$@"; }\n'
    "curl(){ return 0; }\n"
    "getent(){ return 0; }\n"
    "systemctl(){ echo inactive; }\n"
)


_SOURCE_LINE = "[ -r /etc/bastion/machine.env ] && . /etc/bastion/machine.env\n"


def _runnable(tmp_path: Path) -> Path:
    src = SCRIPT.read_text().replace(_SOURCE_LINE, _STUBS, 1)
    dst = tmp_path / "flowcheck"
    dst.write_text(src)
    return dst


def test_missing_wg_and_ss_skip_not_fail(tmp_path):
    fc = _runnable(tmp_path)
    # edge mode with the relay/WG/LAN vars set so all three conditional checks are REACHED.
    env = {"PATH": "/usr/bin:/bin", "MODE": "edge", "RELAY_IF": "wg0",
           "WG_SERVER_IF": "wg1", "LAN_IP": "10.0.0.1"}
    r = subprocess.run(["/bin/bash", str(fc)], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=40)
    # wg absent -> both relay/WG checks SKIP naming wg; ss absent -> local-DNS check SKIPs naming ss.
    assert "SKIP  relay handshake fresh (<180s) — wg not installed" in r.stdout
    assert "SKIP  WireGuard server iface present — wg not installed" in r.stdout
    assert "SKIP  local DNS listening 10.0.0.1:53 — ss not installed" in r.stdout
    # and crucially NOT the old misleading FAILs for those same checks
    assert "FAIL  relay handshake fresh" not in r.stdout
    assert "FAIL  WireGuard server iface present" not in r.stdout
    assert "FAIL  local DNS listening" not in r.stdout


def test_present_tool_still_runs_the_check(tmp_path):
    # Control: when the tool IS present (no command override hiding it), ck_need delegates to ck and
    # the check runs — proving SKIP is gated on absence, not always-on. Use `ss` present + a LAN_IP
    # that won't be listening, so the check RUNS and reports (PASS or FAIL), never SKIP.
    import shutil
    if not shutil.which("ss"):
        import pytest
        pytest.skip("ss not installed on this host")
    # Only hide wg; leave ss visible so its check actually executes.
    stubs = (
        'command(){ if [ "$1" = -v ] && [ "$2" = wg ]; then return 1; fi; builtin command "$@"; }\n'
        "curl(){ return 0; }\ngetent(){ return 0; }\nsystemctl(){ echo inactive; }\n"
    )
    src = SCRIPT.read_text().replace(_SOURCE_LINE, stubs, 1)
    fc = tmp_path / "flowcheck"; fc.write_text(src)
    env = {"PATH": "/usr/bin:/bin", "MODE": "edge", "LAN_IP": "10.0.0.1"}
    r = subprocess.run(["/bin/bash", str(fc)], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=40)
    # ss present -> the local-DNS check runs (PASS/FAIL), it must NOT be skipped.
    assert "local DNS listening 10.0.0.1:53" in r.stdout
    assert "SKIP  local DNS listening" not in r.stdout
