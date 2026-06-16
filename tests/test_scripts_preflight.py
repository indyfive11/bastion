"""B4 — shared missing-binary `need <bin>` preflight in the operational shell scripts.

Each guarded script names any missing required command up front (rc 1) instead of failing
obscurely mid-run. Hermetic: every script runs with a PATH that deliberately OMITS the target
binary (a temp dir of symlinks to the common tools minus the omitted ones), so the preflight
fires before the script touches the network/firewall. No machine.env, no root, no mutation.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"

# Tools the guarded preamble + need() may legitimately use; we symlink the present ones into the
# sandbox PATH, then drop whatever a given case wants "missing".
_BASE_TOOLS = ("bash", "sh", "mktemp", "rm", "logger", "sed", "awk", "grep",
               "cat", "tr", "sort", "printf", "env")


def _restricted_path(tmp_path: Path, omit: set[str]) -> str:
    binp = tmp_path / "bin"
    binp.mkdir(exist_ok=True)
    for tool in _BASE_TOOLS:
        if tool in omit:
            continue
        src = shutil.which(tool)
        if src:
            link = binp / tool
            if not link.exists():
                link.symlink_to(src)
    return str(binp)


def _run(script: str, path: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/bash", str(SCRIPTS / script), *args],
                          env={"PATH": path}, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=20)


# (script, args, the binary we strip, the name we expect the preflight to report)
CASES = [
    ("flowcheck", (), "curl", "curl"),
    ("net-confirm", (), "curl", "curl"),
    ("edge-feed-fetch", (), "curl", "curl"),
    ("edge-dnsblock-update", (), "curl", "curl"),
    ("edge-watchdog", ("once",), "curl", "curl"),
]


@pytest.mark.parametrize("script,args,strip,expect", CASES)
def test_preflight_names_missing_binary(tmp_path, script, args, strip, expect):
    # `strip` is omitted from PATH AND from the sandbox (curl etc. aren't in _BASE_TOOLS, so a
    # restricted PATH never has them) — the preflight must catch it and name it, exiting non-zero.
    path = _restricted_path(tmp_path, omit={strip})
    r = _run(script, path, *args)
    assert r.returncode == 1, f"{script} should exit 1 when {strip} is missing (got {r.returncode})"
    assert "missing required command(s):" in r.stderr
    assert expect in r.stderr


def test_preflight_passes_when_binaries_present(tmp_path):
    # Sanity: with the real PATH (curl present here), flowcheck's preflight does NOT trip — it
    # gets past `need` into the actual checks (which may pass or fail, but never the preflight).
    if not shutil.which("curl"):
        pytest.skip("curl not installed on this host")
    r = subprocess.run(["/bin/bash", str(SCRIPTS / "flowcheck")],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=40)
    assert "missing required command(s):" not in r.stderr
