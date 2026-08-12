"""M7 — bound the analyzer's read of the pluggable backend so a hung / compromised / local backend
cannot OOM the (unprivileged) analyzer by streaming unbounded output.

`edge-ai-analyze` used `subprocess.run(..., capture_output=True)`, which buffers the child's entire
stdout AND stderr into memory before any size can be checked; the 60s timeout is no help (a backend
can emit gigabytes in seconds). The fix reads stdout/stderr under a hard byte ceiling + an ABSOLUTE
deadline, with the signals FILE as the child's stdin (no stdin pipe -> no deadlock). These tests drive
`run_backend` with REAL subprocess backends (not mocks) so the concurrency/IO behaviour is exercised
for real. Loaded via the standard standalone-script idiom.
"""
import importlib.util
import json
import os
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-ai-analyze"


def _load():
    loader = SourceFileLoader("edge_ai_analyze_mod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("edge_ai_analyze_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


mod = _load()


def _backend(pycode):
    """A BACKEND_CMD (argv list) running the given python snippet."""
    return ["python3", "-c", pycode]


def _signals(tmp_path, payload=None):
    p = tmp_path / "signals.json"
    p.write_text(json.dumps(payload if payload is not None else {"observations": []}))
    return str(p)


def test_normal_output_passes_through(tmp_path):
    # A well-behaved backend under the cap returns unchanged.
    sig = _signals(tmp_path)
    code = 'import sys; sys.stdin.read(); sys.stdout.write(\'{"version":1,"intents":[]}\')'
    rc, out, err = mod.run_backend(_backend(code), sig, 10, dict(os.environ), 1 << 20)
    assert rc == 0
    assert json.loads(out) == {"version": 1, "intents": []}


def test_oversize_stdout_raises_before_oom(tmp_path):
    # 50 MiB of stdout, cap 1 MiB — must raise (never buffer it all), tagged 'out'.
    sig = _signals(tmp_path)
    code = 'import sys; sys.stdin.read(); sys.stdout.write("x"*50_000_000)'
    with pytest.raises(mod.BackendTooBig) as ei:
        mod.run_backend(_backend(code), sig, 15, dict(os.environ), 1 << 20)
    assert ei.value.stream == "out"


def test_oversize_stderr_bounded(tmp_path):
    # The OOM must not just relocate to stderr — stderr is capped too (MAX_STDERR_BYTES).
    sig = _signals(tmp_path)
    code = 'import sys; sys.stdin.read(); sys.stderr.write("e"*50_000_000)'
    with pytest.raises(mod.BackendTooBig) as ei:
        mod.run_backend(_backend(code), sig, 15, dict(os.environ), 1 << 20)
    assert ei.value.stream == "err"


def test_timeout_fires_fast(tmp_path):
    # A backend that hangs is cut at ~timeout, not at its own sleep.
    sig = _signals(tmp_path)
    code = 'import sys,time; sys.stdin.read(); time.sleep(30)'
    t0 = time.monotonic()
    with pytest.raises(mod.BackendTimeout):
        mod.run_backend(_backend(code), sig, 1, dict(os.environ), 1 << 20)
    assert time.monotonic() - t0 < 6      # cut near 1s, not 30s


def test_slow_drip_under_cap_still_times_out(tmp_path):
    # The absolute deadline must fire even though output dribbles forever UNDER the byte cap
    # (a per-iteration timeout that resets each byte would run forever).
    sig = _signals(tmp_path)
    code = ('import sys,time\n'
            'sys.stdin.read()\n'
            'while True:\n'
            '    sys.stdout.write("x"); sys.stdout.flush(); time.sleep(0.05)')
    t0 = time.monotonic()
    with pytest.raises(mod.BackendTimeout):
        mod.run_backend(_backend(code), sig, 1, dict(os.environ), 1 << 20)
    assert time.monotonic() - t0 < 6


def test_large_stdin_no_deadlock(tmp_path):
    # signals bigger than the pipe buffer + a backend that writes output BEFORE draining stdin —
    # the classic pipe deadlock, which file-backed stdin structurally avoids.
    big = {"observations": [{"ip": f"45.33.{i // 256}.{i % 256}", "n": i} for i in range(20000)]}
    sig = _signals(tmp_path, big)
    assert Path(sig).stat().st_size > 200_000     # comfortably past the ~64 KiB pipe buffer
    code = ('import sys\n'
            'sys.stdout.write(\'{"version":1,"intents":[]}\'); sys.stdout.flush()\n'
            'sys.stdin.read()')
    rc, out, err = mod.run_backend(_backend(code), sig, 10, dict(os.environ), 1 << 20)
    assert rc == 0 and json.loads(out)["version"] == 1


def test_forking_backend_is_group_killed(tmp_path):
    # A backend whose GRANDCHILD keeps streaming while the direct child sleeps — killpg must reap the
    # whole group, not just the direct child. Discriminator: the grandchild also touches a marker
    # file each iteration; after run_backend returns, the marker must STOP growing. A plain child-kill
    # (reaping only the sleeper) would leave the grandchild alive and the marker growing — so this
    # actually distinguishes the group kill (a timing-only assert would pass either way).
    sig = _signals(tmp_path)
    marker = tmp_path / "alive"
    # Direct child causes the stdout overflow; the grandchild touches ONLY the marker (never stdout,
    # so closing the pipe on __exit__ can't kill it — only a real killpg can). If _kill_group fell
    # back to a plain child-kill, the orphaned grandchild would keep growing the marker.
    code = ('import os,sys,time\n'
            'sys.stdin.read()\n'
            'if os.fork() == 0:\n'
            f'    f = open({str(marker)!r}, "w")\n'
            '    while True:\n'
            '        f.write("x"); f.flush(); time.sleep(0.005)\n'
            'else:\n'
            '    while True:\n'
            '        sys.stdout.write("y"*65536); sys.stdout.flush()')
    t0 = time.monotonic()
    with pytest.raises(mod.BackendTooBig):
        mod.run_backend(_backend(code), sig, 15, dict(os.environ), 1 << 20)
    assert time.monotonic() - t0 < 10          # returned promptly (group killed, not 30s parent)
    size1 = marker.stat().st_size if marker.exists() else 0
    time.sleep(0.5)
    size2 = marker.stat().st_size if marker.exists() else 0
    assert size1 == size2                       # grandchild stopped => the whole group was killed


def test_non_object_intents_dont_crash(tmp_path, monkeypatch):
    # A hostile backend returning non-object intent items (int/str/null) must be skipped, not crash
    # the analyzer with an uncaught AttributeError on the default (no-jsonschema) manual path.
    _wire_main(tmp_path, monkeypatch,
               "import sys,json\n"
               "sys.stdin.read()\n"
               "print(json.dumps({'version':1,'backend':'stub','intents':["
               "1, 'x', None, {'action':'block_src','cidr':'45.33.0.1/32','ttl':300}]}))\n")
    assert mod.main() == 0
    doc = json.loads((tmp_path / "intents.json").read_text())
    assert len(doc["intents"]) == 1            # the one valid dict applied; the junk items skipped


def test_bad_max_output_bytes_override_falls_back(tmp_path, monkeypatch):
    # A malformed MAX_OUTPUT_BYTES in backend.conf must degrade to the default, never survive as a
    # string that would crash the bounded read.
    conf = tmp_path / "backend.conf"
    conf.write_text("BACKEND_CMD=/bin/true\nMAX_OUTPUT_BYTES=not-a-number\n")
    monkeypatch.setattr(mod, "BACKENDCONF", str(conf))
    cfg = mod.load_conf()
    assert cfg["MAX_OUTPUT_BYTES"] == 1 << 20


def _wire_main(tmp_path, monkeypatch, backend_py, pre_intents=None):
    """Point the module's fixed paths at a temp sandbox + a stub backend, for a real main() run."""
    (tmp_path / "signals.json").write_text('{"observations":[]}')
    (tmp_path / "schema.json").write_text('{"type":"object"}')     # permissive: accept any envelope
    backend = tmp_path / "backend.py"
    backend.write_text(backend_py)
    (tmp_path / "backend.conf").write_text(f"BACKEND_CMD=python3 {backend}\n")
    intents = tmp_path / "intents.json"
    if pre_intents is not None:
        intents.write_text(pre_intents)
    for name, val in (("SIGNALS", "signals.json"), ("INTENTS", "intents.json"),
                      ("PROPOSALS", "proposals.jsonl"), ("SCHEMA", "schema.json"),
                      ("BACKENDCONF", "backend.conf")):
        monkeypatch.setattr(mod, name, str(tmp_path / val))
    return intents


def test_proposals_count_capped(tmp_path, monkeypatch, capsys):
    # A backend returning FAR more than MAX_TOTAL_INTENTS proposals must not write them all — the
    # applied-only MAX_INTENTS break does not bound the proposals path (M7 #3).
    n = mod.MAX_TOTAL_INTENTS + 200
    _wire_main(tmp_path, monkeypatch,
               "import sys,json\n"
               "sys.stdin.read()\n"
               f"docs=[{{'action':'propose_base_change','description':'d','reason':'r'}} "
               f"for _ in range({n})]\n"
               "print(json.dumps({'version':1,'backend':'stub','intents':docs}))\n")
    assert mod.main() == 0
    lines = (tmp_path / "proposals.jsonl").read_text().splitlines()
    assert len(lines) == mod.MAX_TOTAL_INTENTS      # capped, not n


def test_parse_failure_leaves_prior_intents(tmp_path, monkeypatch):
    # A hostile / malformed envelope (here: deeply-nested JSON that trips RecursionError, which is
    # NOT a JSONDecodeError) must die gracefully and leave the previous intents.json untouched — no
    # uncaught traceback, self-heal via TTL (M7 #4).
    sentinel = '{"version":1,"generated_epoch":0,"backend":"prev","intents":[]}'
    intents = _wire_main(tmp_path, monkeypatch,
                         "import sys\n"
                         "sys.stdin.read()\n"
                         "sys.stdout.write('['*60000 + ']'*60000)\n",   # valid but pathologically deep
                         pre_intents=sentinel)
    with pytest.raises(SystemExit):
        mod.main()
    assert intents.read_text() == sentinel          # prior spool untouched


def test_valid_max_output_bytes_override_honored(tmp_path, monkeypatch):
    conf = tmp_path / "backend.conf"
    conf.write_text("BACKEND_CMD=/bin/true\nMAX_OUTPUT_BYTES=4096\n")
    monkeypatch.setattr(mod, "BACKENDCONF", str(conf))
    cfg = mod.load_conf()
    assert cfg["MAX_OUTPUT_BYTES"] == 4096
    # and it actually bounds the read
    sig = _signals(tmp_path)
    code = 'import sys; sys.stdin.read(); sys.stdout.write("x"*100000)'
    with pytest.raises(mod.BackendTooBig):
        mod.run_backend(_backend(code), sig, 10, dict(os.environ), cfg["MAX_OUTPUT_BYTES"])
