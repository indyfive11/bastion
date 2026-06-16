"""0.4 — the shared advisory lock that serializes an edge-reconciler pass against the edge-ctl
kill switch (panic / ai-disable / rollback). Both standalone root scripts are loaded as modules
(top level is import-safe); they must resolve the SAME lock path and genuinely exclude each other.
"""
import fcntl
import importlib.util
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"


def _load(modname, filename, lockpath):
    # LOCK_FILE is read at import time from the env, so point both modules at the test path first.
    os.environ["BASTION_RECONCILE_LOCK"] = str(lockpath)
    loader = SourceFileLoader(modname, str(SCRIPTS / filename))
    spec = importlib.util.spec_from_loader(modname, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture
def both(tmp_path):
    lock = tmp_path / "reconcile.lock"
    rec = _load("edge_reconciler_lockmod", "edge-reconciler", lock)
    ctl = _load("edge_ctl_lockmod", "edge-ctl", lock)
    return rec, ctl, lock


def test_both_resolve_the_same_lock_path(both):
    rec, ctl, lock = both
    assert rec.LOCK_FILE == ctl.LOCK_FILE == str(lock)


def test_reconcile_lock_excludes_a_concurrent_holder(both):
    rec, _ctl, lock = both
    with rec.reconcile_lock():
        # while held, an independent open-file-description on the same path cannot take LOCK_EX
        fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
    # released on context exit → now acquirable
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # must not raise
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def test_kill_switch_lock_excludes_reconcile(both):
    # the edge-ctl side (panic/ai-disable/rollback) blocks a reconcile pass for the same file.
    rec, ctl, lock = both
    with ctl.kill_switch_lock():
        fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
