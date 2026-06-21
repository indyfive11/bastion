"""Regression tests for CLI-surface findings surfaced by the VPS dogfood (C1: --version, C2: mode)."""
from pathlib import Path

import pytest

from bastion import cli, __version__
from bastion.layers.base import Context
from bastion.system import System


def test_version_flag_prints_and_exits_zero(capsys):
    # C1: `bastion --version` (and -V) print the version and exit 0 — previously argparse errored
    # with "the following arguments are required: command".
    for flag in ("--version", "-V"):
        with pytest.raises(SystemExit) as exc:
            cli.main([flag])
        assert exc.value.code == 0
        assert __version__ in capsys.readouterr().out


def _ctx(config):
    return Context(system=System(root=Path("/")), config=config,
                   templates_dir=Path("."), scripts_dir=Path("."))


def test_mode_unset_when_no_machine_conf():
    # C2: with no machine.conf loaded (config has no [machine]), mode is "unset" — not a misleading
    # default of "edge" that status/doctor would otherwise print on a fresh box.
    assert _ctx({}).mode == "unset"


def test_mode_reflects_machine_conf_when_present():
    assert _ctx({"machine": {"mode": "endpoint"}}).mode == "endpoint"
    assert _ctx({"machine": {"mode": "edge"}}).mode == "edge"
