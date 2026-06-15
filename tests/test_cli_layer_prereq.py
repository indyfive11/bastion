"""`bastion layer install/uninstall` enforces the declared layer dependency graph.

cli._prerequisite_block reads each Layer.prerequisites so that:
  - install of a layer whose prerequisites are not installed is refused, and
  - uninstall of a layer that a still-installed layer depends on is refused
    (the case that matters most: `uninstall l0` while L1-L6 remain would delete the base nft
    table, bastion-recovery, and the kill switch out from under them).
`--force` bypasses the check.
"""
from types import SimpleNamespace

from bastion import cli


def _layer(name, prerequisites, installed):
    return SimpleNamespace(
        name=name,
        prerequisites=prerequisites,
        status=lambda ctx: SimpleNamespace(installed=installed),
    )


def _wire(monkeypatch, layers):
    registry = {l.name: l for l in layers}
    monkeypatch.setattr(cli.layermod, "get", lambda n: registry.get(n))
    monkeypatch.setattr(cli.layermod, "all_layers", lambda: list(registry.values()))


def test_install_blocked_when_prerequisite_missing(monkeypatch):
    l0 = _layer("l0", (), installed=False)
    l1 = _layer("l1", ("l0",), installed=False)
    _wire(monkeypatch, [l0, l1])
    reason = cli._prerequisite_block(None, l1, "install")
    assert reason and "l0" in reason


def test_install_ok_when_prerequisite_present(monkeypatch):
    l0 = _layer("l0", (), installed=True)
    l1 = _layer("l1", ("l0",), installed=False)
    _wire(monkeypatch, [l0, l1])
    assert cli._prerequisite_block(None, l1, "install") is None


def test_uninstall_blocked_when_dependent_still_installed(monkeypatch):
    l0 = _layer("l0", (), installed=True)
    l1 = _layer("l1", ("l0",), installed=True)
    _wire(monkeypatch, [l0, l1])
    reason = cli._prerequisite_block(None, l0, "uninstall")
    assert reason and "l1" in reason


def test_uninstall_ok_in_reverse_order(monkeypatch):
    # l1 already gone => uninstalling l0 is allowed.
    l0 = _layer("l0", (), installed=True)
    l1 = _layer("l1", ("l0",), installed=False)
    _wire(monkeypatch, [l0, l1])
    assert cli._prerequisite_block(None, l0, "uninstall") is None


def test_force_flag_bypasses_check(monkeypatch, tmp_path):
    # cmd_layer must not even consult _prerequisite_block when --force is set.
    called = {"checked": False}

    def _boom(*a, **k):
        called["checked"] = True
        return "should not be consulted"

    monkeypatch.setattr(cli, "_prerequisite_block", _boom)

    l0 = SimpleNamespace(name="l0", prerequisites=(),
                         install=lambda ctx: None, uninstall=lambda ctx: None,
                         packages=())
    monkeypatch.setattr(cli.layermod, "get", lambda n: l0 if n == "l0" else None)
    monkeypatch.setattr(cli, "_install_layer_packages", lambda ctx, layer: None)

    rc = cli.main(["layer", "uninstall", "l0", "--force", "--root", str(tmp_path)])
    assert rc == 0
    assert called["checked"] is False
