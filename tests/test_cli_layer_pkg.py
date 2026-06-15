"""`bastion layer install` auto-installs the layer's resolvable packages (Option 1).

A recording FakeSystem models pacman query/availability/install so the orchestration in
cli._install_layer_packages is checked without a real package database.
"""
import subprocess
from pathlib import Path
from types import SimpleNamespace

from bastion import cli
from bastion.layers.base import Context
from bastion.system import System

TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"


class FakeSystem(System):
    def __init__(self, installed: set, *, live=True, available=None, have=("pacman",)):
        super().__init__(root=Path("/") if live else Path("/staged"))
        self._installed = installed
        self._available = available           # None = all resolvable
        self._have = set(have)
        self.calls: list[tuple] = []

    @property
    def is_live(self):
        return self.root == Path("/")

    def command_exists(self, name):
        return name in self._have

    def run(self, *args, capture=True):
        self.calls.append(args)
        if args[:2] == ("pacman", "-Q"):
            return subprocess.CompletedProcess(args, 0 if args[2] in self._installed else 1, "", "")
        if args[:2] == ("pacman", "-Si"):
            ok = self._available is None or args[2] in self._available
            return subprocess.CompletedProcess(args, 0 if ok else 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def _ctx(sys_):
    return Context(system=sys_, config={"machine": {"distro": "pacman"}},
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def _layer(name, packages):
    return SimpleNamespace(name=name, packages=packages)


def _pacman_install_calls(sys_):
    return [c for c in sys_.calls if c[:2] == ("pacman", "-S")]


def test_resolvable_packages_installed_live(capsys):
    sys_ = FakeSystem(installed=set())                 # nothing installed yet
    cli._install_layer_packages(_ctx(sys_), _layer("l4", ("dnsmasq", "unbound")))
    out = capsys.readouterr().out
    assert "installed via pacman" in out and "[OK]" in out
    calls = _pacman_install_calls(sys_)
    assert calls and ("pacman", "-S", "--needed", "--noconfirm", "dnsmasq", "unbound") in calls


def test_already_present_is_noop(capsys):
    sys_ = FakeSystem(installed={"dnsmasq", "unbound"})
    cli._install_layer_packages(_ctx(sys_), _layer("l4", ("dnsmasq", "unbound")))
    assert "already present" in capsys.readouterr().out
    assert _pacman_install_calls(sys_) == []


def test_unavailable_aur_surfaced_not_installed(capsys):
    # crowdsec missing AND not resolvable; only resolvable deps get installed.
    sys_ = FakeSystem(installed=set(), available={"nftables", "curl"})
    cli._install_layer_packages(_ctx(sys_), _layer("l2", ("crowdsec",)))
    out = capsys.readouterr().out
    assert "AUR" in out and "crowdsec" in out
    assert not any("crowdsec" in c for c in _pacman_install_calls(sys_))


def test_no_packages_is_silent(capsys):
    sys_ = FakeSystem(installed=set())
    cli._install_layer_packages(_ctx(sys_), _layer("l5", ()))
    assert capsys.readouterr().out == ""
    assert sys_.calls == []


def test_staged_root_previews_without_installing(capsys):
    sys_ = FakeSystem(installed=set(), live=False)
    cli._install_layer_packages(_ctx(sys_), _layer("l4", ("dnsmasq", "unbound")))
    out = capsys.readouterr().out
    assert "would install" in out and "staged" in out
    assert _pacman_install_calls(sys_) == []        # nothing actually installed
