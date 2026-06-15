"""Package-manager abstraction (Phase 5 / pkg.py).

A fake System records the argv passed to run() and returns scripted return codes, so install
idempotency + dry-run safety are checked without touching a real package database.
"""
import subprocess

from bastion.setup import pkg
from bastion.system import System


class FakeSystem(System):
    def __init__(self, installed: set, *, live: bool = True, have=("pacman",), available=None):
        super().__init__()
        self._installed = installed       # packages dpkg/pacman report present
        self._live = live
        self._have = set(have)
        # packages the manager can resolve from its repos. None = everything resolvable (the
        # common case); a set models AUR-only packages (e.g. crowdsec) being absent from it.
        self._available = available
        self.calls: list[tuple] = []

    @property
    def is_live(self):
        return self._live

    def command_exists(self, name):
        return name in self._have

    def run(self, *args, capture=True):
        self.calls.append(args)
        # query forms: ("pacman","-Q",pkg) / ("dpkg","-s",pkg)
        if args[:2] in (("pacman", "-Q"), ("dpkg", "-s")):
            return subprocess.CompletedProcess(args, 0 if args[2] in self._installed else 1, "", "")
        # availability forms: ("pacman","-Si",pkg) / ("apt-cache","show",pkg)
        if args[:2] in (("pacman", "-Si"), ("apt-cache", "show")):
            ok = self._available is None or args[2] in self._available
            return subprocess.CompletedProcess(args, 0 if ok else 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def test_detect_manager_by_binary():
    assert pkg.detect_manager(FakeSystem(set(), have=("pacman",))).name == "pacman"
    assert pkg.detect_manager(FakeSystem(set(), have=("apt-get",))).name == "apt"
    assert pkg.detect_manager(FakeSystem(set(), have=())) is None


def test_detect_manager_explicit_name_wins():
    # apt named explicitly even though only pacman binary is present.
    assert pkg.detect_manager(FakeSystem(set(), have=("pacman",)), "apt").name == "apt"


def test_unsupported_present_names_dnf():
    # Fedora-style box: dnf is the only manager → no supported manager, but it's recognized
    # as detected-but-unimplemented (clean message), not "no package manager at all".
    fedora = FakeSystem(set(), have=("dnf",))
    assert pkg.detect_manager(fedora) is None
    assert pkg.unsupported_present(fedora) == "Fedora/RHEL-family (dnf)"
    # A supported box returns None (nothing unsupported to flag).
    assert pkg.unsupported_present(FakeSystem(set(), have=("pacman",))) is None


def test_get_manager_unknown_raises():
    try:
        pkg.get_manager("nix")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_pacman_install_argv_and_missing():
    m = pkg.Pacman()
    sys = FakeSystem({"nftables"})            # nftables already present, curl is not
    assert m.missing(sys, ["nftables", "curl", "curl"]) == ["curl"]   # de-dup + filter
    assert m.install_command(["nftables", "curl"]) == \
        ["pacman", "-S", "--needed", "--noconfirm", "nftables", "curl"]


def test_apt_query_and_install_argv():
    m = pkg.Apt()
    assert m._query_argv("curl") == ["dpkg", "-s", "curl"]
    assert m._install_argv(["curl", "unbound"]) == ["apt-get", "install", "-y", "curl", "unbound"]


def test_install_only_missing_when_live():
    m = pkg.Pacman()
    sys = FakeSystem({"nftables"}, live=True)
    res = m.install(sys, ["nftables", "curl"])
    assert res.ran and res.returncode == 0
    assert res.missing == ["curl"]
    # The install argv installs ONLY the missing package, not the already-present one.
    assert ("pacman", "-S", "--needed", "--noconfirm", "curl") in sys.calls
    assert not any(c[:4] == ("pacman", "-S", "--needed", "--noconfirm") and "nftables" in c
                   for c in sys.calls)


def test_install_noop_when_all_present():
    m = pkg.Pacman()
    sys = FakeSystem({"nftables", "curl"})
    res = m.install(sys, ["nftables", "curl"])
    assert not res.ran and res.missing == [] and res.command == []


def test_install_dry_run_does_not_execute():
    m = pkg.Pacman()
    sys = FakeSystem({"nftables"}, live=True)
    res = m.install(sys, ["nftables", "curl"], dry_run=True)
    assert not res.ran and res.returncode is None
    assert res.command == ["pacman", "-S", "--needed", "--noconfirm", "curl"]
    # No install argv was ever handed to run() — only the read-only query.
    assert all(c[:2] != ("pacman", "-S") for c in sys.calls)


def test_install_noop_when_not_live():
    m = pkg.Pacman()
    sys = FakeSystem({"nftables"}, live=False)
    res = m.install(sys, ["nftables", "curl"])
    assert not res.ran and res.command == ["pacman", "-S", "--needed", "--noconfirm", "curl"]


def test_install_separates_aur_unavailable_live():
    # crowdsec is missing AND not resolvable by pacman (AUR-only); nftables is missing but available.
    m = pkg.Pacman()
    sys = FakeSystem(set(), live=True, available={"nftables"})
    res = m.install(sys, ["nftables", "crowdsec"])
    assert res.unavailable == ["crowdsec"]
    assert res.ran and res.returncode == 0
    # ONLY the resolvable package is handed to pacman -S; crowdsec never is (would fail the txn).
    assert ("pacman", "-S", "--needed", "--noconfirm", "nftables") in sys.calls
    assert not any(c[:2] == ("pacman", "-S") and "crowdsec" in c for c in sys.calls)


def test_install_all_unavailable_runs_nothing():
    m = pkg.Pacman()
    sys = FakeSystem(set(), live=True, available=set())   # nothing resolvable
    res = m.install(sys, ["crowdsec"])
    assert res.unavailable == ["crowdsec"]
    assert not res.ran and res.returncode is None and res.command == []
    assert not any(c[:2] == ("pacman", "-S") for c in sys.calls)


def test_pacman_unavailable_hint_points_at_aur():
    h = pkg.Pacman().unavailable_hint(["crowdsec"])
    assert "AUR" in h and "crowdsec" in h and "paru" in h


def test_apt_available_argv():
    assert pkg.Apt()._available_argv("crowdsec") == ["apt-cache", "show", "crowdsec"]
