"""Package-manager abstraction for the installer (§10 step 7, §14 Phase 5).

Phase 5 targets pacman + apt (the founding document's stated scope); the base class makes a
third manager (dnf) a trivial add later. Every install is idempotent — the underlying commands
(`pacman -S --needed`, `apt-get install`) are safe to re-run, satisfying Commandment #4.

Nothing here runs during a dry-run: `install()` returns the command it WOULD run and executes
only when `dry_run=False` and the system is live. Package-name differences across distros are a
known follow-up (the gate is a clean Arch VM); `translate()` is the per-manager hook for it and
defaults to identity today.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..system import System


@dataclass
class InstallResult:
    command: list[str]          # the argv that was (or would be) run
    ran: bool                   # False in dry-run / non-live
    returncode: int | None      # None when not run
    missing: list[str]          # packages that were not already present
    unavailable: list[str] = field(default_factory=list)  # missing AND not resolvable by this
                                # manager (e.g. AUR-only on Arch) — never handed to the installer


class PackageManager:
    """Base class. Subclasses set `name` and the query/install argv builders."""
    name = "auto"

    def translate(self, pkg: str) -> str:
        """Map a generic package name to this distro's name. Identity by default."""
        return pkg

    # --- to be overridden ---
    def _query_argv(self, pkg: str) -> list[str]:
        raise NotImplementedError

    def _available_argv(self, pkg: str) -> list[str]:
        """argv that returns 0 iff the manager can resolve `pkg` from its repos."""
        raise NotImplementedError

    def _install_argv(self, pkgs: list[str]) -> list[str]:
        raise NotImplementedError

    def unavailable_hint(self, pkgs: list[str]) -> str:
        """Operator instruction for packages this manager cannot resolve. Overridden per distro."""
        return (f"not available via {self.name}: {', '.join(pkgs)} — install these manually, "
                "then re-run.")

    # --- shared behaviour ---
    def is_installed(self, sys: System, pkg: str) -> bool:
        return sys.run(*self._query_argv(self.translate(pkg))).returncode == 0

    def is_available(self, sys: System, pkg: str) -> bool:
        """True if the manager can install `pkg` from its repos right now (db assumed synced)."""
        return sys.run(*self._available_argv(self.translate(pkg))).returncode == 0

    def missing(self, sys: System, pkgs) -> list[str]:
        """Subset of pkgs not already installed (preserves order, de-duplicates)."""
        seen, out = set(), []
        for p in pkgs:
            if p not in seen:
                seen.add(p)
                if not self.is_installed(sys, p):
                    out.append(p)
        return out

    def install_command(self, pkgs) -> list[str]:
        return self._install_argv([self.translate(p) for p in pkgs])

    def install(self, sys: System, pkgs, *, dry_run: bool = False) -> InstallResult:
        """Install only the missing packages. No-op (ran=False) in dry-run or when not live.

        Live installs first split off packages the manager cannot resolve (e.g. crowdsec, which
        is AUR-only on Arch): handing an unresolvable name to `pacman -S` fails the WHOLE
        transaction, so those are returned in `unavailable` for an operator instruction instead.
        bastion never builds AUR packages itself (Commandment #5 — narrowest scope)."""
        missing = self.missing(sys, pkgs)
        if not missing:
            return InstallResult(command=[], ran=False, returncode=0, missing=[])
        if dry_run or not sys.is_live:
            cmd = self._install_argv([self.translate(p) for p in missing])
            return InstallResult(command=cmd, ran=False, returncode=None, missing=missing)
        unavailable = [p for p in missing if not self.is_available(sys, p)]
        available = [p for p in missing if p not in unavailable]
        cmd = self._install_argv([self.translate(p) for p in available]) if available else []
        rc = sys.run(*cmd, capture=False).returncode if available else None
        return InstallResult(command=cmd, ran=bool(available), returncode=rc,
                             missing=missing, unavailable=unavailable)


class Pacman(PackageManager):
    name = "pacman"

    def _query_argv(self, pkg: str) -> list[str]:
        return ["pacman", "-Q", pkg]

    def _available_argv(self, pkg: str) -> list[str]:
        return ["pacman", "-Si", pkg]          # 0 iff pkg is in a sync repo (not AUR)

    def _install_argv(self, pkgs: list[str]) -> list[str]:
        return ["pacman", "-S", "--needed", "--noconfirm", *pkgs]

    def unavailable_hint(self, pkgs: list[str]) -> str:
        joined = " ".join(pkgs)
        return ("not in the official Arch repositories — these are AUR packages: "
                f"{', '.join(pkgs)}. Install with an AUR helper "
                f"(e.g. `paru -S {joined}`) or makepkg, then re-run. "
                "bastion does not build AUR packages itself.")


class Apt(PackageManager):
    name = "apt"

    def _query_argv(self, pkg: str) -> list[str]:
        return ["dpkg", "-s", pkg]

    def _available_argv(self, pkg: str) -> list[str]:
        return ["apt-cache", "show", pkg]      # 0 iff pkg is a known apt target

    def _install_argv(self, pkgs: list[str]) -> list[str]:
        return ["apt-get", "install", "-y", *pkgs]


_MANAGERS: dict[str, type[PackageManager]] = {"pacman": Pacman, "apt": Apt}

# Package managers bastion can DETECT but does not yet drive. When one of these is the only
# manager present (e.g. Fedora/RHEL-family ships dnf), the installer surfaces a clear
# "not yet supported" message instead of a generic "no package manager found" — so the
# operator knows their distro is recognized, just unimplemented. Adding a manager = move it
# into _MANAGERS with a PackageManager subclass.
UNSUPPORTED_BINARIES: tuple[tuple[str, str], ...] = (
    ("dnf", "Fedora/RHEL-family (dnf)"),
)


def unsupported_present(sys: System) -> str | None:
    """Label of a known-but-unimplemented package manager present on this system, else None.

    Lets the installer distinguish "your distro's manager isn't supported yet" (actionable)
    from "no recognizable package manager at all"."""
    for binary, label in UNSUPPORTED_BINARIES:
        if sys.command_exists(binary):
            return label
    return None


def get_manager(name: str) -> PackageManager:
    """Return a PackageManager by name. Falls back to pacman-binary / apt-binary detection
    only via `detect_manager`; an unknown explicit name raises (surfaces a bad machine.conf)."""
    cls = _MANAGERS.get(name)
    if cls is None:
        raise ValueError(f"unsupported package manager: {name!r} (have: {', '.join(_MANAGERS)})")
    return cls()


def detect_manager(sys: System, name: str | None = None) -> PackageManager | None:
    """Resolve the package manager: an explicit/known name, else probe for a binary on PATH.
    Returns None if nothing is recognized (caller decides how to warn)."""
    if name and name in _MANAGERS:
        return _MANAGERS[name]()
    for binary, mgr in (("pacman", "pacman"), ("apt-get", "apt")):
        if sys.command_exists(binary):
            return _MANAGERS[mgr]()
    return None
