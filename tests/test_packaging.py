"""Guard the wheel's package-data spec.

The operational scripts and config templates ship INSIDE the wheel as package-data so an installed
`bastion` resolves them package-relative. A per-subdirectory glob list silently dropped
`templates/logrotate/*` (extensionless files in a subdir the spec never named), so every packaged
install failed at `layer install l1`/`l3` (install_logrotate) from v1.1.0 until it was caught
dogfooding the 1.5.1 package on a real host. This asserts the spec covers EVERY shipped file, so a
new template subdir can never be omitted again.
"""
import glob
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "bastion"


def _package_data_patterns() -> list[str]:
    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    return data["tool"]["setuptools"]["package-data"]["bastion"]


def test_package_data_covers_every_shipped_file():
    patterns = _package_data_patterns()
    matched: set[Path] = set()
    for pat in patterns:
        for rel in glob.glob(pat, root_dir=PKG, recursive=True):
            p = (PKG / rel)
            if p.is_file():
                matched.add(p.resolve())

    shipped: set[Path] = set()
    for sub in ("scripts", "templates"):
        for f in (PKG / sub).rglob("*"):
            # Skip Python bytecode caches — dev artifacts (tests load edge-ctl via SourceFileLoader),
            # not shipped source. Everything else under scripts/ + templates/ must be in the wheel.
            if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc":
                shipped.add(f.resolve())

    missing = sorted(str(m.relative_to(PKG)) for m in (shipped - matched))
    assert not missing, f"package-data omits shipped files: {missing}"


def test_logrotate_templates_are_covered():
    # The specific files whose omission broke packaged l1/l3 installs — pinned explicitly.
    patterns = _package_data_patterns()
    for name in ("templates/logrotate/edge-reconciler", "templates/logrotate/edge-ai"):
        assert (PKG / name).is_file(), f"fixture missing: {name}"
        assert any(glob.fnmatch.fnmatch(name, pat) or name in
                   glob.glob(pat, root_dir=PKG, recursive=True) for pat in patterns), \
            f"{name} not covered by package-data {patterns}"
