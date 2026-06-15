"""Minimal placeholder template engine for bastion. No Jinja2 dependency.

Resolves ``{{ section.key }}`` placeholders from a nested config dict (as produced by
:func:`bastion.state.load_conf`). Contract (founding document §8):

1. Resolve every ``{{ section.key }}`` from machine.conf values.
2. Raise an explicit error for any UNRESOLVED placeholder — never emit a silent empty
   value. (A *present but blank* value is considered resolved and renders as empty.)
3. Never read secrets.conf — secrets reach services via systemd EnvironmentFile, not
   templates. The engine only ever sees the dict it is handed; a ``{{ secrets.* }}``
   reference therefore fails as unresolved unless a secrets section is explicitly passed,
   which the CLI never does.
4. Support a check that validates all placeholders resolve without writing output.
"""
from __future__ import annotations

import re
from pathlib import Path

# section.key — both are identifier-like; whitespace inside the braces is tolerated.
PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\}\}")


class UnresolvedPlaceholderError(Exception):
    """Raised when a template references a placeholder absent from the config."""


def find_placeholders(text: str) -> set[tuple[str, str]]:
    """Return the set of ``(section, key)`` pairs referenced in ``text``."""
    return {(m.group(1), m.group(2)) for m in PLACEHOLDER_RE.finditer(text)}


def missing_placeholders(text: str, config: dict) -> list[str]:
    """Return a sorted list of ``"section.key"`` referenced but not present in ``config``.

    "Present" means the section exists and the key exists in it — even if its value is the
    empty string. Only genuinely absent keys are reported. Derived keys (see :func:`_derived`)
    count as present.
    """
    cfg = _derived(config)
    missing = []
    for section, key in find_placeholders(text):
        if key not in cfg.get(section, {}):
            missing.append(f"{section}.{key}")
    return sorted(set(missing))


def _derived(config: dict) -> dict:
    """Return a copy of ``config`` augmented with computed, template-only keys.

    These are never written back to machine.conf — they exist only at render/check time so a
    template can express something the raw config cannot. Currently:

    * ``network.trusted_hosts_elements`` — the nftables ``elements = { ... }`` line for the
      static ``trusted_hosts`` set, or ``""`` when no trusted hosts are configured. An empty
      ``elements = { }`` is an nftables *syntax error*, so when the list is blank the whole
      line must vanish, not render empty braces. (Blank ``trusted_hosts`` is a valid operator
      choice — the wizard offers "blank = none".)
    """
    net = config.get("network")
    if not net or "trusted_hosts" not in net:
        return config
    hosts = str(net.get("trusted_hosts") or "").strip().strip(",").strip()
    elements = f"elements = {{ {hosts} }}" if hosts else ""
    return {**config, "network": {**net, "trusted_hosts_elements": elements}}


def render(text: str, config: dict) -> str:
    """Resolve every placeholder in ``text``. Raise if any cannot be resolved.

    Collects ALL missing placeholders before raising, so the error lists everything wrong
    at once rather than failing one at a time.
    """
    cfg = _derived(config)
    missing = missing_placeholders(text, config)
    if missing:
        raise UnresolvedPlaceholderError("unresolved placeholders: " + ", ".join(missing))
    return PLACEHOLDER_RE.sub(lambda m: str(cfg[m.group(1)][m.group(2)]), text)


def render_file(src: Path, config: dict) -> str:
    """Render the template file at ``src`` and return the resolved text."""
    return render(Path(src).read_text(), config)


def check_file(src: Path, config: dict) -> list[str]:
    """Return the list of unresolved ``section.key`` for the template at ``src`` (no write)."""
    return missing_placeholders(Path(src).read_text(), config)
