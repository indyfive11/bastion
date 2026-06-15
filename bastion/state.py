"""bastion state — machine.conf / secrets.conf read+write and machine.env rendering.

Key invariants (founding document §3 #8, §8):
  * machine.conf (topology/layers) and secrets.conf (API keys) are read by SEPARATE
    functions and never merged. The template config dict NEVER contains secrets.
  * secrets.conf is written chmod 600 and is never rendered into any committed output.
  * `bastion generate` renders machine.env — a flat, shell-sourceable file the operational
    scripts read — from machine.conf only.
"""
from __future__ import annotations

import configparser
import os
from pathlib import Path

# Standard search order for a real machine.conf (system install, then user install).
DEFAULT_CONF_PATHS = (
    Path("/etc/bastion/machine.conf"),
    Path.home() / ".config/bastion/machine.conf",
)


def _parser() -> configparser.ConfigParser:
    # interpolation=None: values may contain '%' or '$' literally (paths, URLs).
    # inline_comment_prefixes left at default (None): a value may contain '#'
    # (e.g. dns_upstream = 127.0.0.1#5335). Comments must be on their own lines.
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str  # preserve key case as written (keys are lowercase by convention)
    return cp


def load_conf(path: str | Path) -> dict[str, dict[str, str]]:
    """Load an INI file into a nested ``{section: {key: value}}`` dict.

    Used for machine.conf. Does NOT read secrets — secrets live in their own file and are
    loaded only by :func:`load_secrets`.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"config not found: {path}")
    cp = _parser()
    cp.read(path)
    return {section: dict(cp.items(section)) for section in cp.sections()}


def find_conf(explicit: str | Path | None = None) -> Path:
    """Resolve which machine.conf to use: explicit arg, else the default search order."""
    if explicit:
        return Path(explicit)
    for candidate in DEFAULT_CONF_PATHS:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "no machine.conf found (looked in: "
        + ", ".join(str(p) for p in DEFAULT_CONF_PATHS)
        + "); pass --conf or run `bastion setup`"
    )


def write_conf(config: dict[str, dict[str, str]], path: str | Path) -> None:
    """Write a nested dict back to an INI file at ``path``, atomically.

    Render to a temp file in the same directory then ``os.replace()`` — a crash or
    interruption mid-write can never leave a truncated/corrupt machine.conf on disk
    (the live file is either the old contents or the complete new contents).
    """
    cp = _parser()
    for section, items in config.items():
        cp[section] = {k: str(v) for k, v in items.items()}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        with tmp.open("w") as fh:
            cp.write(fh)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def load_secrets(path: str | Path) -> dict[str, str]:
    """Load secrets.conf [secrets] section. Kept entirely separate from machine.conf."""
    path = Path(path)
    if not path.is_file():
        return {}
    cp = _parser()
    cp.read(path)
    return dict(cp.items("secrets")) if cp.has_section("secrets") else {}


def write_secrets(secrets: dict[str, str], path: str | Path) -> None:
    """Write secrets.conf chmod 600, atomically. Never rendered into any template output.

    The temp file is created 0600 from the start, so the secret never touches disk
    world-readable; ``os.replace()`` then swaps it into place (the destination inherits
    the temp file's 0600 mode), so a crash mid-write can't leave a partial or
    wrongly-permissioned secrets file.
    """
    cp = _parser()
    cp["secrets"] = {k: str(v) for k, v in secrets.items()}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            cp.write(fh)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


# --- machine.env rendering -------------------------------------------------
#
# (env_var, section, key) mapping for the flat shell file the operational scripts source.
# Scripts carry generic fallbacks, so a blank value here is fine.
ENV_MAP: tuple[tuple[str, str, str], ...] = (
    ("LAN_IF", "interfaces", "lan"),
    ("WAN_IF", "interfaces", "wan"),
    ("ZT_IF", "interfaces", "zt_iface"),
    ("RELAY_IF", "interfaces", "wg_vps_iface"),
    ("WG_SERVER_IF", "interfaces", "wg_server_iface"),
    ("LAN_NET", "network", "lan_cidr"),
    ("LAN_IP", "network", "lan_ip"),
    ("GATEWAY", "network", "gateway"),
    ("DNS_UPSTREAM", "network", "dns_upstream"),
    ("RELAY_DST", "monitoring", "relay_dst"),
    ("NM_CONN", "monitoring", "nm_conn"),
    ("EGRESS_PROBE", "monitoring", "egress_probe"),
    ("DNSBLOCK_SOURCES", "monitoring", "dnsblock_sources"),
    ("RECOVERY_DEDICATED_PORT", "recovery", "dedicated_port"),
    ("RECOVERY_WINDOW_SECONDS", "recovery", "window_seconds"),
    ("RECOVERY_TRY_PORT_22", "recovery", "try_port_22"),
)


def _shell_quote(value: str) -> str:
    """Single-quote a value for safe shell sourcing."""
    return "'" + value.replace("'", "'\\''") + "'"


def render_machine_env(config: dict[str, dict[str, str]]) -> str:
    """Render the flat, shell-sourceable machine.env from a machine.conf dict.

    Missing keys render as empty (the scripts fall back). LAN_IP_CIDR is derived from
    lan_ip + the prefix length of lan_cidr.
    """
    lines = [
        "# bastion machine.env — generated by `bastion generate`. DO NOT EDIT.",
        "# Sourced by the operational shell scripts (edge-watchdog, lan-verify, etc.).",
    ]
    for env_var, section, key in ENV_MAP:
        value = config.get(section, {}).get(key, "")
        lines.append(f"{env_var}={_shell_quote(value)}")

    # Derived: LAN_IP_CIDR = lan_ip/<prefix-of-lan_cidr>
    lan_ip = config.get("network", {}).get("lan_ip", "")
    lan_cidr = config.get("network", {}).get("lan_cidr", "")
    lan_ip_cidr = ""
    if lan_ip and "/" in lan_cidr:
        lan_ip_cidr = f"{lan_ip}/{lan_cidr.split('/', 1)[1]}"
    lines.append(f"LAN_IP_CIDR={_shell_quote(lan_ip_cidr)}")

    # Derived: NFT_TABLE — the base table the reconciler writes managed sets into.
    # edge template defines `table inet edge`; endpoint defines `table inet bastion`.
    mode = config.get("machine", {}).get("mode", "edge")
    nft_table = "inet bastion" if mode == "endpoint" else "inet edge"
    lines.append(f"NFT_TABLE={_shell_quote(nft_table)}")

    # Mode signal — flowcheck (and other scripts) gate edge-only flows (relay tunnel, WG server,
    # local DNS chain) on this, so an endpoint never false-fails checks for subsystems it lacks
    # even if its conf still carries leftover edge values.
    lines.append(f"MODE={_shell_quote(mode)}")

    return "\n".join(lines) + "\n"
