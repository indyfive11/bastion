"""AI backend configuration for `bastion setup` (the AI key/provider step).

The L3 analysis layer is PROVIDER-AGNOSTIC: `edge-ai-analyze` shells out to a BACKEND_CMD
(stdin = sanitized signals JSON, stdout = intent-envelope JSON). The shipped Claude backend
(`edge-ai-backend-claude`) is just the default; a local model — or any executable honouring the
contract — works too, and `edge-ai-backend-mock` needs no network at all.

This module is the *setup-time* half. It (1) DETECTS an already-configured backend/key so a
reinstall reuses it without re-prompting (precedence: bastion's own config first, then the live
edge-ai files, then the environment), (2) backs the provider menu, and (3) writes the one secret a
key-bearing backend needs — into secrets.conf (chmod 600) and the edge-ai EnvironmentFile
(/etc/edge-ai/claude.env, chmod 600) — NEVER into machine.conf.

Hard boundary (narrowest scope): bastion never implements a provider's wire protocol. It only
points BACKEND_CMD at an executable and injects ONE secret as an env var. Everything here is
pure / IO-thin and driven through `System`, so it is fully testable with a fake System and an
injected environment — no host access, no network.
"""
from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path

from .. import state
from ..system import System

SBIN = "/usr/local/sbin"
EDGE_AI_ENV = "/etc/edge-ai/claude.env"          # EnvironmentFile loaded by edge-ai.service
EDGE_AI_BACKENDCONF = "/etc/edge-ai/backend.conf"
DEFAULT_SECRETS_FILE = "/etc/bastion/secrets.conf"


@dataclass(frozen=True)
class Provider:
    key: str                 # stable id
    label: str               # menu label
    backend_cmd: str | None  # None -> operator supplies a path (custom / local model)
    default_model: str       # "" when not applicable
    key_env: str | None      # env var the backend reads its secret from; None -> needs no key


PROVIDERS: tuple[Provider, ...] = (
    Provider("claude", "Claude (Anthropic API — needs an API key)",
             f"{SBIN}/edge-ai-backend-claude", "claude-opus-4-8", "ANTHROPIC_API_KEY"),
    Provider("custom", "Custom / local model (you provide BACKEND_CMD)",
             None, "", None),
    Provider("mock", "Mock (offline, deterministic — no key, no network)",
             f"{SBIN}/edge-ai-backend-mock", "", None),
)


def provider_by_label(label: str) -> Provider:
    for p in PROVIDERS:
        if p.label == label:
            return p
    return PROVIDERS[0]


def provider_for_cmd(backend_cmd: str | None) -> Provider | None:
    """Map an already-configured BACKEND_CMD back to a known provider (so a reinstall
    pre-selects it). An unrecognised command -> the 'custom' provider; nothing -> None."""
    if not backend_cmd:
        return None
    for p in PROVIDERS:
        if p.backend_cmd and p.backend_cmd == backend_cmd:
            return p
    return provider_by_label(PROVIDERS[1].label)   # custom


# --- detection (reinstall reuse: bastion config first) ---------------------

@dataclass
class BackendState:
    backend_cmd: str | None = None
    model: str | None = None
    key_present: bool = False
    key_source: str | None = None    # "secrets.conf" | EDGE_AI_ENV | "env:ANTHROPIC_API_KEY"
    key_env: str | None = None


def _read_optional(sys: System, path: str) -> str | None:
    return sys.read(path) if sys.exists(path) else None


def _ini_section(text: str | None, section: str) -> dict[str, str]:
    if not text:
        return {}
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str
    try:
        cp.read_string(text)
    except configparser.Error:
        return {}
    return dict(cp.items(section)) if cp.has_section(section) else {}


def _env_pairs(text: str | None) -> dict[str, str]:
    """Parse a KEY=value file (backend.conf / EnvironmentFile). Whole-line `#` comments only."""
    out: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def detect_backend(sys: System, *, env: dict | None = None) -> BackendState:
    """Discover an existing backend + key so a reinstall reuses it. Precedence
    ("bastion config first"): machine.conf [ai] + secrets.conf -> the live /etc/edge-ai files ->
    the environment. All reads go through `sys` (so --root staging and tests work); the
    environment defaults to ``os.environ`` but can be injected."""
    env = os.environ if env is None else env
    machine_conf = _read_optional(sys, "/etc/bastion/machine.conf")
    ai = _ini_section(machine_conf, "ai")
    secrets_file = _ini_section(machine_conf, "machine").get("secrets_file") or DEFAULT_SECRETS_FILE

    st = BackendState(backend_cmd=ai.get("backend_cmd") or None, model=ai.get("model") or None)

    # 1. bastion config first — secrets.conf
    secrets = _ini_section(_read_optional(sys, secrets_file), "secrets")
    for name in ("anthropic_api_key", "api_key"):
        if secrets.get(name):
            st.key_present, st.key_source, st.key_env = True, "secrets.conf", "ANTHROPIC_API_KEY"
            break

    # 2. the live edge-ai files (key in the EnvironmentFile; BACKEND_CMD/MODEL in backend.conf)
    if not st.key_present:
        envf = _env_pairs(_read_optional(sys, EDGE_AI_ENV))
        if envf.get("ANTHROPIC_API_KEY"):
            st.key_present, st.key_source, st.key_env = True, EDGE_AI_ENV, "ANTHROPIC_API_KEY"
    if st.backend_cmd is None:
        bc = _env_pairs(_read_optional(sys, EDGE_AI_BACKENDCONF))
        st.backend_cmd = bc.get("BACKEND_CMD") or st.backend_cmd
        st.model = st.model or (bc.get("MODEL") or None)

    # 3. environment (last)
    if not st.key_present and (env.get("ANTHROPIC_API_KEY") or "").strip():
        st.key_present, st.key_source, st.key_env = True, "env:ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"

    return st


# --- write the captured secret (live / staged) -----------------------------

def write_env_file(path: Path, variables: dict[str, str]) -> None:
    """Write a systemd EnvironmentFile (KEY=value) chmod 600 from creation. API keys carry no
    special characters, so plain KEY=value is correct (systemd reads it verbatim)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{k}={v}\n" for k, v in variables.items())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o600)


def apply_secret(sys: System, *, secrets_path: str, key_env: str, key_value: str) -> list[str]:
    """Persist the captured secret: merged into secrets.conf [secrets] (chmod 600) and rendered
    into the edge-ai EnvironmentFile (chmod 600). Both paths are root-prefixed via ``sys.path`` so
    --root staging stays contained. Returns the logical (un-rooted) paths written. NEVER touches
    machine.conf."""
    sp = sys.path(secrets_path)
    secrets = state.load_secrets(sp) if sp.is_file() else {}
    secrets[key_env.lower()] = key_value
    state.write_secrets(secrets, sp)

    write_env_file(sys.path(EDGE_AI_ENV), {key_env: key_value})
    return [secrets_path, EDGE_AI_ENV]
