"""System-access helpers, isolated so layers are testable.

`root` prefixes all path checks (default "/"); tests point it at a temp dir to simulate a
fresh or partially-installed system. Live queries (systemd, nft) hit the real host and fail
soft (return False) when unprivileged or unavailable, so read-only `bastion status` never
crashes for a non-root user.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class System:
    root: Path = Path("/")
    dry_run: bool = False

    @property
    def is_live(self) -> bool:
        """True only when operating on the real root (not a staged tree) and not dry-run.
        Live system mutations (systemctl, nft -f) must be gated on this."""
        return self.root == Path("/") and not self.dry_run

    def path(self, p: str) -> Path:
        return self.root / str(p).lstrip("/")

    def exists(self, p: str) -> bool:
        return self.path(p).exists()

    def read(self, p: str) -> str:
        return self.path(p).read_text()

    def command_exists(self, name: str) -> bool:
        return shutil.which(name) is not None

    def run(self, *args: str, capture: bool = True,
            input: str | None = None) -> subprocess.CompletedProcess:
        """Run a command. In dry_run, mutating callers should guard; this still executes
        read-only queries. ``input`` feeds stdin (e.g. `wg pubkey` reads a key from stdin).
        Never raises on non-zero — callers inspect returncode."""
        try:
            return subprocess.run(list(args), text=True, capture_output=capture, input=input)
        except FileNotFoundError:
            return subprocess.CompletedProcess(args, 127, "", "command not found")

    # --- live, read-only queries (fail soft) ---
    def unit_active(self, unit: str) -> bool:
        return self.run("systemctl", "is-active", "--quiet", unit).returncode == 0

    def unit_enabled(self, unit: str) -> bool:
        return self.run("systemctl", "is-enabled", "--quiet", unit).returncode == 0

    def nft_table_exists(self, family: str, table: str) -> bool:
        return self.run("nft", "list", "table", family, table).returncode == 0

    def nft_set_exists(self, family: str, table: str, name: str) -> bool:
        return self.run("nft", "list", "set", family, table, name).returncode == 0
