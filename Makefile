.PHONY: leak-check test test-deps lint install-hook generate-check

# generate-check — Phase 2 gate: every template placeholder resolves against the example.
generate-check:
	@python -m bastion generate --check --conf bastion/machine.conf.example --templates bastion/templates

# leak-check — fail the build/commit if any committed file carries real values.
# This rule contains ONLY GENERIC STRUCTURAL secret patterns, so the Makefile itself leaks
# nothing (no hostnames, no real IPs):
#   * API keys (Anthropic key prefix + payload), PEM private-key headers
#   * base64 WireGuard keys (43 chars + '=')
#   * MAC addresses
# INSTALLATION-SPECIFIC identifiers (your hostnames, your real upstream IPs, emails, capability
# tokens, hardware UUIDs) live in a GITIGNORED `.leak-denylist`, loaded below if present. This
# keeps the detector from leaking the very strings it guards. See .leak-denylist.example.
# RFC1918 / documentation IP ranges and well-known public probe IPs are intentionally NOT
# flagged structurally (too many legitimate uses); the denylist catches per-install values.
LEAK_RE := (sk-ant-[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|[A-Za-z0-9+/]{43}=|[0-9a-f]{2}(:[0-9a-f]{2}){5})

leak-check:
	@echo "Checking for leaks..."
	@hits=0; \
	grep -rniE '$(LEAK_RE)' --exclude-dir=.git . && hits=1 || true; \
	if [ -f .leak-denylist ]; then \
	  grep -rniFf .leak-denylist --exclude-dir=.git --exclude=.leak-denylist . && hits=1 || true; \
	fi; \
	if [ "$$hits" = "1" ]; then echo "LEAK FOUND — fix before commit/push"; exit 1; fi; \
	echo "Leak check passed"

# Install leak-check as a pre-push git hook (run once after `git init`).
install-hook:
	@printf '#!/bin/sh\nmake leak-check\n' > .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "Installed .git/hooks/pre-push -> make leak-check"

test:
	@command -v pytest >/dev/null 2>&1 && pytest -q || \
	 echo "pytest not installed — run 'make test-deps' (or install python-pytest yourself)."

# test-deps — install the bench-suite dev dependency (pytest) that the runtime package omits.
# pytest is a DEV dep, not a runtime one, so a fresh `yay -S bastionfw` + repo clone won't have it;
# this is the one-shot to make `make test` runnable. Best-effort across the supported managers.
test-deps:
	@echo "Installing bench-suite dev deps (pytest)..."
	@if command -v pacman >/dev/null 2>&1; then sudo pacman -S --needed --noconfirm python-pytest; \
	 elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y python3-pytest; \
	 elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y python3-pytest; \
	 else python -m pip install --user pytest || echo "Install pytest manually (e.g. python-pytest)."; fi

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check bastion || echo "ruff not installed"
