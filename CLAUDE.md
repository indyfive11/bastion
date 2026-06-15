# Bastion — Project Instructions

## What this is
A modular Linux firewall framework. The `full-edge` profile is the primary reference
implementation. Do NOT reference any specific machines, hostnames, or network values
anywhere in code, docs, or commits — templates use `{{ }}` placeholders and the operational
scripts read real values from `/etc/bastion/machine.env` at runtime.

When the architecture is ambiguous, resolve to the narrowest scope.

## Hard rules (non-negotiable)
- `make leak-check` must pass before any commit. Run it.
- No real IPs, MACs, hostnames, keys in any committed file. Templates use `{{ }}`.
- No-arch-leak for the AI setup wizard: only sanitized topology signals reach the API.
- No hard deps (`Requires=`/`BindsTo=`) on external or boot-path services — use `After=`/`Wants=`. Internal same-subsystem pipelines (e.g. `edge-ai` → `edge-ai-collect`, split for privilege separation) MAY use `Requires=` when the consumer is non-functional without the producer's fresh output.
- `edge-reconciler` is the ONLY nft writer. No other script adds nft set elements.
- Secrets never in machine.conf or templates. Injected via systemd EnvironmentFile.
- Idempotent: every installer action is safe to re-run.
- Human kill switch always present; Expert-Mode canary non-optional; `bastion-recovery` always in L0.

## Layout
- `bastion/` — Python package (CLI, setup wizard, layer modules, template engine, state).
- `bastion/scripts/` — operational `edge-*`/`net-*`/`flowcheck` scripts, installed to
  `/usr/local/sbin/`. Machine-specific values are read at runtime from `/etc/bastion/machine.env`
  (rendered by `bastion generate` from machine.conf); fallbacks are generic, never real topology.
- `bastion/templates/` — config templates (`{{ section.key }}` placeholders only, no real values).
  Shipped as package-data so an installed `bastion setup` can find scripts + templates.

## Development
`make leak-check` (leak gate) · `make generate-check` (templates resolve) · `python -m pytest -q`.
See `README.md` for install and usage.

## Identity (public repo)
Author/committer: `indyfive11 <203553604+indyfive11@users.noreply.github.com>`.
No `Co-Authored-By` trailers. No AI attribution in commit messages or PR descriptions.
