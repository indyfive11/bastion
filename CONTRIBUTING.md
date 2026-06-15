# Contributing to Bastion

Thanks for your interest in improving Bastion. A few project-specific rules keep the
repository safe to publish.

## The one hard rule: no real topology in the repo

`make leak-check` runs on every commit (and as a pre-push hook). **It must pass.**

- No real IPs, MACs, hostnames, keys, or other installation-specific values in any committed file.
- Config templates use `{{ section.key }}` placeholders only. Real values are read at runtime
  from `/etc/bastion/machine.env` (rendered by `bastion generate`), never hardcoded.
- Secrets live in `secrets.conf` / a systemd `EnvironmentFile`, never in `machine.conf` or a template.

## Development workflow

```sh
make leak-check        # leak gate
make generate-check   # every template resolves against machine.conf.example
python -m pytest -q   # test suite
```

`bastion setup --dry-run` is a safe, offline smoke test of the wizard (writes nothing, no network).

## Design invariants

- The reconciler is the **only** writer to managed nftables sets.
- No hard service dependencies (`Requires=`/`BindsTo=`) on external or boot-path units — use `After=`/`Wants=`.
- Every install action is idempotent (safe to re-run).
- A human kill switch and the always-installed recovery service are mandatory and must not be removed.

## Pull requests

- Keep changes scoped; unrelated improvements belong in a separate PR.
- Include tests for new behavior.
- Make sure `make leak-check`, `make generate-check`, and the test suite all pass.
