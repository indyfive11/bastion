# Bastion documentation

Reference and how-to docs for [`bastionfw`](../README.md). Start with the project
[README](../README.md) for install and a quick tour; come here for depth.

## Start here

- **[Getting started](getting-started.md)** — the 5-minute path from a fresh box to a
  working firewall: install, run the wizard, check health, open a port, cut over safely.
- **[Use cases & recipes](use-cases.md)** — end-to-end walkthroughs: stand up an edge
  router, harden a laptop endpoint, expose a service to just the LAN, coexist with
  libvirt/Docker, cut over safely, recover from a lockout.
- **[FAQ](faq.md)** — the questions that come up first, answered short.

## Reference

- **[Command reference](commands.md)** — every `bastion` subcommand and what it does.
- **[Architecture](architecture.md)** — how bastion is built: the render spine, the
  sole-writer reconciler, the safety-net triad, and the privacy/security model.
- **[Layers](layers.md)** — what each of L0–L6 installs, its packages, units, scripts,
  dependencies, and health checks.
- **[Troubleshooting](troubleshooting.md)** — symptom → cause → fix for the failure
  modes that actually come up.

## Configuration options

- **[Zones & ownership mode](options/zones-and-ownership.md)** — the `source → action`
  inbound policy, `exclusive` vs `cooperative` scope, and `bastion switch`.
- **[Blocklist feeds (L1)](options/blocklist-options.md)** — choosing threat-intel feeds.
- **[DNS upstreams (L4)](options/dns-options.md)** — the resolver categories you can point at.

## The two commands to reach for first

When anything looks wrong, these two read-only commands pinpoint most problems without
changing anything:

```sh
bastion doctor     # binaries, config drift, reboot persistence, recovery readiness, AI state
bastion verify     # do the live configs still match what `bastion generate` would produce?
```
