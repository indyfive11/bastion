# DNS upstream options

This catalog lists the *categories* of DNS upstream `bastion` (L4) can be configured with.
It documents what kinds of upstream exist — it does not prescribe or reveal any particular
choice. Set your selection in `machine.conf` as `network.dns_upstream`; the wizard writes it
into `dnsmasq.conf`.

| Category | `dns_upstream` form | Notes |
|---|---|---|
| **Local validating stub** | `127.0.0.1#5335` | A local unbound instance (see `templates/unbound.conf`) does recursive, DNSSEC-validating resolution. No third party sees per-query data. |
| **Public plaintext** | `<resolver-ip>` | A public resolver over plain UDP/53. Simple; unencrypted on the wire. Some such resolvers also offer content filtering. |
| **Public DoT / DoH** | `<resolver-ip>` (with a stub/forwarder doing DoT) | Encrypted transport to a public resolver. Requires a DoT-capable forwarder in front of, or instead of, dnsmasq. |
| **Private encrypted** | `<private-ip>` over a tunnel | Forward to your own resolver reachable only across a VPN/WireGuard tunnel. Fleet-consistent; keeps resolution on infrastructure you control. |

Trade-offs to weigh: privacy of query data, whether you want content filtering, DNSSEC
validation, and whether resolution should survive an upstream/ISP outage.
