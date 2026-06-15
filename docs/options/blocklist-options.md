# Blocklist feed options (L1)

L1 (`feeds`) populates the `blk_feed` nft set from one or more public IP blocklists. The feed
URLs are configurable; `edge-feed-fetch` ships with a small set of widely-used public lists as
defaults. Pick lists that match your tolerance for false positives — aggressive lists block
more but occasionally catch shared/CGNAT space.

| Category | Description | Typical false-positive risk |
|---|---|---|
| **Curated level-1 / "drop" lists** | Hijacked netblocks and direct-allocation bad actors. Conservative, high-confidence. | Low |
| **Aggregated abuse lists** | Aggregated reports of hosts seen attacking (SSH/HTTP/etc.). Broader coverage. | Medium |
| **Threat-specific feeds** | Lists scoped to a specific malware family or botnet C2. | Low, but narrow |

Configuration notes:
- The never-block allowlist (`templates/policy.allowlist`) always wins: any feed entry that
  overlaps an allowlist entry is rejected by the reconciler.
- Per-source CIDR-width floors prevent a feed from blocking an over-broad range.
- Choose feeds you trust to be maintained; a stale or hijacked feed URL is itself a risk.
