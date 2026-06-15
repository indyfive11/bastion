"""Layer registry. Layers are added here as they are implemented (Phase 3: L0; Phase 4: L1–L6)."""
from __future__ import annotations

from .base import Layer, Context, LayerStatus, HealthCheck
from .l0_core import L0Core
from .l1_feeds import L1Feeds
from .l2_crowdsec import L2Crowdsec
from .l3_ai import L3AiAnalysis
from .l4_dns_dhcp import L4DnsDhcp
from .l5_vpn import L5Vpn
from .l6_monitoring import L6Monitoring

# Ordered registry: id -> Layer instance. Order is install/display order.
REGISTRY: dict[str, Layer] = {
    "l0": L0Core(),
    "l1": L1Feeds(),
    "l2": L2Crowdsec(),
    "l3": L3AiAnalysis(),
    "l4": L4DnsDhcp(),
    "l5": L5Vpn(),
    "l6": L6Monitoring(),
}


def get(layer_id: str) -> Layer | None:
    return REGISTRY.get(layer_id)


def all_layers() -> list[Layer]:
    return list(REGISTRY.values())


__all__ = ["Layer", "Context", "LayerStatus", "HealthCheck", "REGISTRY", "get", "all_layers"]
