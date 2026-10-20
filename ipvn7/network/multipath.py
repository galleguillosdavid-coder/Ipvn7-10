"""
IPVN 7 Multipath Transport Scheduler (MPTS)
===========================================
RFC-7001 Multipath Packet Striping & Interface Scheduling (Dimension 8).

Key Features:
- Striping across heterogenous physical interfaces (Wi-Fi, Cellular 5G, Satellite LEO, Virtual).
- Dynamic Selection Policies:
  * LOWEST_LATENCY: Dispatches strictly over lowest measured RTT interface.
  * BALANCED: Weighted round-robin load distribution across healthy active links.
  * CRITICAL_DUPLICATION: Bicast redundant transmission for zero-loss & lowest-jitter datagrams.
- Autonomous Failover: Automatically shifts traffic away from links exceeding loss or latency thresholds.
"""

import time
import socket
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field


class MultipathStrategy(str, Enum):
    LOWEST_LATENCY = "LOWEST_LATENCY"
    BALANCED = "BALANCED"
    CRITICAL_DUPLICATION = "CRITICAL_DUPLICATION"


@dataclass
class PhysicalPath:
    """Represents a physical network link available on the host or mesh."""
    name: str  # e.g., "wlan0", "wwan5g", "leo_sat0", "tun-default"
    iface_type: str  # "WIFI", "CELLULAR", "SAT", "ETHERNET", "VIRTUAL"
    local_ip: str
    latency_ms: float = 10.0
    loss_rate: float = 0.0  # 0.0 to 1.0
    weight: int = 10  # Capacity weight
    active: bool = True
    last_probe: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "iface_type": self.iface_type,
            "local_ip": self.local_ip,
            "latency_ms": round(self.latency_ms, 2),
            "loss_rate": round(self.loss_rate, 4),
            "weight": self.weight,
            "active": self.active,
            "last_probe": self.last_probe,
        }


class MultipathScheduler:
    """
    Coordinates multipath routing, load balancing, and bicast packet duplication.
    """

    def __init__(self, default_strategy: MultipathStrategy = MultipathStrategy.LOWEST_LATENCY):
        self.strategy = default_strategy
        self.interfaces: Dict[str, PhysicalPath] = {}
        self._rr_counter = 0

        # Telemetry
        self.stats = {
            "packets_routed": 0,
            "packets_duplicated": 0,
            "failover_events": 0,
            "strategy_switches": 0,
        }

        # Initialize default virtual path
        self.register_interface(
            PhysicalPath(
                name="default-mesh0",
                iface_type="VIRTUAL",
                local_ip="127.0.0.1",
                latency_ms=99.0,
                loss_rate=0.0,
                weight=1,
                active=True,
            )
        )

    def register_interface(self, path: PhysicalPath) -> None:
        """Registers or updates a physical interface descriptor."""
        if path.name != "default-mesh0" and "default-mesh0" in self.interfaces:
            # If default-mesh0 is sole interface and a real interface is added, prune fallback
            if len(self.interfaces) == 1:
                self.interfaces.pop("default-mesh0", None)
        self.interfaces[path.name] = path

    def set_interface_status(self, name: str, active: bool, latency_ms: Optional[float] = None, loss_rate: Optional[float] = None) -> bool:
        """Updates link status metrics for an interface."""
        path = self.interfaces.get(name)
        if not path:
            return False
        
        old_active = path.active
        path.active = active
        if latency_ms is not None:
            path.latency_ms = max(0.1, latency_ms)
        if loss_rate is not None:
            path.loss_rate = max(0.0, min(1.0, loss_rate))
        path.last_probe = time.time()

        if old_active and not active:
            self.stats["failover_events"] += 1

        return True

    def set_strategy(self, strategy: MultipathStrategy) -> None:
        """Changes the current dispatch strategy."""
        if strategy != self.strategy:
            self.strategy = strategy
            self.stats["strategy_switches"] += 1

    def select_paths_for_packet(self, packet_bytes: bytes, is_critical: bool = False) -> List[PhysicalPath]:
        """
        Determines the physical interface(s) over which to dispatch a datagram.
        Returns a list of 1 path (for normal routing) or multiple paths (for critical duplication).
        """
        active_paths = [p for p in self.interfaces.values() if p.active and p.loss_rate < 0.50]
        if not active_paths:
            # Fallback to any interface
            active_paths = list(self.interfaces.values())
            if not active_paths:
                return []

        self.stats["packets_routed"] += 1

        # Explicit critical traffic forces bicast duplication
        if is_critical or self.strategy == MultipathStrategy.CRITICAL_DUPLICATION:
            if len(active_paths) >= 2:
                # Select top-2 lowest latency paths
                sorted_by_rtt = sorted(active_paths, key=lambda p: (p.latency_ms, p.loss_rate))
                selected = sorted_by_rtt[:2]
                self.stats["packets_duplicated"] += 1
                return selected
            return active_paths[:1]

        # LOWEST_LATENCY strategy
        if self.strategy == MultipathStrategy.LOWEST_LATENCY:
            best_path = min(active_paths, key=lambda p: (p.latency_ms, p.loss_rate))
            return [best_path]

        # BALANCED strategy (Weighted Round-Robin)
        if self.strategy == MultipathStrategy.BALANCED:
            # Expand by weight for weighted distribution
            weighted_pool = []
            for p in active_paths:
                weighted_pool.extend([p] * max(1, p.weight))
            idx = self._rr_counter % len(weighted_pool)
            self._rr_counter += 1
            return [weighted_pool[idx]]

        return [active_paths[0]]

    def get_summary(self) -> Dict[str, Any]:
        """Returns complete multipath status and telemetry."""
        return {
            "current_strategy": self.strategy.value,
            "interfaces_count": len(self.interfaces),
            "active_interfaces": [p.to_dict() for p in self.interfaces.values() if p.active],
            "all_interfaces": [p.to_dict() for p in self.interfaces.values()],
            "stats": self.stats,
        }
