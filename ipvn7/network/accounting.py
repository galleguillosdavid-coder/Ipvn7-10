"""
IPVN 7 Transit Accounting & Algorithmic Reciprocity (Tit-for-Tat)
Enforces game-theoretic bandwidth fairness to mitigate free-riding and resource exhaustion.
Inspired by ipvn7 vX7 pkg/l2/accounting.go.
"""

from __future__ import annotations
import time
import threading
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, field


class ServiceTier(Enum):
    PRIORITY = "PRIORITY"       # Ratio >= 1.0: Exemplary contributor (high QoS priority)
    NORMAL = "NORMAL"           # 0.5 <= Ratio < 1.0: Standard acceptable cooperation
    BEST_EFFORT = "BEST_EFFORT" # 0.2 <= Ratio < 0.5: Deficient contribution (deprioritized queue)
    THROTTLED = "THROTTLED"     # Ratio < 0.2: Free-rider or abusive node (severe rate limiting)


@dataclass
class PeerAccounting:
    did: str
    bytes_tx: int = 0      # Bytes this node transmitted to peer
    bytes_rx: int = 0      # Bytes peer routed or delivered to this node
    packets_tx: int = 0
    packets_rx: int = 0
    ratio: float = 1.0     # Tit-for-Tat reciprocity ratio (Rx / Tx)
    tier: ServiceTier = ServiceTier.NORMAL
    last_active: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "did": self.did,
            "bytes_tx": self.bytes_tx,
            "bytes_rx": self.bytes_rx,
            "packets_tx": self.packets_tx,
            "packets_rx": self.packets_rx,
            "tit_for_tat_ratio": round(self.ratio, 3),
            "tier": self.tier.value,
            "last_active": self.last_active,
        }


class TransitAccounting:
    """
    Game-Theoretic Bandwidth Reciprocity Engine.
    Tracks bidirectional byte flows per DID and classifies nodes into service tiers.
    """

    def __init__(
        self,
        courtesy_bytes: int = 1048576, # 1 MB courtesy margin for bootstrap
        courtesy_packets: int = 1000,
    ):
        self._lock = threading.Lock()
        self.accounts: Dict[str, PeerAccounting] = {}
        self.courtesy_bytes = courtesy_bytes
        self.courtesy_packets = courtesy_packets
        self.stats = {
            "total_enforced": 0,
            "total_throttled": 0,
        }

    def _get_or_create(self, did: str) -> PeerAccounting:
        if did in self.accounts:
            return self.accounts[did]
        acc = PeerAccounting(did=did, tier=ServiceTier.NORMAL, last_active=time.time())
        self.accounts[did] = acc
        return acc

    def record_tx(self, did: str, byte_count: int) -> ServiceTier:
        """Records transmitted bytes to peer and recalculates service tier."""
        with self._lock:
            acc = self._get_or_create(did)
            acc.bytes_tx += byte_count
            acc.packets_tx += 1
            acc.last_active = time.time()
            self._recalculate_tier(acc)
            return acc.tier

    def record_rx(self, did: str, byte_count: int) -> ServiceTier:
        """Records received/routed bytes from peer and recalculates service tier."""
        with self._lock:
            acc = self._get_or_create(did)
            acc.bytes_rx += byte_count
            acc.packets_rx += 1
            acc.last_active = time.time()
            self._recalculate_tier(acc)
            return acc.tier

    def _recalculate_tier(self, acc: PeerAccounting) -> None:
        """Evaluates Tit-for-Tat reciprocity ratio against courtesy thresholds."""
        # Grant courtesy tier during bootstrap phase
        if acc.bytes_tx < self.courtesy_bytes and acc.packets_tx < self.courtesy_packets:
            acc.ratio = 1.0
            acc.tier = ServiceTier.NORMAL
            return

        if acc.bytes_tx == 0:
            acc.ratio = 1.0 if acc.bytes_rx > 0 else 0.5
        else:
            acc.ratio = acc.bytes_rx / acc.bytes_tx

        self.stats["total_enforced"] += 1

        if acc.ratio >= 1.0:
            acc.tier = ServiceTier.PRIORITY
        elif acc.ratio >= 0.5:
            acc.tier = ServiceTier.NORMAL
        elif acc.ratio >= 0.2:
            acc.tier = ServiceTier.BEST_EFFORT
        else:
            acc.tier = ServiceTier.THROTTLED
            self.stats["total_throttled"] += 1

    def get_tier(self, did: str) -> ServiceTier:
        """Returns current service tier for target DID."""
        with self._lock:
            acc = self.accounts.get(did)
            return acc.tier if acc else ServiceTier.NORMAL

    def get_peer_account(self, did: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            acc = self.accounts.get(did)
            return acc.to_dict() if acc else None

    def list_accounts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            accs = list(self.accounts.values())
        accs.sort(key=lambda a: a.last_active, reverse=True)
        return [a.to_dict() for a in accs[:limit]]

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            counts = {
                ServiceTier.PRIORITY.value: 0,
                ServiceTier.NORMAL.value: 0,
                ServiceTier.BEST_EFFORT.value: 0,
                ServiceTier.THROTTLED.value: 0,
            }
            total_tx = 0
            total_rx = 0
            for a in self.accounts.values():
                counts[a.tier.value] += 1
                total_tx += a.bytes_tx
                total_rx += a.bytes_rx

        return {
            "tracked_peers": len(self.accounts),
            "tier_distribution": counts,
            "total_bytes_tx": total_tx,
            "total_bytes_rx": total_rx,
            "stats": self.stats,
        }
