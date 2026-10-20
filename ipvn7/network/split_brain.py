"""
IPVN 7 Split-Brain Guard & Network Partition Detector
Prevents distributed state divergence and Byzantine routing splits
by monitoring quorum thresholds across active mesh peers.
Inspired by ipvn7 vX7 pkg/l2/split_brain_guard.go.
"""

from __future__ import annotations
import time
import threading
from typing import Dict, Tuple, Optional, Any
from enum import Enum
from dataclasses import dataclass, field


class PartitionState(Enum):
    HEALTHY = "HEALTHY"
    PARTITIONED = "PARTITIONED"
    RECOVERING = "RECOVERING"


@dataclass
class PeerLiveness:
    peer_did: str
    last_seen: float = 0.0
    is_active: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "peer_did": self.peer_did,
            "last_seen": self.last_seen,
            "is_active": self.is_active,
        }


class SplitBrainGuard:
    """
    Guards the node against network split-brain anomalies and partition isolation.
    Enforces quorum thresholds before committing distributed state transitions.
    """

    def __init__(
        self,
        heartbeat_timeout: float = 10.0,
        partition_threshold: float = 0.50,
        recovery_window: float = 5.0,
    ):
        self._lock = threading.Lock()
        self.peers: Dict[str, PeerLiveness] = {}
        self.state: PartitionState = PartitionState.HEALTHY
        self.heartbeat_timeout: float = heartbeat_timeout
        self.partition_threshold: float = partition_threshold
        self.recovery_window: float = recovery_window
        self.state_changed_at: float = time.time()
        self.stats = {
            "audits_performed": 0,
            "partitions_detected": 0,
            "recoveries_completed": 0,
        }

    def register_peer(self, peer_did: str) -> None:
        """Adds a known peer to the census table."""
        with self._lock:
            if peer_did not in self.peers:
                self.peers[peer_did] = PeerLiveness(peer_did=peer_did, last_seen=0.0, is_active=False)

    def unregister_peer(self, peer_did: str) -> None:
        """Removes a peer from census."""
        with self._lock:
            self.peers.pop(peer_did, None)

    def record_heartbeat(self, peer_did: str, at: Optional[float] = None) -> None:
        """Records an active liveness signal from a remote peer."""
        now = at if at is not None else time.time()
        with self._lock:
            if peer_did not in self.peers:
                self.peers[peer_did] = PeerLiveness(peer_did=peer_did)
            p = self.peers[peer_did]
            p.last_seen = now
            p.is_active = True

    def audit_liveness(self, at: Optional[float] = None) -> Tuple[PartitionState, str]:
        """
        Audits swarm health against heartbeat timeouts and quorum threshold.
        Returns the updated PartitionState and human-readable reason.
        """
        now = at if at is not None else time.time()
        with self._lock:
            self.stats["audits_performed"] += 1
            total = len(self.peers)
            if total == 0:
                return self.state, "Standalone mode (0 registered peers)"

            active_count = 0
            for p in self.peers.values():
                if now - p.last_seen <= self.heartbeat_timeout:
                    p.is_active = True
                    active_count += 1
                else:
                    p.is_active = False

            ratio = active_count / total
            prev_state = self.state

            if ratio < self.partition_threshold:
                if self.state != PartitionState.PARTITIONED:
                    self.state = PartitionState.PARTITIONED
                    self.state_changed_at = now
                    self.stats["partitions_detected"] += 1
                reason = f"Partition detected: {active_count}/{total} active ({ratio*100:.1f}% < {self.partition_threshold*100:.1f}%)"
                return self.state, reason

            # Ratio meets or exceeds threshold
            if self.state == PartitionState.PARTITIONED:
                self.state = PartitionState.RECOVERING
                self.state_changed_at = now
                reason = f"Entering recovery: {active_count}/{total} active"
                return self.state, reason

            if self.state == PartitionState.RECOVERING:
                if now - self.state_changed_at >= self.recovery_window:
                    self.state = PartitionState.HEALTHY
                    self.state_changed_at = now
                    self.stats["recoveries_completed"] += 1
                    reason = f"Healthy quorum fully restored ({active_count}/{total} active)"
                else:
                    reason = f"Stabilizing in recovery window ({active_count}/{total} active)"
                return self.state, reason

            return self.state, f"Healthy quorum ({active_count}/{total} active, {ratio*100:.1f}%)"

    def is_partitioned(self) -> bool:
        """Returns True if the node is currently partitioned or isolated."""
        with self._lock:
            return self.state == PartitionState.PARTITIONED

    def get_mesh_health(self) -> Dict[str, Any]:
        """Returns consolidated health telemetry."""
        with self._lock:
            active_count = sum(1 for p in self.peers.values() if p.is_active)
            total = len(self.peers)
            ratio = (active_count / total) if total > 0 else 1.0
            return {
                "state": self.state.value,
                "active_peers": active_count,
                "total_peers": total,
                "quorum_ratio": round(ratio, 4),
                "threshold": self.partition_threshold,
                "stats": self.stats,
            }
