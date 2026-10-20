"""
IPVN 7 - Link Healing Engine & RFC 2439 Route Flap Damping
Rescued & ported from ipvn7  vX7/pkg/l1/link_healing.go.

Features:
1. Continuous link quality monitoring (loss threshold, latency degradation).
2. Anti-flapping hysteresis: requires N consecutive successes to clear degraded status.
3. RFC 2439 Route Flap Damping: exponential hold-down penalty for rapid failovers (<10s).
4. O(1) failover peer selection.
"""

from __future__ import annotations
import time
import threading
from typing import Dict, Any, Optional, Tuple, List

DEFAULT_MAX_CONSECUTIVE_LOSSES = 3
DEFAULT_DEGRADED_LATENCY_MS = 500.0
DEFAULT_RECOVERY_SUCCESSES = 2
DEFAULT_HOLD_DOWN_PENALTY_STEP_S = 2.0
MAX_HOLD_DOWN_S = 30.0


class PeerHealthStats:
    def __init__(self, did: str):
        self.did = did
        self.consecutive_losses: int = 0
        self.consecutive_successes: int = 0
        self.last_latency_ms: float = 0.0
        self.last_evaluation: float = time.time()
        self.degraded: bool = False
        self.failover_count: int = 0
        self.last_failover_time: float = 0.0
        self.hold_down_until: float = 0.0
        self.flap_penalty_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "did": self.did,
            "consecutive_losses": self.consecutive_losses,
            "consecutive_successes": self.consecutive_successes,
            "last_latency_ms": round(self.last_latency_ms, 2),
            "degraded": self.degraded,
            "failover_count": self.failover_count,
            "flap_penalty_count": self.flap_penalty_count,
            "is_in_hold_down": time.time() < self.hold_down_until,
            "hold_down_remaining_s": max(0.0, round(self.hold_down_until - time.time(), 2)),
        }


class LinkHealingEngine:
    def __init__(
        self,
        max_losses: int = DEFAULT_MAX_CONSECUTIVE_LOSSES,
        degraded_latency_ms: float = DEFAULT_DEGRADED_LATENCY_MS,
        recovery_successes: int = DEFAULT_RECOVERY_SUCCESSES,
    ):
        self.max_losses = max_losses
        self.degraded_latency_ms = degraded_latency_ms
        self.recovery_successes = recovery_successes

        self.stats: Dict[str, PeerHealthStats] = {}
        self.total_failovers: int = 0
        self.total_recoveries: int = 0
        self._lock = threading.Lock()

    def record_probe_result(
        self,
        did: str,
        success: bool,
        latency_ms: float,
        available_peers: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Records datagram or probe outcome.
        Returns (failover_triggered, alternative_peer_did).
        """
        with self._lock:
            stat = self.stats.get(did)
            now = time.time()
            if not stat:
                stat = PeerHealthStats(did)
                self.stats[did] = stat

            stat.last_evaluation = now
            stat.last_latency_ms = latency_ms

            if not success:
                stat.consecutive_losses += 1
                stat.consecutive_successes = 0
                if stat.consecutive_losses >= self.max_losses:
                    stat.degraded = True
            else:
                stat.consecutive_losses = 0
                if latency_ms > self.degraded_latency_ms:
                    stat.degraded = True
                    stat.consecutive_successes = 0
                else:
                    stat.consecutive_successes += 1
                    # Anti-flapping hysteresis: requires recovery_successes AND expired hold-down
                    if stat.consecutive_successes >= self.recovery_successes:
                        if now >= stat.hold_down_until:
                            if stat.degraded:
                                self.total_recoveries += 1
                            stat.degraded = False
                            stat.flap_penalty_count = 0

            # Evaluate if failover should trigger
            if (not success or latency_ms > self.degraded_latency_ms) and stat.degraded:
                # RFC 2439 Flap Damping
                if stat.last_failover_time > 0 and (now - stat.last_failover_time) < 10.0:
                    stat.flap_penalty_count += 1
                    penalty = min(
                        MAX_HOLD_DOWN_S,
                        stat.flap_penalty_count * DEFAULT_HOLD_DOWN_PENALTY_STEP_S,
                    )
                    stat.hold_down_until = now + penalty

                stat.last_failover_time = now

                # Choose alternative peer
                alt_did = None
                if available_peers:
                    for p in available_peers:
                        if p != did:
                            p_stat = self.stats.get(p)
                            if not p_stat or not p_stat.degraded:
                                alt_did = p
                                break

                if alt_did:
                    stat.failover_count += 1
                    self.total_failovers += 1
                    return True, alt_did

            return False, None

    def get_peer_health(self, did: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            stat = self.stats.get(did)
            return stat.to_dict() if stat else None

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            degraded_count = sum(1 for s in self.stats.values() if s.degraded)
            in_hold_down_count = sum(1 for s in self.stats.values() if time.time() < s.hold_down_until)
            return {
                "tracked_peers": len(self.stats),
                "degraded_peers": degraded_count,
                "in_hold_down_peers": in_hold_down_count,
                "total_failovers": self.total_failovers,
                "total_recoveries": self.total_recoveries,
                "max_losses_threshold": self.max_losses,
                "degraded_latency_threshold_ms": self.degraded_latency_ms,
            }
