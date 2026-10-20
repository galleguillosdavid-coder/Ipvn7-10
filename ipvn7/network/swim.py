"""
IPVN 7 SWIM Failure Detector Protocol (Scalable Weakly-consistent Infection-style Process Group Membership)
O(1) peer health monitoring with direct ping and indirect ping-req via k intermediaries.
Prevents false-positive churn declarations during temporary network jitter.
Inspired by ipvn7 vX7 pkg/l1/swim_failure_detector.go.
"""

from __future__ import annotations
import random
import time
from typing import Dict, List, Optional, Tuple, Callable
from enum import Enum
from dataclasses import dataclass


class SWIMState(Enum):
    ALIVE = "ALIVE"
    SUSPECT = "SUSPECT"
    DEAD = "DEAD"


@dataclass
class SWIMProbeResult:
    target_did: str
    state: SWIMState
    via_indirect: bool
    intermediary_did: Optional[str]
    latency_ms: float


class SWIMFailureDetector:
    """
    SWIM Failure Detector with two-phase probing:
    1. Direct Ping: send probe to target. If ACK received in direct_timeout, target is ALIVE.
    2. Indirect Ping: if direct ping fails/times out, select k random peer candidates
       and request them to probe the target (Ping-Req). If any intermediary receives ACK,
       target is confirmed ALIVE (preventing false positive). Otherwise, declare SUSPECT/DEAD.
    """

    def __init__(
        self,
        local_did: str,
        indirect_k: int = 3,
        direct_timeout_sec: float = 0.15,
        indirect_timeout_sec: float = 0.35,
        direct_probe_func: Optional[Callable[[str], bool]] = None,
        indirect_probe_func: Optional[Callable[[str, str], bool]] = None,
    ):
        self.local_did = local_did
        self.indirect_k = indirect_k
        self.direct_timeout = direct_timeout_sec
        self.indirect_timeout = indirect_timeout_sec
        self.direct_probe_func = direct_probe_func or (lambda target_did: True)
        self.indirect_probe_func = indirect_probe_func or (lambda inter_did, target_did: True)

        self.peer_health: Dict[str, SWIMState] = {}
        self.stats = {
            "probes_total": 0,
            "direct_success": 0,
            "indirect_success": 0,
            "suspect_declared": 0,
            "dead_declared": 0,
        }

    def probe_peer(
        self,
        target_did: str,
        active_mesh_peers: List[str],
    ) -> SWIMProbeResult:
        """
        Executes full SWIM probe cycle on target_did.
        """
        self.stats["probes_total"] += 1
        t0 = time.perf_counter()

        # Phase 1: Direct Probe
        try:
            ok = self.direct_probe_func(target_did)
        except Exception:
            ok = False

        if ok:
            elapsed = (time.perf_counter() - t0) * 1000.0
            self.stats["direct_success"] += 1
            self.peer_health[target_did] = SWIMState.ALIVE
            return SWIMProbeResult(
                target_did=target_did,
                state=SWIMState.ALIVE,
                via_indirect=False,
                intermediary_did=None,
                latency_ms=round(elapsed, 2),
            )

        # Phase 2: Indirect Probes via k intermediaries
        candidates = [p for p in active_mesh_peers if p != target_did and p != self.local_did]
        k_samples = random.sample(candidates, min(len(candidates), self.indirect_k)) if candidates else []

        for intermediary in k_samples:
            try:
                ind_ok = self.indirect_probe_func(intermediary, target_did)
                if ind_ok:
                    elapsed = (time.perf_counter() - t0) * 1000.0
                    self.stats["indirect_success"] += 1
                    self.peer_health[target_did] = SWIMState.ALIVE
                    return SWIMProbeResult(
                        target_did=target_did,
                        state=SWIMState.ALIVE,
                        via_indirect=True,
                        intermediary_did=intermediary,
                        latency_ms=round(elapsed, 2),
                    )
            except Exception:
                continue

        # Both direct and indirect failed
        elapsed = (time.perf_counter() - t0) * 1000.0
        self.stats["suspect_declared"] += 1
        self.peer_health[target_did] = SWIMState.SUSPECT
        return SWIMProbeResult(
            target_did=target_did,
            state=SWIMState.SUSPECT,
            via_indirect=False,
            intermediary_did=None,
            latency_ms=round(elapsed, 2),
        )
