"""
IPVN 7 - Post-Blackout Cascaded Recovery & Stochastic Decorrelated Jitter
Rescued & ported from ipvn7  vX7/pkg/l1/blackout_recovery.go.

Features:
1. 5-Phase Cascaded Cold-Boot Recovery (Cold Memory, Off-Grid Proximity, WAN Probe, Blind Rendezvous, Converged Mesh).
2. Stochastic Decorrelated Jitter Timer: T_{i+1} = min(T_max, Uniform(T_base, T_current * 3.0)).
3. Absolute Anti-Thundering Herd protection across peer clusters.
"""

from __future__ import annotations
import time
import random
import threading
from enum import Enum
from typing import Dict, Any, Optional

DEFAULT_BASE_INTERVAL_S = 1.0
DEFAULT_MAX_INTERVAL_S = 60.0
DEFAULT_MULTIPLIER = 3.0


class RecoveryPhase(str, Enum):
    COLD_MEMORY = "PHASE_1_COLD_LOCAL_MEMORY"
    OFFGRID_PROXIMITY = "PHASE_2_OFFGRID_PROXIMITY"
    WAN_PROBE = "PHASE_3_WAN_PROBE"
    BLIND_RENDEZVOUS = "PHASE_4_BLIND_RENDEZVOUS"
    CONVERGED_MESH = "PHASE_5_CONVERGED_MESH"


class DecorrelatedJitterTimer:
    """Calculates stochastic desynchronized backoff intervals to prevent thundering herds."""

    def __init__(
        self,
        base_s: float = DEFAULT_BASE_INTERVAL_S,
        max_s: float = DEFAULT_MAX_INTERVAL_S,
        multiplier: float = DEFAULT_MULTIPLIER,
    ):
        self.base_s = base_s
        self.max_s = max_s
        self.current_s = base_s
        self.multiplier = multiplier
        self.step_count = 0
        self._rng = random.Random(time.time_ns())
        self._lock = threading.Lock()

    def next_interval(self) -> float:
        """
        Calculates next interval:
        T_{i+1} = min(T_max, Uniform(T_base, T_current * multiplier))
        """
        with self._lock:
            upper = min(self.max_s, self.current_s * self.multiplier)
            lower = min(self.base_s, upper)
            next_interval_val = self._rng.uniform(lower, upper)
            self.current_s = next_interval_val
            self.step_count += 1
            return round(next_interval_val, 3)

    def reset(self) -> None:
        with self._lock:
            self.current_s = self.base_s
            self.step_count = 0


class BlackoutRecoveryManager:
    """Orchestrates 5-phase cold recovery and mesh reconvergence."""

    def __init__(
        self,
        base_interval_s: float = DEFAULT_BASE_INTERVAL_S,
        max_interval_s: float = DEFAULT_MAX_INTERVAL_S,
        min_converged_peers: int = 2,
    ):
        self.min_converged_peers = min_converged_peers
        self.current_phase: RecoveryPhase = RecoveryPhase.COLD_MEMORY
        self.timer = DecorrelatedJitterTimer(base_s=base_interval_s, max_s=max_interval_s)
        self.blackout_start_time: float = time.time()
        self.converged_time: Optional[float] = None
        self.consecutive_reconnects: int = 0
        self._lock = threading.Lock()

    def advance_phase(self) -> RecoveryPhase:
        """Advances progressively through the cold boot recovery cascade."""
        with self._lock:
            if self.current_phase == RecoveryPhase.COLD_MEMORY:
                self.current_phase = RecoveryPhase.OFFGRID_PROXIMITY
            elif self.current_phase == RecoveryPhase.OFFGRID_PROXIMITY:
                self.current_phase = RecoveryPhase.WAN_PROBE
            elif self.current_phase == RecoveryPhase.WAN_PROBE:
                self.current_phase = RecoveryPhase.BLIND_RENDEZVOUS
            elif self.current_phase == RecoveryPhase.BLIND_RENDEZVOUS:
                self.current_phase = RecoveryPhase.CONVERGED_MESH
                self.converged_time = time.time()
            return self.current_phase

    def record_peer_connected(self, active_peer_count: int) -> bool:
        """Notifies recovery manager of connected peers. Returns True if mesh converged."""
        with self._lock:
            self.consecutive_reconnects += 1
            if active_peer_count >= self.min_converged_peers:
                if self.current_phase != RecoveryPhase.CONVERGED_MESH:
                    self.current_phase = RecoveryPhase.CONVERGED_MESH
                    self.converged_time = time.time()
                return True
            return False

    def trigger_cold_boot(self) -> None:
        """Resets the state machine back to cold memory boot."""
        with self._lock:
            self.current_phase = RecoveryPhase.COLD_MEMORY
            self.blackout_start_time = time.time()
            self.converged_time = None
            self.consecutive_reconnects = 0
            self.timer.reset()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            elapsed_s = now - self.blackout_start_time
            return {
                "phase": self.current_phase.value,
                "is_converged": self.current_phase == RecoveryPhase.CONVERGED_MESH,
                "elapsed_recovery_s": round(elapsed_s, 2),
                "consecutive_reconnects": self.consecutive_reconnects,
                "next_jittered_interval_s": self.timer.next_interval(),
                "step_count": self.timer.step_count,
            }
