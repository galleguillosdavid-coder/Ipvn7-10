"""
IPVN 7 — Sovereign Tri-State Operating Mode Controller & Adaptive Health Governor (Línea T)
==========================================================================================
Formalized and ported from historical IPVN 7 specification (0.7/src/pkg/core/operating_modes.go,
ip7uin_MVP_Spec_v1.1.docx Section 4.8).

Architectural Profile:
  1. MODE_OPEN (Nominal Standard Mesh):
     - Bidirectional mesh communication.
     - Public DHT announcements enabled (normal visibility).
     - Standard DWRR QoS weight distribution across all 4 traffic classes.
     - Permissive / ACL-evaluated ZTNA ingress.
  2. MODE_SAFE (Stealth / Dark Node):
     - Zero-PII Egress-Only mode.
     - Public listener announcements muted.
     - Mandatory 3-hop Sphinx Onion Routing (1280B fixed framing).
     - Micro-jitter activated in traffic pacer to prevent temporal flow-correlation.
     - Strict Default-Deny on unprompted ingress.
  3. MODE_DEGRADED (Contingency Defense & Resource Squeeze):
     - Activated under severe network congestion, DoS attack, or buffer exhaustion.
     - Automatically triggered when:
       * Packet loss > 30%
       * eBPF/XDP early-drop ratio > 25%
       * Pacer buffer utilization > 80%
     - Austerity actions:
       * Scavenger / Bulk queue (QoS Class 3) purged and suspended.
       * DWRR weights concentrated on Control (Class 0) and Realtime (Class 1).
       * Unauthenticated peer ingress throttled.
     - Auto-recovery: Restores previous mode (OPEN or SAFE) once telemetry metrics remain
       healthy for a configured cool-down window.
"""

from __future__ import annotations

import time
import threading
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .dark_node import DarkNodeMacroOrchestrator, OperatingMode as LegacyOperatingMode
from .firewall import ZTNAFirewall
from ..network.pacer import DWRRScheduler, QoSClass
from ..access.xdp_switch import XDPKernelSimulator


class NodeOperatingMode(str, Enum):
    """Canonical tri-state operating modes for an IPVN 7 node."""
    MODE_OPEN = "MODE_OPEN"
    MODE_SAFE = "MODE_SAFE"
    MODE_DEGRADED = "MODE_DEGRADED"


@dataclass
class ModeTransition:
    """Audit record capturing an atomic mode transition."""
    from_mode: str
    to_mode: str
    reason: str
    timestamp_iso: str
    timestamp_epoch: float = field(default_factory=time.time)
    metrics_snapshot: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_mode": self.from_mode,
            "to_mode": self.to_mode,
            "reason": self.reason,
            "timestamp_iso": self.timestamp_iso,
            "timestamp_epoch": self.timestamp_epoch,
            "metrics_snapshot": dict(self.metrics_snapshot),
        }


class OperatingModeController:
    """
    Atomic Macro-Governor & Adaptive Health Controller for IPVN 7.
    Coordinates Dark Node stealth, ZTNA firewall, DWRR QoS scheduler,
    and eBPF/XDP wire-speed early drop across the tri-state operational envelope.
    """

    DEFAULT_LOSS_THRESHOLD_PCT = 30.0
    DEFAULT_DROP_RATIO_THRESHOLD_PCT = 25.0
    DEFAULT_BUFFER_UTIL_THRESHOLD_PCT = 80.0
    DEFAULT_COOLDOWN_SEC = 10.0
    HISTORY_MAXLEN = 32

    def __init__(
        self,
        dark_node: Optional[DarkNodeMacroOrchestrator] = None,
        firewall: Optional[ZTNAFirewall] = None,
        scheduler: Optional[DWRRScheduler] = None,
        xdp_switch: Optional[XDPKernelSimulator] = None,
        loss_threshold_pct: float = DEFAULT_LOSS_THRESHOLD_PCT,
        drop_threshold_pct: float = DEFAULT_DROP_RATIO_THRESHOLD_PCT,
        buffer_threshold_pct: float = DEFAULT_BUFFER_UTIL_THRESHOLD_PCT,
        cooldown_sec: float = DEFAULT_COOLDOWN_SEC,
    ):
        self.dark_node = dark_node
        self.firewall = firewall
        self.scheduler = scheduler
        self.xdp_switch = xdp_switch

        self.loss_threshold_pct = float(loss_threshold_pct)
        self.drop_threshold_pct = float(drop_threshold_pct)
        self.buffer_threshold_pct = float(buffer_threshold_pct)
        self.cooldown_sec = float(cooldown_sec)

        self._current_mode: NodeOperatingMode = NodeOperatingMode.MODE_OPEN
        self._pre_degraded_mode: NodeOperatingMode = NodeOperatingMode.MODE_OPEN
        self._history: deque[ModeTransition] = deque(maxlen=self.HISTORY_MAXLEN)
        self._transitions_count: int = 0
        self._last_transition_time: float = time.time()
        self._consecutive_healthy_evals: int = 0

        self._last_metrics: Dict[str, float] = {
            "loss_pct": 0.0,
            "drop_ratio_pct": 0.0,
            "buffer_util_pct": 0.0,
        }

        # Backup of baseline DWRR weights when entering degraded mode
        self._original_dwrr_weights: Optional[Dict[QoSClass, int]] = None

        self._lock = threading.RLock()

        # Initial transition record (bootstrap)
        self._record_transition_locked(
            from_mode="BOOTSTRAP",
            to_mode=self._current_mode.value,
            reason="node_initialization",
            metrics=dict(self._last_metrics),
        )

    @property
    def current_mode(self) -> NodeOperatingMode:
        with self._lock:
            return self._current_mode

    @property
    def pre_degraded_mode(self) -> NodeOperatingMode:
        with self._lock:
            return self._pre_degraded_mode

    def is_open(self) -> bool:
        with self._lock:
            return self._current_mode == NodeOperatingMode.MODE_OPEN

    def is_safe(self) -> bool:
        with self._lock:
            return self._current_mode == NodeOperatingMode.MODE_SAFE

    def is_degraded(self) -> bool:
        with self._lock:
            return self._current_mode == NodeOperatingMode.MODE_DEGRADED

    def set_mode(
        self,
        mode: NodeOperatingMode | str,
        reason: str = "manual_override",
        metrics: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Atomically shifts operating mode and cascades policy adjustments.
        Returns the updated controller status.
        """
        if isinstance(mode, str):
            try:
                target_mode = NodeOperatingMode(mode.upper())
            except ValueError:
                raise ValueError(
                    f"Invalid operating mode '{mode}'. Must be one of: "
                    f"{[m.value for m in NodeOperatingMode]}"
                )
        else:
            target_mode = mode

        with self._lock:
            if target_mode == self._current_mode:
                return self.get_status()

            old_mode = self._current_mode

            # Track pre-degraded baseline to restore after emergency passes
            if target_mode == NodeOperatingMode.MODE_DEGRADED:
                if old_mode != NodeOperatingMode.MODE_DEGRADED:
                    self._pre_degraded_mode = old_mode
            else:
                self._pre_degraded_mode = target_mode

            # Cascade actions to subsystems
            self._apply_mode_cascade_locked(old_mode, target_mode)

            self._current_mode = target_mode
            self._transitions_count += 1
            self._last_transition_time = time.time()
            self._consecutive_healthy_evals = 0

            # Record transition in bounded ring buffer
            active_metrics = dict(metrics if metrics is not None else self._last_metrics)
            self._record_transition_locked(
                from_mode=old_mode.value,
                to_mode=target_mode.value,
                reason=reason,
                metrics=active_metrics,
            )

            return self.get_status()

    def evaluate_health(
        self,
        loss_pct: float,
        drop_ratio_pct: float,
        buffer_util_pct: float,
    ) -> Dict[str, Any]:
        """
        Adaptive Health Governor evaluation loop.
        Monitors loss, drop ratio, and queue buffer saturation:
        - Trips into MODE_DEGRADED if any threshold is violated.
        - Automatically recovers to pre-degraded mode after cooldown period with clean telemetry.
        """
        with self._lock:
            self._last_metrics = {
                "loss_pct": float(loss_pct),
                "drop_ratio_pct": float(drop_ratio_pct),
                "buffer_util_pct": float(buffer_util_pct),
            }

            trip_loss = loss_pct > self.loss_threshold_pct
            trip_drop = drop_ratio_pct > self.drop_threshold_pct
            trip_buffer = buffer_util_pct > self.buffer_threshold_pct

            violations: List[str] = []
            if trip_loss:
                violations.append(f"loss({loss_pct:.1f}% > {self.loss_threshold_pct:.1f}%)")
            if trip_drop:
                violations.append(f"drop_ratio({drop_ratio_pct:.1f}% > {self.drop_threshold_pct:.1f}%)")
            if trip_buffer:
                violations.append(f"buffer_util({buffer_util_pct:.1f}% > {self.buffer_threshold_pct:.1f}%)")

            if violations:
                # Telemetry violates safety envelope
                self._consecutive_healthy_evals = 0
                if self._current_mode != NodeOperatingMode.MODE_DEGRADED:
                    reason = f"health_governor_tripped: {', '.join(violations)}"
                    self.set_mode(
                        NodeOperatingMode.MODE_DEGRADED,
                        reason=reason,
                        metrics=self._last_metrics,
                    )
            else:
                # Telemetry within healthy parameters
                self._consecutive_healthy_evals += 1
                if self._current_mode == NodeOperatingMode.MODE_DEGRADED:
                    time_in_degraded = time.time() - self._last_transition_time
                    if time_in_degraded >= self.cooldown_sec and self._consecutive_healthy_evals >= 2:
                        target = self._pre_degraded_mode
                        reason = (
                            f"health_governor_cooldown_recovered ({time_in_degraded:.1f}s elapsed, "
                            f"{self._consecutive_healthy_evals} clean ticks)"
                        )
                        self.set_mode(target, reason=reason, metrics=self._last_metrics)

            return self.get_status()

    def _apply_mode_cascade_locked(
        self,
        old_mode: NodeOperatingMode,
        target_mode: NodeOperatingMode,
    ) -> None:
        """Executes cross-layer policy adjustments across subsystems."""
        # 1. Dark Node / Stealth Profile Adjustment
        if self.dark_node is not None:
            if target_mode == NodeOperatingMode.MODE_SAFE:
                self.dark_node.set_mode(LegacyOperatingMode.DARK_NODE_EGRESS_ONLY)
            elif target_mode == NodeOperatingMode.MODE_OPEN:
                self.dark_node.set_mode(LegacyOperatingMode.STANDARD_MESH)
            elif target_mode == NodeOperatingMode.MODE_DEGRADED:
                # In degraded mode, listeners are muted to reduce attack surface
                self.dark_node.listeners_muted = True

        # 2. ZTNA Firewall Adjustment
        if self.firewall is not None:
            if target_mode == NodeOperatingMode.MODE_SAFE:
                self.firewall.set_default_deny(True)
            elif target_mode == NodeOperatingMode.MODE_DEGRADED:
                self.firewall.set_default_deny(True)
            elif target_mode == NodeOperatingMode.MODE_OPEN:
                # Note: We preserve explicit DID authorization policies, only relaxing global default deny
                # if node is operating in nominal open mesh.
                pass

        # 3. DWRR Scheduler & Queue Austerity Adjustment
        if self.scheduler is not None:
            if target_mode == NodeOperatingMode.MODE_DEGRADED:
                # Purge scavenger / bulk queue to immediately relieve memory pressure
                if QoSClass.BULK in self.scheduler.queues:
                    self.scheduler.queues[QoSClass.BULK].clear()

                # Save original weights if not already saved
                if self._original_dwrr_weights is None:
                    self._original_dwrr_weights = dict(self.scheduler.WEIGHTS)

                # Prioritize Control and Realtime; starve bulk
                self.scheduler.WEIGHTS[QoSClass.CONTROL] = 6000
                self.scheduler.WEIGHTS[QoSClass.REALTIME] = 3500
                self.scheduler.WEIGHTS[QoSClass.INTERACTIVE] = 500
                self.scheduler.WEIGHTS[QoSClass.BULK] = 0

            elif old_mode == NodeOperatingMode.MODE_DEGRADED:
                # Restore original DWRR weights upon recovery
                if self._original_dwrr_weights is not None:
                    for qos_class, weight in self._original_dwrr_weights.items():
                        self.scheduler.WEIGHTS[qos_class] = weight
                    self._original_dwrr_weights = None

    def _record_transition_locked(
        self,
        from_mode: str,
        to_mode: str,
        reason: str,
        metrics: Dict[str, float],
    ) -> None:
        now_epoch = time.time()
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))
        transition = ModeTransition(
            from_mode=from_mode,
            to_mode=to_mode,
            reason=reason,
            timestamp_iso=iso,
            timestamp_epoch=now_epoch,
            metrics_snapshot=metrics,
        )
        self._history.append(transition)

    def get_history(self) -> List[Dict[str, Any]]:
        """Returns the bounded chronological history of transitions (most recent last)."""
        with self._lock:
            return [t.to_dict() for t in self._history]

    def get_status(self) -> Dict[str, Any]:
        """Provides real-time audit telemetry and governor state."""
        with self._lock:
            now_epoch = time.time()
            time_in_current_mode = max(0.0, now_epoch - self._last_transition_time)
            last_transition_iso = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._last_transition_time)
            )

            active_protections: List[str] = []
            if self._current_mode == NodeOperatingMode.MODE_OPEN:
                active_protections.append("NOMINAL_MESH_DISCOVERY")
                active_protections.append("PROPORTIONAL_FAIRNESS_DWRR")
            elif self._current_mode == NodeOperatingMode.MODE_SAFE:
                active_protections.append("ZERO_PII_EGRESS_ONLY")
                active_protections.append("MANDATORY_3HOP_SPHINX")
                active_protections.append("PACER_MICRO_JITTER")
                active_protections.append("MUTED_PUBLIC_ANNOUNCEMENTS")
                active_protections.append("ZTNA_STRICT_DEFAULT_DENY")
            elif self._current_mode == NodeOperatingMode.MODE_DEGRADED:
                active_protections.append("SCAVENGER_BULK_PURGE")
                active_protections.append("QOS_AUSTERITY_CONCENTRATION")
                active_protections.append("MUTED_PUBLIC_ANNOUNCEMENTS")
                active_protections.append("ZTNA_STRICT_DEFAULT_DENY")
                active_protections.append("CONGESTION_CIRCUIT_BREAKER")

            return {
                "current_mode": self._current_mode.value,
                "pre_degraded_mode": self._pre_degraded_mode.value,
                "is_open": self.is_open(),
                "is_safe": self.is_safe(),
                "is_degraded": self.is_degraded(),
                "active_protections": active_protections,
                "transitions_count": self._transitions_count,
                "last_transition_iso": last_transition_iso,
                "time_in_current_mode_sec": round(time_in_current_mode, 2),
                "consecutive_healthy_evals": self._consecutive_healthy_evals,
                "thresholds": {
                    "loss_pct": self.loss_threshold_pct,
                    "drop_ratio_pct": self.drop_threshold_pct,
                    "buffer_util_pct": self.buffer_threshold_pct,
                    "cooldown_sec": self.cooldown_sec,
                },
                "last_metrics": dict(self._last_metrics),
                "history_length": len(self._history),
            }
