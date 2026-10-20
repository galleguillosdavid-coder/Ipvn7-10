"""
IPVN 7 - Dark Node Macro Orchestrator & Stealth Mode Engine
Rescued & ported from ipvn7  vX7/pkg/l1/dark_node_profile.go.

Provides an atomic macro-action that cascades across 4 protocol layers:
1. ZTNA Firewall: Imposes strict Default-Deny on all unprompted inbound traffic.
2. DHT / Locators: Mutes public listener announcements (Zero-PII / Egress-Only).
3. Sphinx Onion Routing: Mandates 3-hop fixed 1280-byte framing for outbound flows.
4. Traffic Pacer: Activates micro-jitter to defeat temporal flow-correlation analysis.
"""

from __future__ import annotations
import time
import threading
from enum import Enum
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..security.firewall import ZTNAFirewall
    from ..network.onion import SphinxRouter
    from ..network.pacer import DWRRScheduler


class OperatingMode(str, Enum):
    STANDARD_MESH = "STANDARD_MESH"
    DARK_NODE_EGRESS_ONLY = "DARK_NODE_EGRESS_ONLY"


class DarkNodeMacroOrchestrator:
    """
    Atomic Macro-Orchestrator for Dark Node and Stealth Operations.
    Coordinates ZTNA, Onion, DHT announcement, and Pacer without restarts.
    """

    def __init__(
        self,
        firewall: Optional[ZTNAFirewall] = None,
        sphinx_router: Optional[SphinxRouter] = None,
        scheduler: Optional[DWRRScheduler] = None,
    ):
        self.firewall = firewall
        self.sphinx_router = sphinx_router
        self.scheduler = scheduler

        self.current_mode: OperatingMode = OperatingMode.STANDARD_MESH
        self.listeners_muted: bool = False
        self.sphinx_mandatory: bool = False
        self.active_hops: int = 0
        self.micro_jitter_active: bool = False

        self.transitions_count: int = 0
        self.last_transition: float = time.time()
        self._lock = threading.Lock()

    def toggle_mode(self) -> OperatingMode:
        """Toggles atomically between Standard Mesh and Dark Node Egress-Only mode."""
        with self._lock:
            target = (
                OperatingMode.DARK_NODE_EGRESS_ONLY
                if self.current_mode == OperatingMode.STANDARD_MESH
                else OperatingMode.STANDARD_MESH
            )
            self._apply_transition_locked(target)
            return self.current_mode

    def set_mode(self, target: OperatingMode) -> None:
        """Sets explicit operating mode."""
        with self._lock:
            if self.current_mode != target:
                self._apply_transition_locked(target)

    def _apply_transition_locked(self, target: OperatingMode) -> None:
        if target == OperatingMode.DARK_NODE_EGRESS_ONLY:
            # 1. ZTNA: Force default-deny
            if self.firewall is not None:
                self.firewall.default_deny = True

            # 2. DHT / Locators: Mute public listen announcements
            self.listeners_muted = True

            # 3. Sphinx Onion: Force mandatory 3-hop 1280-byte framing
            self.sphinx_mandatory = True
            self.active_hops = 3

            # 4. Pacer: Activate micro-jitter anti-correlation
            self.micro_jitter_active = True

            self.current_mode = OperatingMode.DARK_NODE_EGRESS_ONLY

        elif target == OperatingMode.STANDARD_MESH:
            # Revert to standard bidirectional mesh
            self.listeners_muted = False
            self.sphinx_mandatory = False
            self.active_hops = 0
            self.micro_jitter_active = False

            # Note: We keep firewall custom policies intact, only lifting global mute
            self.current_mode = OperatingMode.STANDARD_MESH

        self.transitions_count += 1
        self.last_transition = time.time()

    def is_dark_node(self) -> bool:
        """Returns True if node is currently in stealth dark node mode."""
        with self._lock:
            return self.current_mode == OperatingMode.DARK_NODE_EGRESS_ONLY

    def get_status(self) -> Dict[str, Any]:
        """Returns state and audit telemetry for the stealth orchestrator."""
        with self._lock:
            return {
                "operating_mode": self.current_mode.value,
                "is_stealth": self.current_mode == OperatingMode.DARK_NODE_EGRESS_ONLY,
                "listeners_muted": self.listeners_muted,
                "sphinx_mandatory": self.sphinx_mandatory,
                "active_hops": self.active_hops,
                "micro_jitter_active": self.micro_jitter_active,
                "transitions_count": self.transitions_count,
                "last_transition_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.last_transition)
                ),
            }
