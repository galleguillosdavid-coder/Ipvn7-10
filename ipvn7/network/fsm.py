"""
Deterministic Node & Peer Lifecycle Finite State Machine (FSM).
Rescued from 0.7/src/pkg/interfaces/fsm.go.

Guarantees predictable, auditable state progressions between:
DISCONNECTED -> SYNCING -> VALIDATING -> ACTIVE, with QUARANTINED containment.
"""

from __future__ import annotations
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class NodeState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    SYNCING = "SYNCING"
    VALIDATING = "VALIDATING"
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"


class FSMEvent(str, Enum):
    NETWORK_SIGNAL = "NETWORK_SIGNAL"
    SYNC_COMPLETED = "SYNC_COMPLETED"
    DID_VERIFIED = "DID_VERIFIED"
    HEARTBEAT_LOST = "HEARTBEAT_LOST"
    SECURITY_THREAT = "SECURITY_THREAT"
    RESET = "RESET"


# Valid Transition Matrix: (CurrentState, Event) -> NextState
TRANSITION_MAP: Dict[Tuple[NodeState, FSMEvent], NodeState] = {
    (NodeState.DISCONNECTED, FSMEvent.NETWORK_SIGNAL): NodeState.SYNCING,
    (NodeState.SYNCING, FSMEvent.SYNC_COMPLETED): NodeState.VALIDATING,
    (NodeState.SYNCING, FSMEvent.HEARTBEAT_LOST): NodeState.DISCONNECTED,
    (NodeState.VALIDATING, FSMEvent.DID_VERIFIED): NodeState.ACTIVE,
    (NodeState.VALIDATING, FSMEvent.HEARTBEAT_LOST): NodeState.DISCONNECTED,
    (NodeState.VALIDATING, FSMEvent.SECURITY_THREAT): NodeState.QUARANTINED,
    (NodeState.ACTIVE, FSMEvent.HEARTBEAT_LOST): NodeState.DISCONNECTED,
    (NodeState.ACTIVE, FSMEvent.SECURITY_THREAT): NodeState.QUARANTINED,
    (NodeState.QUARANTINED, FSMEvent.RESET): NodeState.DISCONNECTED,
    (NodeState.ACTIVE, FSMEvent.RESET): NodeState.DISCONNECTED,
    (NodeState.SYNCING, FSMEvent.RESET): NodeState.DISCONNECTED,
    (NodeState.VALIDATING, FSMEvent.RESET): NodeState.DISCONNECTED,
}


StateTransitionHook = Callable[[NodeState, NodeState, FSMEvent, Any], None]


class DeterministicNodeFSM:
    """
    Deterministic Finite State Machine managing peer connection and node lifecycle.
    """

    def __init__(self, initial_state: NodeState = NodeState.DISCONNECTED):
        self._state: NodeState = initial_state
        self._hooks: List[StateTransitionHook] = []
        self._transition_history: List[Dict[str, Any]] = []

    @property
    def current_state(self) -> NodeState:
        return self._state

    def can_transition_to(self, event: FSMEvent) -> bool:
        return (self._state, event) in TRANSITION_MAP

    def trigger_event(self, event: FSMEvent, payload: Any = None) -> NodeState:
        """Triggers a state transition event. Raises ValueError if invalid."""
        key = (self._state, event)
        if key not in TRANSITION_MAP:
            raise ValueError(f"FSM Invalid Transition: No route from {self._state.value} via {event.value}")

        prev_state = self._state
        next_state = TRANSITION_MAP[key]
        self._state = next_state

        rec = {
            "from": prev_state.value,
            "to": next_state.value,
            "event": event.value,
            "timestamp": time.time(),
            "payload": str(payload) if payload is not None else None,
        }
        self._transition_history.append(rec)

        # Notify transition hooks
        for hook in self._hooks:
            try:
                hook(prev_state, next_state, event, payload)
            except Exception:
                pass

        return self._state

    def register_hook(self, hook: StateTransitionHook) -> None:
        """Subscribes an observer callback to state transitions."""
        self._hooks.append(hook)

    def get_summary(self) -> dict:
        return {
            "current_state": self._state.value,
            "total_transitions": len(self._transition_history),
            "recent_transitions": self._transition_history[-5:],
        }
