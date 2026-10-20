"""
IPVN 7 Microservices Lifecycle Manager (Zero-RAM Footprint)
Manages lazy-instantiation, scope-isolation, and automatic idle pruning of overlay network services.
Inspired by ipvn7 vX7 pkg/l4/service_manager.go.
"""

from __future__ import annotations
import time
import threading
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, field


class ServiceState(Enum):
    DORMANT = "DORMANT" # On disk / not instantiated in memory (Zero RAM)
    ACTIVE = "ACTIVE"   # Loaded into memory and serving sessions
    PRUNED = "PRUNED"   # Reclaimed after idle timeout


class ServiceScope(Enum):
    LOCAL = "LOCAL"     # Available only to local loopback/host
    MESH = "MESH"       # Discoverable within neighborhood DHT peers
    GLOBAL = "GLOBAL"   # Publicly advertised across global Kleinberg backbone


@dataclass
class ServiceDescriptor:
    name: str
    scope: ServiceScope = ServiceScope.LOCAL
    state: ServiceState = ServiceState.DORMANT
    instantiated_at: Optional[float] = None
    last_active_at: Optional[float] = None
    active_sessions: int = 0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "scope": self.scope.value,
            "state": self.state.value,
            "instantiated_at": self.instantiated_at,
            "last_active_at": self.last_active_at,
            "active_sessions": self.active_sessions,
            "description": self.description,
        }


class ServiceLifecycleManager:
    """
    Orchestrates on-demand service loading and zero-footprint pruning.
    Prevents memory bloat on lightweight nodes, routers, and edge satellites.
    """

    def __init__(self, idle_timeout_seconds: float = 60.0):
        self._lock = threading.Lock()
        self.services: Dict[str, ServiceDescriptor] = {}
        self.idle_timeout = idle_timeout_seconds
        self.stats = {
            "instantiations": 0,
            "prunes_executed": 0,
        }

    def register_dormant_service(
        self,
        name: str,
        scope: ServiceScope = ServiceScope.LOCAL,
        description: str = "",
    ) -> ServiceDescriptor:
        """Declares a dormant service (0 RAM allocated)."""
        with self._lock:
            desc = ServiceDescriptor(
                name=name,
                scope=scope,
                state=ServiceState.DORMANT,
                description=description,
            )
            self.services[name] = desc
            return desc

    def request_service(self, name: str, scope: Optional[ServiceScope] = None) -> ServiceDescriptor:
        """Instantiates a service in RAM on demand."""
        with self._lock:
            if name not in self.services:
                # Register on the fly if not explicitly declared
                self.services[name] = ServiceDescriptor(name=name)

            svc = self.services[name]
            now = time.time()
            svc.state = ServiceState.ACTIVE
            if scope:
                svc.scope = scope
            svc.instantiated_at = now
            svc.last_active_at = now
            svc.active_sessions += 1
            self.stats["instantiations"] += 1
            return svc

    def touch_service(self, name: str) -> bool:
        """Heartbeats active service to prevent idle pruning."""
        with self._lock:
            svc = self.services.get(name)
            if svc and svc.state == ServiceState.ACTIVE:
                svc.last_active_at = time.time()
                return True
            return False

    def release_service(self, name: str) -> None:
        """Decrements active session count."""
        with self._lock:
            svc = self.services.get(name)
            if svc and svc.active_sessions > 0:
                svc.active_sessions -= 1

    def prune_idle_services(self, force: bool = False, now: Optional[float] = None) -> List[str]:
        """Reclaims memory of services with 0 sessions exceeding idle timeout or forced."""
        current_time = now if now is not None else time.time()
        pruned_names = []

        with self._lock:
            for name, svc in self.services.items():
                if svc.state == ServiceState.ACTIVE and svc.active_sessions == 0:
                    if force or (svc.last_active_at and (current_time - svc.last_active_at) >= self.idle_timeout):
                        svc.state = ServiceState.PRUNED
                        pruned_names.append(name)
                        self.stats["prunes_executed"] += 1

        return pruned_names

    def get_active_services(self) -> List[ServiceDescriptor]:
        """Returns descriptors of currently active (in RAM) services."""
        with self._lock:
            return [s for s in self.services.values() if s.state == ServiceState.ACTIVE]

    def list_services(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [s.to_dict() for s in self.services.values()]
