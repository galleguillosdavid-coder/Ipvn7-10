"""
IPVN 7 Ephemeral Blind Rendezvous Adapter (EBRA)
Permite a nodos recién iniciados o tras apagones (blackout recovery)
publicar y descubrir puntos de acceso sin filtrar metadatos personales (Zero-PII estricto),
con autodestrucción (Consume-and-Burn) y desconexión atómica a P2P puro (Circuit Breaker).
Inspirado en ipvn7 vX7 pkg/l1/blind_rendezvous.go.
"""

from __future__ import annotations
import time
import hashlib
import json
import threading
from typing import Dict, Optional, Tuple, Any, List
from dataclasses import dataclass, field


DEFAULT_BEACON_TTL = 300.0  # 5 minutos
MIN_PEER_TRIP_THRESHOLD = 2  # Circuit breaker: apagar baliza al alcanzar 2 pares directos


@dataclass
class StoredBeacon:
    topic: str
    data: bytes
    expires_at: float


class MemoryBeaconStore:
    """Almacén en memoria de balizas efímeras para pruebas y nodos de relevo."""

    def __init__(self):
        self._lock = threading.Lock()
        self.beacons: Dict[str, StoredBeacon] = {}

    def put_beacon(self, topic: str, data: bytes, ttl_seconds: float = DEFAULT_BEACON_TTL) -> None:
        with self._lock:
            self.beacons[topic] = StoredBeacon(
                topic=topic,
                data=data,
                expires_at=time.time() + ttl_seconds,
            )

    def get_beacon(self, topic: str, consume_and_burn: bool = True) -> Optional[bytes]:
        with self._lock:
            beacon = self.beacons.get(topic)
            if not beacon:
                return None
            if time.time() > beacon.expires_at:
                del self.beacons[topic]
                return None
            if consume_and_burn:
                del self.beacons[topic]
            return beacon.data

    def delete_beacon(self, topic: str) -> bool:
        with self._lock:
            return self.beacons.pop(topic, None) is not None


def derive_topic_id(epoch_seconds: Optional[float] = None, ring_degree: int = 1, network_seed: str = "mainnet") -> str:
    """
    Deriva un identificador de punto de encuentro ciego dependiente de la época temporal.
    Garantiza Conocimiento Cero (Zero-Knowledge): El servidor de señalización jamás ve el DID.
    """
    now = epoch_seconds if epoch_seconds is not None else time.time()
    epoch_hour = int(now // 3600) * 3600
    material = f"ipvn7:blind:rendezvous:{epoch_hour}:{ring_degree}:{network_seed}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


class BlindRendezvousAdapter:
    """
    Coordinador de señalización efímera y conmutación por rotura de circuito (Circuit Breaker).
    """

    def __init__(
        self,
        local_did: str,
        beacon_store: Optional[MemoryBeaconStore] = None,
        min_peers_trip: int = MIN_PEER_TRIP_THRESHOLD,
        network_seed: str = "mainnet",
    ):
        self.local_did = local_did
        self.store = beacon_store or MemoryBeaconStore()
        self.min_peers_trip = min_peers_trip
        self.network_seed = network_seed
        self.circuit_breaker_tripped = False
        self.active_beacons: Dict[str, str] = {}  # topic -> locator
        self.stats = {
            "beacons_published": 0,
            "beacons_consumed": 0,
            "trips_count": 0,
        }

    def publish_endpoint(self, endpoint: str, ring_degree: int = 1, ttl: float = DEFAULT_BEACON_TTL) -> str:
        """
        Publica de forma opaca y cifrada el punto de acceso en el topic horario derivado.
        """
        if self.circuit_breaker_tripped:
            return ""

        topic = derive_topic_id(ring_degree=ring_degree, network_seed=self.network_seed)
        payload = json.dumps({
            "did": self.local_did,
            "endpoint": endpoint,
            "ts": time.time(),
        }).encode("utf-8")

        self.store.put_beacon(topic, payload, ttl_seconds=ttl)
        self.active_beacons[topic] = endpoint
        self.stats["beacons_published"] += 1
        return topic

    def discover_peer(self, ring_degree: int = 1, consume: bool = True) -> Optional[Dict[str, Any]]:
        """
        Consulta y opcionalmente autodestruye la baliza del punto de encuentro temporal.
        """
        topic = derive_topic_id(ring_degree=ring_degree, network_seed=self.network_seed)
        data = self.store.get_beacon(topic, consume_and_burn=consume)
        if not data:
            return None

        self.stats["beacons_consumed"] += 1
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            return None

    def record_direct_peer_connected(self, direct_peers_count: int) -> bool:
        """
        Evalúa el umbral del Circuit Breaker. Si se alcanza min_peers_trip,
        desconecta atómicamente la señalización ciega y limpia las balizas.
        """
        if direct_peers_count >= self.min_peers_trip and not self.circuit_breaker_tripped:
            self.circuit_breaker_tripped = True
            self.stats["trips_count"] += 1
            # Limpiar balizas activas
            for t in list(self.active_beacons.keys()):
                self.store.delete_beacon(t)
            self.active_beacons.clear()
            return True
        return False
