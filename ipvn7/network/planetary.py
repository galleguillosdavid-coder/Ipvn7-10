"""
IPVN 7 - Planetary Mesh & Kleinberg Small-World Overlay (r=2)
Rescued & ported from ipvn7  vX7/pkg/l2/planetary_mesh.go.

Implements Jon Kleinberg's Small-World navigation model over a 2D Euclidean grid:
- Local short links (grid adjacency d <= 1.05)
- Probabilistic power-law long links (P ~ d^-2)
- Decentralized greedy spatial routing in O(log^2 N) hops
- Relativistic latency estimation based on speed of light c = 299,792 km/s (500 km per grid unit)
"""

import math
import random
from typing import Dict, List, Optional, Tuple, Any

class Coordinates2D:
    def __init__(self, x: float, y: float):
        self.x = float(x)
        self.y = float(y)

    def distance(self, other: "Coordinates2D") -> float:
        dx = self.x - other.x
        dy = self.y - other.y
        return math.sqrt(dx * dx + dy * dy)

    def to_dict(self) -> Dict[str, float]:
        return {"x": round(self.x, 3), "y": round(self.y, 3)}


class PlanetaryNode:
    def __init__(self, node_id: str, did: str, coords: Coordinates2D):
        self.node_id = node_id
        self.did = did
        self.coords = coords
        self.short_links: List[str] = []
        self.long_links: List[str] = []
        self.is_online: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "did": self.did,
            "coords": self.coords.to_dict(),
            "short_links": list(self.short_links),
            "long_links": list(self.long_links),
            "is_online": self.is_online,
            "degree": len(self.short_links) + len(self.long_links),
        }


class PlanetaryMeshCluster:
    SPEED_OF_LIGHT_KMS = 299792.458  # km/s
    GRID_UNIT_KM = 500.0             # 1 grid unit = 500 km (typical LEO ISL distance)

    def __init__(self, node_count: int = 16, seed: int = 1337):
        if node_count < 4:
            raise ValueError("planetary_mesh: se requieren al menos 4 nodos para formar la malla")

        self.node_count = node_count
        self.dim = int(math.ceil(math.sqrt(node_count)))
        self.max_hops = self.dim * 4
        self.nodes: Dict[str, PlanetaryNode] = {}
        self.seed = seed
        self._rng = random.Random(seed)

        self._build_topology()

    def _build_topology(self):
        # 1. Instanciar nodos en una cuadrícula 2D
        idx = 0
        for x in range(self.dim):
            for y in range(self.dim):
                if idx >= self.node_count:
                    break
                node_id = f"sat-{idx:03d}"
                did = f"did:ipvn7:planet:{idx:03d}"
                self.nodes[node_id] = PlanetaryNode(node_id, did, Coordinates2D(x, y))
                idx += 1
            if idx >= self.node_count:
                break

        # 2. Enlaces locales de corto alcance (Short Links: adyacencia directa d <= 1.05)
        for nid, node in self.nodes.items():
            for other_id, other_node in self.nodes.items():
                if nid == other_id:
                    continue
                d = node.coords.distance(other_node.coords)
                if d <= 1.05:
                    node.short_links.append(other_id)

        # 3. Enlaces probabilísticos de largo alcance (Kleinberg Long Links con P ~ d^-2)
        for nid, node in self.nodes.items():
            candidates = []
            weights = []
            total_weight = 0.0

            for other_id, other_node in self.nodes.items():
                if nid == other_id:
                    continue
                d = node.coords.distance(other_node.coords)
                if d > 1.05:
                    prob = 1.0 / (d * d)
                    candidates.append(other_id)
                    weights.append(prob)
                    total_weight += prob

            if total_weight <= 0:
                continue

            num_shortcuts = min(2, len(candidates))
            for _ in range(num_shortcuts):
                thresh = self._rng.random() * total_weight
                acc = 0.0
                for cand_id, w in zip(candidates, weights):
                    acc += w
                    if acc >= thresh:
                        if cand_id not in node.long_links:
                            node.long_links.append(cand_id)
                        break

    def route_packet(self, src_id: str, dst_id: str) -> Dict[str, Any]:
        """
        Enruta un datagrama usando el algoritmo greedy descentralizado de Kleinberg.
        Retorna la ruta, el número de saltos, la distancia euclidiana total y la latencia calculada.
        """
        if src_id not in self.nodes or not self.nodes[src_id].is_online:
            raise KeyError(f"planetary_mesh: nodo origen {src_id} no encontrado o fuera de línea")
        if dst_id not in self.nodes or not self.nodes[dst_id].is_online:
            raise KeyError(f"planetary_mesh: nodo destino {dst_id} no encontrado o fuera de línea")

        dst_node = self.nodes[dst_id]
        current = self.nodes[src_id]
        path = [src_id]
        visited = {src_id}
        total_euclidean_distance = 0.0

        while len(path) < self.max_hops:
            if current.node_id == dst_id:
                latency_ms = (total_euclidean_distance * self.GRID_UNIT_KM / self.SPEED_OF_LIGHT_KMS) * 1000.0
                return {
                    "success": True,
                    "src": src_id,
                    "dst": dst_id,
                    "path": path,
                    "hops": len(path) - 1,
                    "distance_units": round(total_euclidean_distance, 3),
                    "distance_km": round(total_euclidean_distance * self.GRID_UNIT_KM, 2),
                    "estimated_latency_ms": round(latency_ms, 3),
                }

            best_next = None
            best_dist = current.coords.distance(dst_node.coords)

            all_neighbors = current.short_links + current.long_links
            for n_id in all_neighbors:
                neighbor = self.nodes.get(n_id)
                if not neighbor or not neighbor.is_online or n_id in visited:
                    continue
                d = neighbor.coords.distance(dst_node.coords)
                if d < best_dist:
                    best_dist = d
                    best_next = n_id

            if best_next is None:
                # Fallback adaptativo: elegir vecino no visitado que esté online
                for n_id in all_neighbors:
                    neighbor = self.nodes.get(n_id)
                    if neighbor and neighbor.is_online and n_id not in visited:
                        best_next = n_id
                        break

            if best_next is None:
                raise RuntimeError(f"planetary_mesh: destino inalcanzable tras agotar saltos de Kleinberg en {current.node_id}")

            hop_dist = current.coords.distance(self.nodes[best_next].coords)
            total_euclidean_distance += hop_dist
            visited.add(best_next)
            path.append(best_next)
            current = self.nodes[best_next]

        raise RuntimeError("planetary_mesh: superado límite máximo de saltos sin alcanzar destino")

    def simulate_failure(self, failure_ratio: float) -> int:
        """Desconecta aleatoriamente una fracción de nodos para probar resiliencia."""
        failed = 0
        for node in self.nodes.values():
            if self._rng.random() < failure_ratio:
                node.is_online = False
                failed += 1
        return failed

    def restore_all(self):
        """Restaura todos los nodos a estado online."""
        for node in self.nodes.values():
            node.is_online = True

    def get_mesh_metrics(self) -> Dict[str, Any]:
        """Calcula métricas globales de la malla."""
        online_count = sum(1 for n in self.nodes.values() if n.is_online)
        total_degree = sum(len(n.short_links) + len(n.long_links) for n in self.nodes.values())
        avg_degree = total_degree / len(self.nodes) if self.nodes else 0.0

        return {
            "node_count": len(self.nodes),
            "online_nodes": online_count,
            "offline_nodes": len(self.nodes) - online_count,
            "dimension": self.dim,
            "grid_unit_km": self.GRID_UNIT_KM,
            "average_degree": round(avg_degree, 2),
            "kleinberg_exponent": 2.0,
            "speed_of_light_kms": self.SPEED_OF_LIGHT_KMS,
        }

    def get_topology_snapshot(self) -> Dict[str, Any]:
        """
        Retorna la topología completa con coordenadas 2D de cuadrícula
        y proyección 3D esférica orbital para el visor de la Tierra en el Control Center.
        """
        nodes_data = []
        half_dim = max(1.0, (self.dim - 1) / 2.0)

        for n in self.nodes.values():
            # Mapeo a latitud [-72°, +72°] y longitud [-180°, +180°]
            lat = ((n.coords.y - half_dim) / half_dim) * (math.pi / 2.5)
            lon = ((n.coords.x - half_dim) / half_dim) * math.pi

            # Coordenadas cartesianas 3D en la esfera unitaria LEO (radio 1.05 con altitud de órbita)
            orbit_r = 1.08
            x3d = orbit_r * math.cos(lat) * math.cos(lon)
            y3d = orbit_r * math.sin(lat)
            z3d = orbit_r * math.cos(lat) * math.sin(lon)

            node_dict = n.to_dict()
            node_dict["geo"] = {
                "lat_deg": round(math.degrees(lat), 2),
                "lon_deg": round(math.degrees(lon), 2),
                "x3d": round(x3d, 4),
                "y3d": round(y3d, 4),
                "z3d": round(z3d, 4),
            }
            nodes_data.append(node_dict)

        return {
            "metrics": self.get_mesh_metrics(),
            "nodes": nodes_data,
        }
