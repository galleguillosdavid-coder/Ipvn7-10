"""
Geo-Distributed Policy Routing & Data Sovereignty Enclave Subsystem.
IPVN 7 Network Layer (L2).

Selects optimal next-hops combining:
1. Physical geodesic distance (Haversine formula on sphere + LEO altitude).
2. Real measured EWMA round-trip latency and packet loss.
3. Transitive Web of Trust reputation scores.
4. Data sovereignty enclaves and regulatory geofencing (e.g. EU-GDPR, MERCOSUR, ORBITAL).
"""

from __future__ import annotations
import enum
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

EARTH_RADIUS_KM = 6371.0


class GeoRegion(enum.Enum):
    LATAM_SANTIAGO = "LATAM_SANTIAGO"
    LATAM_SAO_PAULO = "LATAM_SAO_PAULO"
    NA_VIRGINIA = "NA_VIRGINIA"
    NA_CALIFORNIA = "NA_CALIFORNIA"
    EU_FRANKFURT = "EU_FRANKFURT"
    EU_IRELAND = "EU_IRELAND"
    APAC_TOKYO = "APAC_TOKYO"
    APAC_SINGAPORE = "APAC_SINGAPORE"
    ORBITAL_LEO_1 = "ORBITAL_LEO_1"
    ORBITAL_LEO_2 = "ORBITAL_LEO_2"


class RoutingPolicyMode(enum.Enum):
    MIN_LATENCY = "MIN_LATENCY"
    MAX_TRUST = "MAX_TRUST"
    SOVEREIGNTY_STRICT = "SOVEREIGNTY_STRICT"
    BALANCED = "BALANCED"


@dataclass
class GeoNodeDescriptor:
    node_did: str
    region: GeoRegion
    latitude: float
    longitude: float
    altitude_km: float = 0.0
    measured_rtt_ms: float = 20.0
    wot_trust_score: float = 1.0  # 0.0 to 1.0
    sovereignty_enclaves: List[str] = field(default_factory=list)
    packet_loss_ratio: float = 0.0
    is_online: bool = True


@dataclass
class RouteSelectionDecision:
    selected_node_did: str
    target_did: str
    policy_mode: RoutingPolicyMode
    geodesic_distance_km: float
    effective_cost: float
    measured_rtt_ms: float
    trust_score: float
    sovereignty_compliant: bool
    candidate_count_evaluated: int
    rejection_reasons: Dict[str, str] = field(default_factory=dict)


class GeoPolicyRouter:
    """
    Evaluates multi-attribute path selection across planetary and terrestrial nodes.
    Enforces geopolitical boundaries and jurisdictional sovereignty constraints.
    """

    def __init__(self, local_did: str, local_latitude: float = -33.4489, local_longitude: float = -70.6693):
        # Default origin: Santiago, Chile
        self.local_did = local_did
        self.local_latitude = local_latitude
        self.local_longitude = local_longitude
        self.nodes: Dict[str, GeoNodeDescriptor] = {}
        self.total_routing_decisions = 0

    def register_node(self, descriptor: GeoNodeDescriptor) -> None:
        """Registers or updates a known node's geo coordinates and telemetry."""
        self.nodes[descriptor.node_did] = descriptor

    def compute_distance_km(self, lat1: float, lon1: float, alt1: float, lat2: float, lon2: float, alt2: float) -> float:
        """Computes 3D geodesic distance taking Earth curvature and orbital altitude into account."""
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        # Haversine on mean sphere
        a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        surface_dist = EARTH_RADIUS_KM * c

        # Altitude differential Pythagoras extension
        delta_alt = alt2 - alt1
        return math.sqrt(surface_dist ** 2 + delta_alt ** 2)

    def select_optimal_route(
        self,
        target_did: str,
        policy_mode: RoutingPolicyMode = RoutingPolicyMode.BALANCED,
        required_enclave: Optional[str] = None,
        excluded_regions: Optional[List[GeoRegion]] = None,
        max_acceptable_rtt_ms: float = 350.0,
        min_trust_score: float = 0.5,
    ) -> RouteSelectionDecision:
        """Selects the single best next-hop complying with geo-policy constraints."""
        excluded_regions = excluded_regions or []
        rejections: Dict[str, str] = {}
        candidates: List[Tuple[float, GeoNodeDescriptor, float]] = []

        for did, node in self.nodes.items():
            if not node.is_online:
                rejections[did] = "NODE_OFFLINE"
                continue

            if node.region in excluded_regions:
                rejections[did] = f"REGION_EXCLUDED:{node.region.value}"
                continue

            if required_enclave and required_enclave not in node.sovereignty_enclaves:
                rejections[did] = f"MISSING_REQUIRED_ENCLAVE:{required_enclave}"
                continue

            if node.measured_rtt_ms > max_acceptable_rtt_ms:
                rejections[did] = f"RTT_EXCEEDED:{node.measured_rtt_ms:.1f}ms > {max_acceptable_rtt_ms:.1f}ms"
                continue

            if node.wot_trust_score < min_trust_score:
                rejections[did] = f"INSUFFICIENT_TRUST:{node.wot_trust_score:.2f} < {min_trust_score:.2f}"
                continue

            dist_km = self.compute_distance_km(
                self.local_latitude,
                self.local_longitude,
                0.0,
                node.latitude,
                node.longitude,
                node.altitude_km,
            )

            # Compute normalized cost based on policy mode
            if policy_mode == RoutingPolicyMode.MIN_LATENCY:
                cost = (node.measured_rtt_ms * 0.7) + (dist_km * 0.005) + (node.packet_loss_ratio * 100.0)
            elif policy_mode == RoutingPolicyMode.MAX_TRUST:
                cost = (1.0 - node.wot_trust_score) * 200.0 + (node.measured_rtt_ms * 0.2)
            elif policy_mode == RoutingPolicyMode.SOVEREIGNTY_STRICT:
                # Prioritize enclaves matched and penalize cross-border distance
                cost = (dist_km * 0.01) + (node.measured_rtt_ms * 0.3) - (len(node.sovereignty_enclaves) * 10.0)
            else:  # BALANCED
                cost = (node.measured_rtt_ms * 0.4) + (dist_km * 0.004) + ((1.0 - node.wot_trust_score) * 50.0)

            candidates.append((cost, node, dist_km))

        if not candidates:
            raise LookupError(f"No viable route candidates satisfying geo-policy constraints. Rejections: {rejections}")

        # Sort by lowest cost
        candidates.sort(key=lambda item: item[0])
        best_cost, best_node, best_dist = candidates[0]

        self.total_routing_decisions += 1
        return RouteSelectionDecision(
            selected_node_did=best_node.node_did,
            target_did=target_did,
            policy_mode=policy_mode,
            geodesic_distance_km=round(best_dist, 2),
            effective_cost=round(best_cost, 2),
            measured_rtt_ms=best_node.measured_rtt_ms,
            trust_score=best_node.wot_trust_score,
            sovereignty_compliant=True,
            candidate_count_evaluated=len(self.nodes),
            rejection_reasons=rejections,
        )

    def populate_default_planetary_topology(self) -> None:
        """Initializes standard multi-region sovereign nodes for realistic testing."""
        self.register_node(GeoNodeDescriptor(
            node_did="did:ipvn7:geo:santiago",
            region=GeoRegion.LATAM_SANTIAGO,
            latitude=-33.4489,
            longitude=-70.6693,
            measured_rtt_ms=4.2,
            wot_trust_score=0.98,
            sovereignty_enclaves=["MERCOSUR", "LATAM_SOVEREIGN"],
        ))
        self.register_node(GeoNodeDescriptor(
            node_did="did:ipvn7:geo:saopaulo",
            region=GeoRegion.LATAM_SAO_PAULO,
            latitude=-23.5505,
            longitude=-46.6333,
            measured_rtt_ms=38.5,
            wot_trust_score=0.92,
            sovereignty_enclaves=["MERCOSUR", "LATAM_SOVEREIGN"],
        ))
        self.register_node(GeoNodeDescriptor(
            node_did="did:ipvn7:geo:frankfurt",
            region=GeoRegion.EU_FRANKFURT,
            latitude=50.1109,
            longitude=8.6821,
            measured_rtt_ms=175.0,
            wot_trust_score=0.88,
            sovereignty_enclaves=["EU_GDPR", "EUROPEAN_UNION"],
        ))
        self.register_node(GeoNodeDescriptor(
            node_did="did:ipvn7:geo:virginia",
            region=GeoRegion.NA_VIRGINIA,
            latitude=37.4316,
            longitude=-78.6569,
            measured_rtt_ms=115.0,
            wot_trust_score=0.85,
            sovereignty_enclaves=["US_FEDERAL", "NA_ZONE"],
        ))
        self.register_node(GeoNodeDescriptor(
            node_did="did:ipvn7:geo:tokyo",
            region=GeoRegion.APAC_TOKYO,
            latitude=35.6762,
            longitude=139.6503,
            measured_rtt_ms=240.0,
            wot_trust_score=0.90,
            sovereignty_enclaves=["APAC_ENCLAVE"],
        ))
        self.register_node(GeoNodeDescriptor(
            node_did="did:ipvn7:geo:orbital-leo1",
            region=GeoRegion.ORBITAL_LEO_1,
            latitude=0.0,
            longitude=-60.0,
            altitude_km=550.0,
            measured_rtt_ms=45.0,
            wot_trust_score=0.95,
            sovereignty_enclaves=["ORBITAL_COMMONS", "LATAM_SOVEREIGN"],
        ))

    def get_summary(self) -> Dict[str, Any]:
        """Provides operational diagnostics and table summary."""
        return {
            "total_nodes_registered": len(self.nodes),
            "online_nodes": sum(1 for n in self.nodes.values() if n.is_online),
            "total_routing_decisions": self.total_routing_decisions,
            "origin_coordinates": {
                "latitude": self.local_latitude,
                "longitude": self.local_longitude,
            },
            "registered_regions": list(set(n.region.value for n in self.nodes.values())),
        }
