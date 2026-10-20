"""
IPVN 7 Small-World Network Simulator & Massive Churn Resiliency Engine
Empirically models Kleinberg harmonic routing convergence and evaluates
routing recovery under sudden node failure (churn).
"""

from __future__ import annotations
import math
import random
import hashlib
from typing import Dict, List, Tuple, Set, Any
from dataclasses import dataclass

from ..network.dht import DHTNode, NodeLocator, DHTRoutingTier, xor_distance


@dataclass
class SimulationStats:
    total_nodes: int
    churn_ratio: float
    avg_hops_baseline: float
    avg_hops_post_churn: float
    delivery_success_baseline: float
    delivery_success_post_churn: float
    theoretical_kleinberg_bound: float


@dataclass
class StressSimulationStats:
    total_nodes: int
    churn_ratio: float
    packet_loss_rate: float
    min_latency_ms: float
    max_latency_ms: float
    avg_latency_ms: float
    jitter_ms: float
    delivery_success_under_stress: float
    recovered_via_multipath: int
    resilience_score: float

    def to_dict(self) -> dict:
        return {
            "total_nodes": self.total_nodes,
            "churn_ratio": self.churn_ratio,
            "packet_loss_rate": self.packet_loss_rate,
            "min_latency_ms": self.min_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "avg_latency_ms": self.avg_latency_ms,
            "jitter_ms": self.jitter_ms,
            "delivery_success_under_stress": self.delivery_success_under_stress,
            "recovered_via_multipath": self.recovered_via_multipath,
            "resilience_score": self.resilience_score,
        }


class SmallWorldChurnSimulator:
    """
    Simulates large-scale IPVN 7 DHT topologies with Kleinberg Small-World shortcuts.
    Evaluates greedy routing convergence and fault tolerance under churn.
    """

    def __init__(self, node_count: int = 100, shortcuts_per_node: int = 4, seed: int = 42):
        self.node_count = node_count
        self.shortcuts_per_node = shortcuts_per_node
        self.nodes: List[DHTNode] = []
        self.node_map: Dict[str, DHTNode] = {}
        self.routing_tables: Dict[str, List[str]] = {}  # did -> list of peer dids
        self.alive_nodes: Set[str] = set()
        self.rng = random.Random(seed)

        self._build_topology()

    def _build_topology(self) -> None:
        """Constructs ring lattice + harmonic long-range jump links."""
        # 1. Create nodes along a 1D lattice
        for i in range(self.node_count):
            did = f"did:ipvn7:sim_{i:04d}"
            loc = NodeLocator(ip=f"10.0.{i // 256}.{i % 256}", port=9443)
            node = DHTNode.from_did(did, locators=[loc], tier=DHTRoutingTier.TIER_2_PLANETARY)
            self.nodes.append(node)
            self.node_map[did] = node
            self.routing_tables[did] = []
            self.alive_nodes.add(did)

        # 2. Add local lattice neighbors (k=2 nearest)
        for i in range(self.node_count):
            cur_did = self.nodes[i].did
            left_did = self.nodes[(i - 1) % self.node_count].did
            right_did = self.nodes[(i + 1) % self.node_count].did
            self.routing_tables[cur_did].append(left_did)
            self.routing_tables[cur_did].append(right_did)

        # 3. Add Kleinberg harmonic shortcuts: P(u -> v) ~ 1 / dist(u, v)
        for i in range(self.node_count):
            cur_did = self.nodes[i].did
            candidates = [j for j in range(self.node_count) if j != i]
            distances = [min(abs(i - j), self.node_count - abs(i - j)) for j in candidates]
            # Weights proportional to 1 / distance
            weights = [1.0 / d for d in distances]
            total_w = sum(weights)
            probs = [w / total_w for w in weights]

            selected = self.rng.choices(candidates, weights=probs, k=self.shortcuts_per_node)
            for target_idx in selected:
                target_did = self.nodes[target_idx].did
                if target_did not in self.routing_tables[cur_did]:
                    self.routing_tables[cur_did].append(target_did)

    def route_greedy(self, src_did: str, dst_did: str, max_hops: int = 20) -> Tuple[bool, int]:
        """
        Greedy routing: each node forwards to the neighbor minimizing distance to target.
        """
        if src_did not in self.alive_nodes or dst_did not in self.alive_nodes:
            return False, 0
        if src_did == dst_did:
            return True, 0

        current = src_did
        hops = 0
        visited = {current}

        src_idx = int(src_did.split("_")[-1])
        dst_idx = int(dst_did.split("_")[-1])

        def lattice_dist(a_idx: int, b_idx: int) -> int:
            return min(abs(a_idx - b_idx), self.node_count - abs(a_idx - b_idx))

        while hops < max_hops:
            hops += 1
            cur_idx = int(current.split("_")[-1])
            best_neighbor = None
            best_dist = lattice_dist(cur_idx, dst_idx)

            for neighbor_did in self.routing_tables.get(current, []):
                if neighbor_did in self.alive_nodes and neighbor_did not in visited:
                    n_idx = int(neighbor_did.split("_")[-1])
                    d = lattice_dist(n_idx, dst_idx)
                    if d < best_dist:
                        best_dist = d
                        best_neighbor = neighbor_did

            if not best_neighbor:
                # Local minimum reached or disconnected
                return False, hops

            if best_neighbor == dst_did:
                return True, hops

            visited.add(best_neighbor)
            current = best_neighbor

        return False, hops

    def run_benchmark(self, sample_pairs: int = 100, churn_rate: float = 0.25) -> SimulationStats:
        """
        Runs baseline routing tests, injects massive churn, and measures routing degradation/healing.
        """
        # Baseline
        baseline_success = 0
        baseline_hops: List[int] = []

        all_dids = list(self.alive_nodes)
        for _ in range(sample_pairs):
            src, dst = self.rng.sample(all_dids, 2)
            ok, hops = self.route_greedy(src, dst)
            if ok:
                baseline_success += 1
                baseline_hops.append(hops)

        avg_baseline_hops = sum(baseline_hops) / len(baseline_hops) if baseline_hops else 0.0
        baseline_rate = (baseline_success / sample_pairs) * 100.0

        # Inject massive churn: kill churn_rate of nodes
        kill_count = int(len(all_dids) * churn_rate)
        killed = set(self.rng.sample(all_dids, kill_count))
        self.alive_nodes -= killed

        # Post-churn evaluation
        remaining_dids = list(self.alive_nodes)
        post_churn_success = 0
        post_churn_hops: List[int] = []

        for _ in range(sample_pairs):
            src, dst = self.rng.sample(remaining_dids, 2)
            ok, hops = self.route_greedy(src, dst)
            if ok:
                post_churn_success += 1
                post_churn_hops.append(hops)

        avg_post_churn_hops = sum(post_churn_hops) / len(post_churn_hops) if post_churn_hops else 0.0
        post_churn_rate = (post_churn_success / sample_pairs) * 100.0

        # Theoretical Kleinberg bound: c * (log N)^2
        c = 0.5
        theoretical_bound = c * (math.log2(self.node_count) ** 2)

        return SimulationStats(
            total_nodes=self.node_count,
            churn_ratio=churn_rate,
            avg_hops_baseline=round(avg_baseline_hops, 2),
            avg_hops_post_churn=round(avg_post_churn_hops, 2),
            delivery_success_baseline=round(baseline_rate, 2),
            delivery_success_post_churn=round(post_churn_rate, 2),
            theoretical_kleinberg_bound=round(theoretical_bound, 2),
        )

    def run_stress_benchmark(
        self,
        sample_pairs: int = 100,
        churn_rate: float = 0.20,
        packet_loss_rate: float = 0.10,
        min_latency_ms: float = 100.0,
        max_latency_ms: float = 2000.0,
    ) -> StressSimulationStats:
        """
        Executes stress benchmark simulating harsh adversarial network conditions:
        massive node churn + 5%-20% stochastic packet loss + 100ms-2000ms latency jitter.
        Evaluates multipath rerouting fallback to recover dropped packets.
        """
        all_dids = list(self.alive_nodes)
        kill_count = int(len(all_dids) * churn_rate)
        if kill_count > 0:
            killed = set(self.rng.sample(all_dids, kill_count))
            self.alive_nodes -= killed

        remaining_dids = list(self.alive_nodes)
        if len(remaining_dids) < 2:
            return StressSimulationStats(
                total_nodes=self.node_count,
                churn_ratio=churn_rate,
                packet_loss_rate=packet_loss_rate,
                min_latency_ms=min_latency_ms,
                max_latency_ms=max_latency_ms,
                avg_latency_ms=0.0,
                jitter_ms=0.0,
                delivery_success_under_stress=0.0,
                recovered_via_multipath=0,
                resilience_score=0.0,
            )

        success_count = 0
        multipath_recoveries = 0
        latencies: List[float] = []

        for _ in range(sample_pairs):
            src, dst = self.rng.sample(remaining_dids, 2)
            ok, hops = self.route_greedy(src, dst)
            if not ok:
                continue

            # Simulate physical link loss and jitter along each hop
            path_delivered = True
            path_latency = 0.0

            for _ in range(hops):
                hop_delay = self.rng.uniform(min_latency_ms, max_latency_ms)
                path_latency += hop_delay

                # Stochastic packet drop
                if self.rng.random() < packet_loss_rate:
                    # Multipath reroute retry attempt (bicast / alternate path)
                    if self.rng.random() > packet_loss_rate:
                        multipath_recoveries += 1
                        path_latency += hop_delay * 0.5  # reroute penalty
                    else:
                        path_delivered = False
                        break

            if path_delivered:
                success_count += 1
                latencies.append(path_latency)

        delivery_rate = (success_count / sample_pairs) * 100.0
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        jitter = (
            sum(abs(l - avg_lat) for l in latencies) / len(latencies)
            if latencies
            else 0.0
        )
        resilience = round(delivery_rate * (1.0 - (packet_loss_rate * 0.5)), 2)

        return StressSimulationStats(
            total_nodes=self.node_count,
            churn_ratio=churn_rate,
            packet_loss_rate=packet_loss_rate,
            min_latency_ms=min_latency_ms,
            max_latency_ms=max_latency_ms,
            avg_latency_ms=round(avg_lat, 2),
            jitter_ms=round(jitter, 2),
            delivery_success_under_stress=round(delivery_rate, 2),
            recovered_via_multipath=multipath_recoveries,
            resilience_score=resilience,
        )
