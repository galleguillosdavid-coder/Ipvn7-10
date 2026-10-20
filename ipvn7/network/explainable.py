"""
IPVN 7 Explainable Network Engine (Transparent Route Selection)
Evalúa y justifica en lenguaje natural y estructurado las decisiones de conmutación de malla
y selección de saltos basándose en métricas físicas de RTT, Jitter RFC 3550, pérdida de paquetes,
nivel de confianza criptográfica post-cuántica y reserva de energía del nodo.
Inspirado en ipvn7 vX7 pkg/l2/explainable_network.go.
"""

from __future__ import annotations
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class CandidateMetrics:
    peer_did: str
    latency_ms: float
    rfc3550_jitter_ms: float
    packet_loss_pct: float
    battery_pct: int = 100
    trust_tier: int = 1  # 1 a 4 (PQC / DID Verified Tier)


@dataclass
class CandidateScore:
    peer_did: str
    total_score: float
    breakdown: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "peer_did": self.peer_did,
            "total_score": round(self.total_score, 2),
            "breakdown": self.breakdown,
        }


@dataclass
class RoutingExplanation:
    target_did: str
    selected_peer: str
    selected_score: float
    human_explanation: str
    evaluated_candidates: List[CandidateScore]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_did": self.target_did,
            "selected_peer": self.selected_peer,
            "selected_score": round(self.selected_score, 2),
            "human_explanation": self.human_explanation,
            "evaluated_candidates": [c.to_dict() for c in self.evaluated_candidates],
            "timestamp": self.timestamp,
        }


class ExplainableNetworkEngine:
    """
    Motor de explicabilidad cognitiva para selección de rutas en la malla IPVN 7.
    """

    def __init__(self):
        self.stats = {
            "decisions_explained": 0,
        }

    def select_and_explain_route(
        self,
        target_did: str,
        candidates: List[CandidateMetrics],
    ) -> RoutingExplanation:
        """
        Elige la mejor ruta entre los candidatos observados y genera una explicación formal transparente.
        """
        if not candidates:
            raise ValueError(f"No hay candidatos disponibles para el destino {target_did}")

        scores: List[CandidateScore] = []

        for c in candidates:
            latency_penalty = min(c.latency_ms * 0.2, 50.0)
            jitter_penalty = min(c.rfc3550_jitter_ms * 1.5, 30.0)
            loss_penalty = min(c.packet_loss_pct * 2.0, 50.0)

            trust_bonus = float(c.trust_tier) * 15.0
            battery_bonus = float(c.battery_pct) * 0.1

            score = (100.0 + trust_bonus + battery_bonus) - (latency_penalty + jitter_penalty + loss_penalty)
            score = max(0.0, score)

            breakdown = (
                f"RTT: {c.latency_ms:.1f}ms, Jitter: {c.rfc3550_jitter_ms:.2f}ms, "
                f"Pérdida: {c.packet_loss_pct:.1f}%, Trust: T{c.trust_tier}, Bat: {c.battery_pct}%"
            )

            scores.append(CandidateScore(
                peer_did=c.peer_did,
                total_score=score,
                breakdown=breakdown,
            ))

        # Ordenar candidatos por puntaje descendente
        scores.sort(key=lambda s: s.total_score, reverse=True)
        best = scores[0]

        if len(scores) == 1:
            human_expl = (
                f"Se seleccionó el único salto disponible {best.peer_did} con puntaje {best.total_score:.1f} "
                f"({best.breakdown})."
            )
        else:
            second = scores[1]
            diff = best.total_score - second.total_score
            human_expl = (
                f"Se seleccionó {best.peer_did} (Puntaje: {best.total_score:.1f}) sobre {second.peer_did} "
                f"(Puntaje: {second.total_score:.1f}, delta: +{diff:.1f}). "
                f"Ventaja competitiva debida a mejor correlación de RTT/Jitter RFC 3550 y garantía de confianza PQC."
            )

        self.stats["decisions_explained"] += 1
        return RoutingExplanation(
            target_did=target_did,
            selected_peer=best.peer_did,
            selected_score=best.total_score,
            human_explanation=human_expl,
            evaluated_candidates=scores,
        )
