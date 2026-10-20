"""
IPVN 7 AI Network Copilot & Autonomous Self-Healing Engine
==========================================================
RFC-7001 Autonomous Diagnostics & Closed-Loop Healing (Dimension 11).

Key Features:
- Scans live mesh telemetry: latency spikes, ZTNA firewall drop floods,
  jitter spectral resonances, and RFC 2439 link flap dampening.
- Infers root causes and formulates structured CopilotDiagnosis with confidence scoring.
- Executes closed-loop auto-healing interventions:
  * BLOCK_DID: dynamically installs ZTNA drop policy for abusive DIDs.
  * FAILOVER_PATH: triggers link healing failover to healthy alternative peer.
  * TUNE_PACER: throttles egress rate to relieve bufferbloat.
"""

import time
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


class AnomalySeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class NetworkAnomaly:
    """Describes an incident observed by telemetry or security filters."""
    type: str  # e.g., "LATENCY_SPIKE", "UNAUTHORIZED_FLOOD", "SPECTRAL_RESONANCE", "LINK_FLAP_DAMPED"
    severity: AnomalySeverity
    description: str
    peer_did: str = ""
    value: float = 0.0
    threshold: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity.value,
            "description": self.description,
            "peer_did": self.peer_did,
            "value": self.value,
            "threshold": self.threshold,
            "timestamp": self.timestamp,
        }


@dataclass
class CopilotDiagnosis:
    """Diagnostic report and recommended/executed action formulated by Copilot."""
    root_cause: str
    recommended_fix: str
    action_type: str  # "BLOCK_DID", "FAILOVER_PATH", "TUNE_PACER", "NONE"
    action_target: str
    confidence_score: float  # 0.0 to 1.0
    model_used: str = "IPVN7-NeuralCopilot-v7.1"
    executed_action: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_cause": self.root_cause,
            "recommended_fix": self.recommended_fix,
            "action_type": self.action_type,
            "action_target": self.action_target,
            "confidence_score": self.confidence_score,
            "model_used": self.model_used,
            "executed_action": self.executed_action,
            "timestamp": self.timestamp,
        }


class AICopilotEngine:
    """
    Coordinates deep mesh observability, anomaly inference, and closed-loop auto-healing.
    """

    def __init__(self, firewall=None, link_healing=None, pacer=None, auto_healing: bool = True):
        self.firewall = firewall
        self.link_healing = link_healing
        self.pacer = pacer
        self.auto_healing = auto_healing
        self.history: List[CopilotDiagnosis] = []
        self.anomalies_detected: List[NetworkAnomaly] = []

        self.stats = {
            "scans_performed": 0,
            "anomalies_detected_total": 0,
            "diagnoses_generated": 0,
            "auto_healing_actions_executed": 0,
        }

    def detect_anomalies(
        self,
        latency_ms: float = 0.0,
        firewall_drops: int = 0,
        peer_did: str = "",
        spectral_entropy: float = 1.0,
        is_flap_damped: bool = False,
    ) -> List[NetworkAnomaly]:
        """
        Evaluates input telemetry against operational thresholds to detect anomalies.
        """
        self.stats["scans_performed"] += 1
        anomalies: List[NetworkAnomaly] = []
        now = time.time()

        # 1. Latency Spike Anomaly (> 50.0 ms)
        if latency_ms > 50.0:
            anomalies.append(NetworkAnomaly(
                type="LATENCY_SPIKE",
                severity=AnomalySeverity.WARNING if latency_ms < 150.0 else AnomalySeverity.CRITICAL,
                description=f"High latency spike detected on datapath: {latency_ms:.1f}ms (threshold: 50.0ms)",
                peer_did=peer_did,
                value=latency_ms,
                threshold=50.0,
                timestamp=now,
            ))

        # 2. ZTNA Drop Flood Anomaly (> 5 drops)
        if firewall_drops > 5:
            anomalies.append(NetworkAnomaly(
                type="UNAUTHORIZED_FLOOD",
                severity=AnomalySeverity.CRITICAL,
                description=f"Surge of unauthorized ingress packets discarded by ZTNA firewall: {firewall_drops} drops",
                peer_did=peer_did,
                value=float(firewall_drops),
                threshold=5.0,
                timestamp=now,
            ))

        # 3. Spectral Resonance Anomaly (entropy < 0.45 indicates strong periodic jitter/jamming)
        if 0.0 < spectral_entropy < 0.45:
            anomalies.append(NetworkAnomaly(
                type="SPECTRAL_RESONANCE",
                severity=AnomalySeverity.WARNING,
                description=f"Low spectral entropy ({spectral_entropy:.2f}) indicates micro-bursting or periodic jamming signature",
                peer_did=peer_did,
                value=spectral_entropy,
                threshold=0.45,
                timestamp=now,
            ))

        # 4. RFC 2439 Link Flap Damping Anomaly
        if is_flap_damped:
            anomalies.append(NetworkAnomaly(
                type="LINK_FLAP_DAMPED",
                severity=AnomalySeverity.CRITICAL,
                description=f"Link to peer {peer_did} repeatedly flapping; frozen in RFC 2439 hold-down penalty",
                peer_did=peer_did,
                value=1.0,
                threshold=0.0,
                timestamp=now,
            ))

        self.stats["anomalies_detected_total"] += len(anomalies)
        self.anomalies_detected.extend(anomalies)
        if len(self.anomalies_detected) > 100:
            self.anomalies_detected = self.anomalies_detected[-100:]

        return anomalies

    def diagnose_and_heal(self, anomalies: List[NetworkAnomaly]) -> List[CopilotDiagnosis]:
        """
        Formulates diagnostic assessments from detected anomalies and triggers auto-healing actions.
        """
        diagnoses: List[CopilotDiagnosis] = []

        for anomaly in anomalies:
            diagnosis: Optional[CopilotDiagnosis] = None

            if anomaly.type == "UNAUTHORIZED_FLOOD":
                diagnosis = CopilotDiagnosis(
                    root_cause=f"Brute-force probe or Sybil amplification flood originating from {anomaly.peer_did or 'unknown sender'}",
                    recommended_fix="Isolate abusive DID with ZTNA Default-Deny drop policy and zero ICMP feedback",
                    action_type="BLOCK_DID",
                    action_target=anomaly.peer_did,
                    confidence_score=0.96,
                )

            elif anomaly.type == "LATENCY_SPIKE":
                diagnosis = CopilotDiagnosis(
                    root_cause="Transient bufferbloat or upstream link congestion along primary path",
                    recommended_fix="Trigger failover to low-latency alternate neighbor and engage DWRR QoS scheduler",
                    action_type="FAILOVER_PATH",
                    action_target=anomaly.peer_did,
                    confidence_score=0.88,
                )

            elif anomaly.type == "LINK_FLAP_DAMPED":
                diagnosis = CopilotDiagnosis(
                    root_cause="Physical carrier flapping in Wi-Fi/mesh boundary exceeding RFC 2439 damping threshold",
                    recommended_fix="Migrate datapath traffic to secondary stable mesh peer immediately",
                    action_type="FAILOVER_PATH",
                    action_target=anomaly.peer_did,
                    confidence_score=0.95,
                )

            elif anomaly.type == "SPECTRAL_RESONANCE":
                diagnosis = CopilotDiagnosis(
                    root_cause="Harmonic traffic burst alignment causing periodic queue oscillation",
                    recommended_fix="Inject stochastic pacer micro-jitter and throttle bucket rate by 15%",
                    action_type="TUNE_PACER",
                    action_target="egress_pacer",
                    confidence_score=0.82,
                )

            if diagnosis:
                # Closed-Loop Auto-Healing Execution
                if self.auto_healing:
                    diagnosis.executed_action = self._execute_action(
                        diagnosis.action_type, diagnosis.action_target
                    )
                    if diagnosis.executed_action:
                        self.stats["auto_healing_actions_executed"] += 1

                diagnoses.append(diagnosis)
                self.history.append(diagnosis)
                self.stats["diagnoses_generated"] += 1

        if len(self.history) > 50:
            self.history = self.history[-50:]

        return diagnoses

    def _execute_action(self, action_type: str, action_target: str) -> bool:
        """Applies programmatic remediation to the active network stack."""
        try:
            if action_type == "BLOCK_DID" and action_target and self.firewall:
                # Add strict deny policy for target DID
                self.firewall.set_policy(
                    did=action_target,
                    allow_inbound=False,
                    allow_outbound=False,
                    allow_relay=False,
                )
                return True

            elif action_type == "FAILOVER_PATH" and self.link_healing:
                # Record link failure to force failover to alternative peer
                self.link_healing.record_probe(action_target, success=False, latency_ms=999.0)
                return True

            elif action_type == "TUNE_PACER" and self.pacer:
                # Adjust pacer rate limit down slightly to alleviate bufferbloat
                self.pacer.set_rate_limit(max(10, self.pacer.rate_limit_kbps - 20))
                return True

        except Exception:
            return False

        return False

    def get_summary(self) -> Dict[str, Any]:
        """Returns engine statistics and recent diagnostic history."""
        return {
            "auto_healing_enabled": self.auto_healing,
            "stats": self.stats,
            "recent_anomalies_count": len(self.anomalies_detected),
            "recent_diagnoses": [d.to_dict() for d in self.history[-10:]],
        }
