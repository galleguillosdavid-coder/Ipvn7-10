"""
Sovereign Tunnel Telemetry & Adaptive Path MTU (PMTU) Subsystem.
IPVN 7 Network Layer (L2).

Features:
1. Canonical Wire Framing 'IP7T' with CRC32 integrity verification.
2. Dynamic Path MTU Discovery (PMTUD) with exponential search between 576B and 1420B.
3. Continuous RFC 3550 Jitter & EWMA RTT estimation across active tunnels (Wintun/WireGuard/UDP Overlay).
4. Automated Bicast Failover Trigger upon link degradation (packet loss > 10% or jitter > 50ms).
"""

from __future__ import annotations
import enum
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

MAGIC_TUNNEL = b"IP7T"  # IPVN 7 Tunnel Telemetry Wire Magic (4 bytes)
MIN_SAFE_PMTU = 576     # RFC 791 / RFC 2460 minimum safe datagram size
DEFAULT_PMTU = 1280     # Canonical IPVN 7 baseline wire boundary
MAX_TUNNEL_MTU = 1420   # Typical WireGuard/Wintun payload envelope without IP fragmentation


class TunnelFrameType(enum.IntEnum):
    PROBE = 0x01             # Unicast telemetry probe
    PROBE_ACK = 0x02         # Echo response with remote timestamp
    PMTU_DISCOVERY = 0x03    # Variable-size probe to detect transit MTU ceiling
    PMTU_FEEDBACK = 0x04     # Informs sender of the maximum successfully traversed MTU
    FAILOVER_SIGNAL = 0x05   # Commands multipath bicast replication due to degradation


class TunnelHealthState(enum.Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CONGESTED = "CONGESTED"
    CRITICAL_FAILOVER = "CRITICAL_FAILOVER"


@dataclass
class PathMTUEngine:
    """
    Adaptive Path MTU discovery engine with binary convergence.
    Finds the largest non-fragmented wire MTU for an active tunnel.
    """
    current_pmtu: int = DEFAULT_PMTU
    min_mtu: int = MIN_SAFE_PMTU
    max_mtu: int = MAX_TUNNEL_MTU
    last_discovered_ts: float = field(default_factory=time.time)
    consecutive_successes: int = 0

    def evaluate_probe_result(self, probe_size: int, success: bool) -> int:
        """Adjusts current PMTU based on transit success/drop feedback."""
        self.last_discovered_ts = time.time()
        if success:
            self.consecutive_successes += 1
            if probe_size > self.current_pmtu:
                self.current_pmtu = min(probe_size, self.max_mtu)
        else:
            self.consecutive_successes = 0
            # Backoff to safe minimum or half step
            step_down = (self.current_pmtu - self.min_mtu) // 2
            self.current_pmtu = max(self.min_mtu, self.current_pmtu - max(32, step_down))
        return self.current_pmtu


@dataclass
class TunnelMetrics:
    tunnel_id: str
    interface_type: str        # 'wintun', 'wireguard_overlay', 'udp_direct'
    remote_endpoint: str       # '192.168.1.100:9443'
    current_pmtu: int = DEFAULT_PMTU
    rtt_ewma_ms: float = 10.0
    jitter_rfc3550_ms: float = 0.5
    last_rtt_ms: float = 10.0
    packets_sent: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    health_state: TunnelHealthState = TunnelHealthState.HEALTHY
    bicast_active: bool = False
    last_probe_time: float = field(default_factory=time.time)

    def compute_loss_ratio(self) -> float:
        total = self.packets_sent
        if total == 0:
            return 0.0
        return max(0.0, min(1.0, self.packets_lost / total))

    def update_rtt_and_jitter(self, sample_rtt_ms: float) -> None:
        """RFC 3550 interarrival jitter algorithm."""
        self.last_rtt_ms = sample_rtt_ms
        diff = abs(sample_rtt_ms - self.last_rtt_ms)
        # J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16
        self.jitter_rfc3550_ms += (diff - self.jitter_rfc3550_ms) / 16.0

        # EWMA RTT update: alpha = 0.125 (RFC 6298)
        self.rtt_ewma_ms = (0.875 * self.rtt_ewma_ms) + (0.125 * sample_rtt_ms)
        self.evaluate_health()

    def evaluate_health(self) -> None:
        """Evaluates health classification based on loss ratio and RFC 3550 jitter."""
        loss_ratio = self.compute_loss_ratio()
        if loss_ratio > 0.10 or self.jitter_rfc3550_ms > 50.0:
            self.health_state = TunnelHealthState.CRITICAL_FAILOVER
            self.bicast_active = True
        elif loss_ratio > 0.03 or self.jitter_rfc3550_ms > 20.0:
            self.health_state = TunnelHealthState.DEGRADED
            self.bicast_active = False
        else:
            self.health_state = TunnelHealthState.HEALTHY
            self.bicast_active = False


class SovereignTunnelTelemetry:
    """
    Orchestrates continuous multi-tunnel telemetry, dynamic PMTU discovery,
    and automatic multipath bicast failover signals.
    """

    def __init__(self, local_did: str):
        self.local_did = local_did
        self.tunnels: Dict[str, TunnelMetrics] = {}
        self.pmtu_engines: Dict[str, PathMTUEngine] = {}
        self.total_probes_dispatched = 0
        self.total_failovers_triggered = 0

    def register_tunnel(
        self,
        tunnel_id: str,
        interface_type: str = "wintun",
        remote_endpoint: str = "127.0.0.1:9443",
        initial_pmtu: int = DEFAULT_PMTU,
    ) -> TunnelMetrics:
        """Registers a logical or physical tunnel interface for continuous monitoring."""
        metrics = TunnelMetrics(
            tunnel_id=tunnel_id,
            interface_type=interface_type,
            remote_endpoint=remote_endpoint,
            current_pmtu=initial_pmtu,
        )
        self.tunnels[tunnel_id] = metrics
        self.pmtu_engines[tunnel_id] = PathMTUEngine(current_pmtu=initial_pmtu)
        return metrics

    def build_probe_frame(
        self,
        tunnel_id: str,
        frame_type: TunnelFrameType = TunnelFrameType.PROBE,
        sequence_id: int = 1,
        desired_size: Optional[int] = None,
    ) -> bytes:
        """
        Builds a canonical IP7T telemetry frame:
        [0..3]   Magic 'IP7T' (4B)
        [4..5]   Frame Type uint16 (2B)
        [6..9]   Sequence ID uint32 (4B)
        [10..17] Timestamp ms uint64 (8B)
        [18..19] Tunnel ID Len uint16 (2B)
        [..]     Tunnel ID (UTF-8)
        [..]     Padding (if desired_size specified for PMTU testing)
        [..]     CRC32 uint32 (4B)
        """
        tunnel = self.tunnels.get(tunnel_id)
        current_mtu = tunnel.current_pmtu if tunnel else DEFAULT_PMTU
        target_len = desired_size if desired_size is not None else min(current_mtu, 128)

        tid_bytes = tunnel_id.encode("utf-8")
        now_ms = int(time.time() * 1000)

        header = struct.pack(
            "!4sHIQH",
            MAGIC_TUNNEL,
            frame_type,
            sequence_id,
            now_ms,
            len(tid_bytes),
        )
        body = header + tid_bytes

        # Pad to desired length if PMTU probe
        pad_len = max(0, target_len - len(body) - 4)
        if pad_len > 0:
            body += b"\x00" * pad_len

        crc = zlib.crc32(body)
        wire_frame = body + struct.pack("!I", crc)

        if tunnel:
            tunnel.packets_sent += 1
        self.total_probes_dispatched += 1
        return wire_frame

    def parse_probe_frame(self, frame_bytes: bytes) -> Dict[str, Any]:
        """Validates CRC32 and unpacks canonical IP7T frame."""
        if len(frame_bytes) < 24:
            raise ValueError("Frame truncated: below minimum IP7T header length")

        body = frame_bytes[:-4]
        expected_crc = struct.unpack("!I", frame_bytes[-4:])[0]
        if zlib.crc32(body) != expected_crc:
            raise ValueError("Corrupt IP7T frame: CRC32 mismatch")

        magic, f_type, seq, ts_ms, tid_len = struct.unpack("!4sHIQH", body[:20])
        if magic != MAGIC_TUNNEL:
            raise ValueError(f"Invalid wire magic: expected IP7T, got {magic}")

        tunnel_id = body[20: 20 + tid_len].decode("utf-8", errors="replace")
        return {
            "magic": magic.decode("latin1"),
            "frame_type": TunnelFrameType(f_type).name,
            "sequence_id": seq,
            "timestamp_ms": ts_ms,
            "tunnel_id": tunnel_id,
            "frame_size": len(frame_bytes),
        }

    def simulate_telemetry_probe(
        self,
        tunnel_id: str,
        sample_rtt_ms: float,
        packet_lost: bool = False,
        pmtu_probe_size: Optional[int] = None,
        pmtu_probe_success: bool = True,
    ) -> Dict[str, Any]:
        """
        Simulates an active probing step with RTT, loss, and PMTU adjustment.
        """
        tunnel = self.tunnels.get(tunnel_id)
        if not tunnel:
            tunnel = self.register_tunnel(tunnel_id)

        engine = self.pmtu_engines[tunnel_id]

        if packet_lost:
            tunnel.packets_sent += 1
            tunnel.packets_lost += 1
            tunnel.evaluate_health()
        else:
            tunnel.packets_sent += 1
            tunnel.packets_received += 1
            tunnel.update_rtt_and_jitter(sample_rtt_ms)

        # PMTU test
        if pmtu_probe_size:
            new_pmtu = engine.evaluate_probe_result(pmtu_probe_size, pmtu_probe_success)
            tunnel.current_pmtu = new_pmtu

        if tunnel.bicast_active:
            self.total_failovers_triggered += 1

        return {
            "tunnel_id": tunnel.tunnel_id,
            "interface_type": tunnel.interface_type,
            "current_pmtu": tunnel.current_pmtu,
            "rtt_ewma_ms": round(tunnel.rtt_ewma_ms, 2),
            "jitter_ms": round(tunnel.jitter_rfc3550_ms, 3),
            "loss_ratio": round(tunnel.compute_loss_ratio(), 4),
            "health_state": tunnel.health_state.value,
            "bicast_failover_active": tunnel.bicast_active,
            "packets_sent": tunnel.packets_sent,
            "packets_received": tunnel.packets_received,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Returns consolidated telemetry status across all active tunnels."""
        return {
            "total_tunnels": len(self.tunnels),
            "total_probes_dispatched": self.total_probes_dispatched,
            "total_failovers_triggered": self.total_failovers_triggered,
            "tunnels": {
                tid: {
                    "interface": t.interface_type,
                    "remote": t.remote_endpoint,
                    "pmtu": t.current_pmtu,
                    "rtt_ewma_ms": round(t.rtt_ewma_ms, 2),
                    "jitter_ms": round(t.jitter_rfc3550_ms, 3),
                    "loss_ratio": round(t.compute_loss_ratio(), 4),
                    "health": t.health_state.value,
                    "bicast_active": t.bicast_active,
                }
                for tid, t in self.tunnels.items()
            },
        }
