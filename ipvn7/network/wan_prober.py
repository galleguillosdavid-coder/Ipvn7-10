"""
Active WAN Prober & Quality Telemetry Engine.
Rescued from 0.7/src/pkg/l1/wan_active_prober.go.

Performs active, low-overhead RTT probing using canonical 32-byte binary wire frames
(Magic 0x49503750 'IP7P'), tracking RFC 3550 jitter, min/max latency, and consecutive losses
to feed predictive link healing.
"""

from __future__ import annotations
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

PROBE_MAGIC = 0x49503750  # "IP7P"
PROBE_WIRE_SIZE = 32


@dataclass
class PeerProbeStats:
    did: str
    endpoint: str
    last_rtt_ms: float = 0.0
    min_rtt_ms: float = 9999.0
    max_rtt_ms: float = 0.0
    jitter_ms: float = 0.0
    probes_sent: int = 0
    probes_recv: int = 0
    probes_lost: int = 0
    consecutive_losses: int = 0
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        loss_pct = (self.probes_lost / self.probes_sent * 100.0) if self.probes_sent > 0 else 0.0
        return {
            "did": self.did,
            "endpoint": self.endpoint,
            "last_rtt_ms": round(self.last_rtt_ms, 2),
            "min_rtt_ms": round(self.min_rtt_ms, 2) if self.min_rtt_ms < 9990 else 0.0,
            "max_rtt_ms": round(self.max_rtt_ms, 2),
            "jitter_ms": round(self.jitter_ms, 3),
            "probes_sent": self.probes_sent,
            "probes_recv": self.probes_recv,
            "probes_lost": self.probes_lost,
            "loss_pct": round(loss_pct, 1),
            "consecutive_losses": self.consecutive_losses,
            "last_updated": self.last_updated,
        }


class WANActiveProber:
    """
    Orchestrates continuous background or on-demand active probing of WAN overlay links.
    """

    def __init__(self):
        self._stats: Dict[str, PeerProbeStats] = {}  # key: peer_did
        self._seq_counter = 0

    def build_probe_packet(self, seq: Optional[int] = None) -> Tuple[int, bytes]:
        """Encodes canonical 32-byte binary probe datagram."""
        if seq is None:
            self._seq_counter += 1
            seq = self._seq_counter

        now_ns = time.time_ns()
        # Wire layout: Magic (4B), Sequence (4B), TimestampNs (8B), Padding (16B)
        payload = struct.pack(">IIQ16s", PROBE_MAGIC, seq, now_ns, b"\x00" * 16)
        return seq, payload

    def parse_probe_packet(self, data: bytes) -> Optional[Tuple[int, int]]:
        """Parses probe frame returning (sequence, timestamp_ns) or None if invalid."""
        if len(data) < PROBE_WIRE_SIZE:
            return None
        magic, seq, sent_ns, _ = struct.unpack(">IIQ16s", data[:PROBE_WIRE_SIZE])
        if magic != PROBE_MAGIC:
            return None
        return seq, sent_ns

    def record_probe_dispatch(self, peer_did: str, endpoint: str) -> PeerProbeStats:
        """Registers an outbound probe dispatch."""
        if peer_did not in self._stats:
            self._stats[peer_did] = PeerProbeStats(did=peer_did, endpoint=endpoint)
        st = self._stats[peer_did]
        st.endpoint = endpoint
        st.probes_sent += 1
        st.last_updated = time.time()
        return st

    def record_probe_response(self, peer_did: str, rtt_ms: float) -> PeerProbeStats:
        """Records successful round-trip probe response and computes RFC 3550 jitter."""
        if peer_did not in self._stats:
            self._stats[peer_did] = PeerProbeStats(did=peer_did, endpoint="127.0.0.1")
        st = self._stats[peer_did]
        st.probes_recv += 1
        st.consecutive_losses = 0

        # Jitter RFC 3550: J = J + (|D(i-1, i)| - J) / 16
        if st.last_rtt_ms > 0:
            diff = abs(rtt_ms - st.last_rtt_ms)
            st.jitter_ms += (diff - st.jitter_ms) / 16.0

        st.last_rtt_ms = rtt_ms
        if rtt_ms < st.min_rtt_ms:
            st.min_rtt_ms = rtt_ms
        if rtt_ms > st.max_rtt_ms:
            st.max_rtt_ms = rtt_ms
        st.last_updated = time.time()
        return st

    def record_probe_loss(self, peer_did: str) -> PeerProbeStats:
        """Records probe loss or timeout."""
        if peer_did not in self._stats:
            self._stats[peer_did] = PeerProbeStats(did=peer_did, endpoint="127.0.0.1")
        st = self._stats[peer_did]
        st.probes_lost += 1
        st.consecutive_losses += 1
        st.last_updated = time.time()
        return st

    def get_peer_stats(self, peer_did: str) -> Optional[dict]:
        st = self._stats.get(peer_did)
        return st.to_dict() if st else None

    def get_summary(self) -> dict:
        peers_list = [s.to_dict() for s in self._stats.values()]
        total_sent = sum(s.probes_sent for s in self._stats.values())
        total_recv = sum(s.probes_recv for s in self._stats.values())
        total_lost = sum(s.probes_lost for s in self._stats.values())
        avg_loss = (total_lost / total_sent * 100.0) if total_sent > 0 else 0.0

        return {
            "probed_peers_count": len(self._stats),
            "total_probes_sent": total_sent,
            "total_probes_recv": total_recv,
            "total_probes_lost": total_lost,
            "network_loss_pct": round(avg_loss, 2),
            "peers": peers_list,
        }
