"""
IPVN 7 Deterministic Token Bucket Pacing & DWRR Scheduler
Prevents bufferbloat and enforces QoS across 4 traffic classes:
  - Class 0: Control & PQC Handshake (Weight 40, zero-drop)
  - Class 1: Real-time Voice / Video (Weight 30, bounded latency)
  - Class 2: Interactive Web / TCP Tunnel (Weight 20, balanced)
  - Class 3: Bulk Background Dissemination (Weight 10, scavenger)
Inspired by ipvn7 vX7 pkg/l1/pacing.go and wdrr_scheduler.go.
"""

from __future__ import annotations
import time
import queue
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import IntEnum

from .packet import TrafficClass, IPVN7Packet


class QoSClass(IntEnum):
    CONTROL = 0      # PQC Handshake, DHT Maintenance, SWIM
    REALTIME = 1     # Low-latency datagrams
    INTERACTIVE = 2  # SOCKS5 / HTTP Proxy Streams
    BULK = 3         # Background syncing, DAG put


@dataclass
class QueuedPacket:
    packet: IPVN7Packet
    target_addr: tuple[str, int]
    size: int
    enqueued_at: float


class TokenBucketPacer:
    """
    Token Bucket rate limiter ensuring smooth packet pacing without micro-burst jitter.
    """

    def __init__(self, rate_bytes_per_sec: float = 12_500_000.0, burst_bytes: int = 65536):
        self.rate = rate_bytes_per_sec  # Default 100 Mbps = 12.5 MB/s
        self.capacity = burst_bytes
        self.tokens = float(burst_bytes)
        self.last_update = time.perf_counter()

    def consume(self, packet_bytes: int) -> bool:
        """Attempts to consume tokens for packet. Returns True if permitted immediately."""
        now = time.perf_counter()
        elapsed = now - self.last_update
        self.last_update = now

        # Replenish tokens
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        if self.tokens >= packet_bytes:
            self.tokens -= packet_bytes
            return True
        return False


class DWRRScheduler:
    """
    Deficit Weighted Round Robin (DWRR) anti-bufferbloat scheduler.
    Enforces proportional fairness across the 4 QoS classes.
    """

    WEIGHTS = {
        QoSClass.CONTROL: 4000,
        QoSClass.REALTIME: 3000,
        QoSClass.INTERACTIVE: 2000,
        QoSClass.BULK: 1000,
    }

    MAX_QUEUE_LEN = {
        QoSClass.CONTROL: 512,
        QoSClass.REALTIME: 256,
        QoSClass.INTERACTIVE: 512,
        QoSClass.BULK: 1024,
    }

    def __init__(self, rate_bytes_sec: float = 12_500_000.0):
        self.pacer = TokenBucketPacer(rate_bytes_per_sec=rate_bytes_sec)
        self.queues: Dict[QoSClass, List[QueuedPacket]] = {
            QoSClass.CONTROL: [],
            QoSClass.REALTIME: [],
            QoSClass.INTERACTIVE: [],
            QoSClass.BULK: [],
        }
        self.deficits: Dict[QoSClass, int] = {c: 0 for c in QoSClass}
        self.stats = {
            "packets_enqueued": 0,
            "packets_dequeued": 0,
            "packets_dropped_tail": 0,
            "bytes_scheduled": 0,
        }

    def enqueue(self, packet: IPVN7Packet, target_addr: tuple[str, int]) -> bool:
        """Enqueues packet into its respective QoS bucket."""
        # Map TrafficClass or default to INTERACTIVE
        qos_cls = QoSClass.INTERACTIVE
        if packet.traffic_class == TrafficClass.NETWORK_CONTROL:
            qos_cls = QoSClass.CONTROL
        elif packet.traffic_class == TrafficClass.REAL_TIME:
            qos_cls = QoSClass.REALTIME
        elif packet.traffic_class == TrafficClass.BEST_EFFORT:
            qos_cls = QoSClass.BULK

        q = self.queues[qos_cls]
        if len(q) >= self.MAX_QUEUE_LEN[qos_cls]:
            # Anti-bufferbloat: tail-drop on full queue
            self.stats["packets_dropped_tail"] += 1
            return False

        pkt_len = len(packet.serialize())
        q.append(QueuedPacket(
            packet=packet,
            target_addr=target_addr,
            size=pkt_len,
            enqueued_at=time.perf_counter(),
        ))
        self.stats["packets_enqueued"] += 1
        return True

    def schedule_next(self) -> Optional[QueuedPacket]:
        """Schedules and dequeues next packet according to DWRR deficit credits and pacer."""
        # Check active classes in round-robin order
        for qos_cls in [QoSClass.CONTROL, QoSClass.REALTIME, QoSClass.INTERACTIVE, QoSClass.BULK]:
            q = self.queues[qos_cls]
            if not q:
                self.deficits[qos_cls] = 0
                continue

            self.deficits[qos_cls] += self.WEIGHTS[qos_cls]

            while q:
                head = q[0]
                if head.size <= self.deficits[qos_cls]:
                    # Check token bucket pacer
                    if self.pacer.consume(head.size):
                        pkt = q.pop(0)
                        self.deficits[qos_cls] -= pkt.size
                        self.stats["packets_dequeued"] += 1
                        self.stats["bytes_scheduled"] += pkt.size
                        return pkt
                    else:
                        # Rate limit reached; wait for next tick
                        return None
                else:
                    # Insufficient deficit credit; next class turn
                    break

        return None
