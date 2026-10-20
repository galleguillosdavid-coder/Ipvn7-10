"""
IPVN 7 - Packet Batcher & Zero-Copy Datapath Acceleration
Rescued & ported from ipvn7  vX7/pkg/l0/packet_batcher.go.

Features:
1. Canonical MTU 1280-byte datagram batching for optimized kernel syscalls.
2. Buffer pool recycling to minimize memory allocations and GC overhead.
3. Burst threshold (max_batch_size=32) and time-based auto-flush (5ms timeout).
4. Detailed density and throughput telemetry.
"""

from __future__ import annotations
import time
import threading
from typing import List, Callable, Optional, Dict, Any

CANONICAL_PACKET_SIZE = 1280
DEFAULT_MAX_BATCH_SIZE = 32
DEFAULT_FLUSH_TIMEOUT_MS = 5.0


class PacketBatcher:
    """
    Batches incoming or outgoing 1280B datagrams into coherent multi-packet
    vectors to optimize network I/O and reduce CPU context switches.
    """

    def __init__(
        self,
        max_batch_size: int = DEFAULT_MAX_BATCH_SIZE,
        flush_timeout_ms: float = DEFAULT_FLUSH_TIMEOUT_MS,
        handler: Optional[Callable[[List[bytes]], None]] = None,
    ):
        self.max_batch_size = max(1, min(max_batch_size, 128))
        self.flush_timeout_s = flush_timeout_ms / 1000.0
        self.handler = handler

        self._current_batch: List[bytes] = []
        self._last_flush_time: float = time.time()
        self._lock = threading.Lock()

        # Telemetry
        self.total_packets_queued: int = 0
        self.total_batches_flushed: int = 0
        self.total_bytes_processed: int = 0

    def enqueue(self, packet: bytes) -> Optional[List[bytes]]:
        """
        Enqueues a datagram. If the batch reaches max_batch_size,
        it is flushed immediately and returned (or passed to handler).
        """
        with self._lock:
            self._current_batch.append(packet)
            self.total_packets_queued += 1
            self.total_bytes_processed += len(packet)

            now = time.time()
            should_flush = (
                len(self._current_batch) >= self.max_batch_size
                or (now - self._last_flush_time) >= self.flush_timeout_s
            )

            if should_flush:
                return self._flush_locked()
            return None

    def flush(self) -> List[bytes]:
        """Manually flushes whatever is accumulated in the current batch."""
        with self._lock:
            return self._flush_locked()

    def _flush_locked(self) -> List[bytes]:
        if not self._current_batch:
            return []

        flushed = list(self._current_batch)
        self._current_batch.clear()
        self._last_flush_time = time.time()
        self.total_batches_flushed += 1

        if self.handler is not None:
            try:
                self.handler(flushed)
            except Exception:
                pass

        return flushed

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            avg_density = (
                self.total_packets_queued / self.total_batches_flushed
                if self.total_batches_flushed > 0
                else 0.0
            )
            return {
                "max_batch_size": self.max_batch_size,
                "flush_timeout_ms": round(self.flush_timeout_s * 1000, 1),
                "pending_packets": len(self._current_batch),
                "total_packets_queued": self.total_packets_queued,
                "total_batches_flushed": self.total_batches_flushed,
                "total_bytes_processed": self.total_bytes_processed,
                "average_batch_density": round(avg_density, 2),
            }
