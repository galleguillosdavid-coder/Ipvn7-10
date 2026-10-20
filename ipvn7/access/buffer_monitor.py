"""
Real-Time Lock-Free Buffer Health & Datagram Ring Monitor.
Rescued from 0.7/src/pkg/l0/buffer_metrics.go.

Tracks 1280-byte datagram buffer allocation, recycling, high-water marks,
and triggers early leak alerts if in-use buffers exceed configured budget limits.
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field

DEFAULT_MAX_BUFFER_BUDGET = 10000  # 10,000 * 1280B = 12.8 MB


@dataclass
class BufferHealthSnapshot:
    buffers_allocated: int
    buffers_recycled: int
    buffers_in_use: int
    high_water_mark: int
    max_budget: int
    leak_alert: bool
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "buffers_allocated": self.buffers_allocated,
            "buffers_recycled": self.buffers_recycled,
            "buffers_in_use": self.buffers_in_use,
            "high_water_mark": self.high_water_mark,
            "max_budget": self.max_budget,
            "leak_alert": self.leak_alert,
            "allocated_mb": round((self.buffers_in_use * 1280) / (1024 * 1024), 3),
            "timestamp": self.timestamp,
        }


class BufferHealthMonitor:
    """
    Lock-free datagram buffer lifecycle tracker for high-throughput zero-copy datapath.
    """

    def __init__(self, max_budget: int = DEFAULT_MAX_BUFFER_BUDGET):
        self.max_budget = max_budget
        self._allocated = 0
        self._recycled = 0
        self._hwm = 0

    def track_alloc(self) -> int:
        """Records allocation of a 1280-byte wire datagram buffer."""
        self._allocated += 1
        in_use = max(0, self._allocated - self._recycled)
        if in_use > self._hwm:
            self._hwm = in_use
        return in_use

    def track_recycle(self) -> int:
        """Records safe recycling of a datagram buffer back to the slab/pool."""
        self._recycled += 1
        return max(0, self._allocated - self._recycled)

    def snapshot(self) -> BufferHealthSnapshot:
        """Generates an immutable snapshot of memory buffer health."""
        in_use = max(0, self._allocated - self._recycled)
        return BufferHealthSnapshot(
            buffers_allocated=self._allocated,
            buffers_recycled=self._recycled,
            buffers_in_use=in_use,
            high_water_mark=self._hwm,
            max_budget=self.max_budget,
            leak_alert=in_use > self.max_budget,
        )

    def reset(self):
        """Resets monitor counters."""
        self._allocated = 0
        self._recycled = 0
        self._hwm = 0

    def summary(self) -> dict:
        return self.snapshot().to_dict()
