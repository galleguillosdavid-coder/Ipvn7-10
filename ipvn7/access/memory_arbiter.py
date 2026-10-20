"""
IPVN 7 Global Memory Arbiter (GMA)
==================================
RFC-7001 DoS/OOM Protection & Partitioned Memory Quotas.

Key Features:
- Partitions host RAM into 5 canonical budget classes (ip7uin specification):
  * REPLAY (20%): Anti-replay sliding windows & deduplication Bloom filters.
  * QOS (30%): DWRR priority packet queues & Token Buckets.
  * TRUST (20%): Web of Trust, vouches, and reputation tables.
  * BINDINGS (20%): Mobile locators, Petname dDNS, and DHT routing state.
  * OTHER (10%): Control frames, ephemeral headers, and scratch buffers.
- Enforces strict hard caps (default 64MB) preventing resource exhaustion attacks.
- Atomic reservation, release, and live rejection telemetry.
"""

import threading
from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass


class BudgetClass(str, Enum):
    REPLAY = "replay"
    QOS = "qos"
    TRUST = "trust"
    BINDINGS = "bindings"
    OTHER = "other"


@dataclass
class ClassQuota:
    percentage: float
    limit_bytes: int
    allocated_bytes: int = 0
    dropped_allocations: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "percentage": self.percentage,
            "limit_bytes": self.limit_bytes,
            "allocated_bytes": self.allocated_bytes,
            "usage_pct": round((self.allocated_bytes / max(1, self.limit_bytes)) * 100, 2),
            "dropped_allocations": self.dropped_allocations,
        }


class GlobalMemoryArbiter:
    """
    Orchestrates strict memory allocations across all node subsystems.
    Guarantees DoS/OOM immunity by enforcing pre-allocated class budgets.
    """

    DEFAULT_TOTAL_LIMIT_BYTES = 64 * 1024 * 1024  # 64 MB

    def __init__(self, total_bytes: int = DEFAULT_TOTAL_LIMIT_BYTES):
        self.total_limit = max(1024, total_bytes)
        self.total_allocated = 0
        self.total_rejections = 0
        self._lock = threading.Lock()

        # Partition ratios: 20% Replay, 30% QoS, 20% Trust, 20% Bindings, 10% Other
        self.quotas: Dict[BudgetClass, ClassQuota] = {
            BudgetClass.REPLAY: ClassQuota(percentage=0.20, limit_bytes=int(self.total_limit * 0.20)),
            BudgetClass.QOS: ClassQuota(percentage=0.30, limit_bytes=int(self.total_limit * 0.30)),
            BudgetClass.TRUST: ClassQuota(percentage=0.20, limit_bytes=int(self.total_limit * 0.20)),
            BudgetClass.BINDINGS: ClassQuota(percentage=0.20, limit_bytes=int(self.total_limit * 0.20)),
            BudgetClass.OTHER: ClassQuota(percentage=0.10, limit_bytes=int(self.total_limit * 0.10)),
        }

    def reserve(self, budget_class: BudgetClass, num_bytes: int) -> bool:
        """
        Atomically requests memory reservation for a specific budget class.
        Returns True if allocation is permitted within quota, False if rejected.
        """
        if num_bytes <= 0:
            return True

        with self._lock:
            q = self.quotas.get(budget_class, self.quotas[BudgetClass.OTHER])

            # Class quota check
            if q.allocated_bytes + num_bytes > q.limit_bytes:
                q.dropped_allocations += 1
                self.total_rejections += 1
                return False

            # Global pool check
            if self.total_allocated + num_bytes > self.total_limit:
                q.dropped_allocations += 1
                self.total_rejections += 1
                return False

            q.allocated_bytes += num_bytes
            self.total_allocated += num_bytes
            return True

    def release(self, budget_class: BudgetClass, num_bytes: int) -> None:
        """Frees previously reserved memory."""
        if num_bytes <= 0:
            return

        with self._lock:
            q = self.quotas.get(budget_class, self.quotas[BudgetClass.OTHER])
            freed = min(q.allocated_bytes, num_bytes)
            q.allocated_bytes -= freed
            self.total_allocated = max(0, self.total_allocated - freed)

    def get_summary(self) -> Dict[str, Any]:
        """Returns memory arbiter quotas and utilization telemetry."""
        with self._lock:
            return {
                "total_limit_bytes": self.total_limit,
                "total_allocated_bytes": self.total_allocated,
                "usage_percentage": round((self.total_allocated / self.total_limit) * 100, 2),
                "total_rejections": self.total_rejections,
                "classes": {k.value: v.to_dict() for k, v in self.quotas.items()},
            }
