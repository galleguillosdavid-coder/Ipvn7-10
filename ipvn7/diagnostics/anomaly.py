"""
IPVN 7 O(1) Anomaly Fingerprinting & Telemetry Aggregator
Compacts millions of runtime networking errors and security anomalies
into deterministic cryptographic signatures without disk or memory bloat.
Inspired by ipvn7 vX7 pkg/l2/anomaly_fingerprinter.go.
"""

from __future__ import annotations
import hashlib
import time
import threading
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, field


class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def compute_signature(err_type: str, subsystem: str, root_cause: str) -> str:
    """Generates a deterministic 12-char hex cryptographic fingerprint."""
    h = hashlib.sha256()
    h.update(err_type.encode("utf-8"))
    h.update(b":")
    h.update(subsystem.encode("utf-8"))
    h.update(b":")
    h.update(root_cause.encode("utf-8"))
    return h.hexdigest()[:12]


@dataclass
class ErrorFingerprint:
    signature: str
    error_type: str
    subsystem: str
    root_cause: str
    severity: SeverityLevel
    count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature": self.signature,
            "error_type": self.error_type,
            "subsystem": self.subsystem,
            "root_cause": self.root_cause,
            "severity": self.severity.value,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_seen_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.last_seen)),
        }


class AnomalyFingerprinter:
    """
    Thread-safe, O(1) failure and anomaly aggregator.
    Maintains a deduplicated map of incident signatures.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.fingerprints: Dict[str, ErrorFingerprint] = {}
        self.total_count: int = 0

    def record_anomaly(
        self,
        err_type: str,
        subsystem: str,
        root_cause: str,
        severity: SeverityLevel = SeverityLevel.MEDIUM,
    ) -> ErrorFingerprint:
        """Records or increments an anomaly event in O(1) time."""
        sig = compute_signature(err_type, subsystem, root_cause)
        now = time.time()

        with self._lock:
            self.total_count += 1
            if sig in self.fingerprints:
                fp = self.fingerprints[sig]
                fp.count += 1
                fp.last_seen = now
                return fp

            new_fp = ErrorFingerprint(
                signature=sig,
                error_type=err_type,
                subsystem=subsystem,
                root_cause=root_cause,
                severity=severity,
                count=1,
                first_seen=now,
                last_seen=now,
            )
            self.fingerprints[sig] = new_fp
            return new_fp

    def get_fingerprints(
        self,
        severity: Optional[SeverityLevel] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Returns fingerprints sorted by event count and recency."""
        with self._lock:
            fps = list(self.fingerprints.values())

        if severity:
            fps = [fp for fp in fps if fp.severity == severity]

        fps.sort(key=lambda x: (x.count, x.last_seen), reverse=True)
        return [fp.to_dict() for fp in fps[:limit]]

    def get_summary(self) -> Dict[str, Any]:
        """Returns consolidated metrics across all anomaly fingerprints."""
        with self._lock:
            total = self.total_count
            unique = len(self.fingerprints)
            by_sev = {
                SeverityLevel.CRITICAL.value: 0,
                SeverityLevel.HIGH.value: 0,
                SeverityLevel.MEDIUM.value: 0,
                SeverityLevel.LOW.value: 0,
            }
            for fp in self.fingerprints.values():
                by_sev[fp.severity.value] += fp.count

        return {
            "total_incidents_recorded": total,
            "unique_fingerprints": unique,
            "counts_by_severity": by_sev,
        }

    def reset(self) -> None:
        with self._lock:
            self.fingerprints.clear()
            self.total_count = 0
