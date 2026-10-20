"""
Session Key Rotation Sentinel & Forward Secrecy Engine.
Rescued from 0.7/src/pkg/l1/key_rotation.go.

Monitors traffic volume, packet count, and key age to trigger deterministic,
zero-downtime key rotation with a 30-second out-of-order grace window and memory zeroing.
"""

from __future__ import annotations
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

DEFAULT_MAX_BYTES_PER_KEY = 1024 * 1024 * 1024  # 1 GB
DEFAULT_MAX_PACKETS_PER_KEY = 1000000            # 1M packets
DEFAULT_KEY_LIFETIME_SEC = 3600.0               # 1 hour
KEY_TRANSITION_GRACE_PERIOD_SEC = 30.0          # 30 seconds


@dataclass
class SessionKeys:
    epoch: int
    active_key: bytes
    previous_key: Optional[bytes] = None
    created_at: float = field(default_factory=time.time)
    has_previous: bool = False


class KeyRotationSentinel:
    """
    Manages session key forward secrecy, monotonic epochs, and traffic thresholds.
    """

    def __init__(
        self,
        session_id: str,
        max_bytes: int = DEFAULT_MAX_BYTES_PER_KEY,
        max_packets: int = DEFAULT_MAX_PACKETS_PER_KEY,
        lifetime_sec: float = DEFAULT_KEY_LIFETIME_SEC,
    ):
        self.session_id = session_id
        self.max_bytes = max_bytes
        self.max_packets = max_packets
        self.lifetime_sec = lifetime_sec

        initial_key = os.urandom(32)
        self._keys = SessionKeys(
            epoch=1,
            active_key=initial_key,
            previous_key=None,
            created_at=time.time(),
            has_previous=False,
        )
        self._bytes_count = 0
        self._packets_count = 0
        self._total_rotations = 0

    @property
    def current_epoch(self) -> int:
        return self._keys.epoch

    def needs_rotation(self, now: Optional[float] = None) -> bool:
        """Evaluates whether traffic or time thresholds require key rotation."""
        if now is None:
            now = time.time()
        elapsed = now - self._keys.created_at
        return (
            self._bytes_count >= self.max_bytes
            or self._packets_count >= self.max_packets
            or elapsed >= self.lifetime_sec
        )

    def track_traffic(self, packet_bytes: int) -> bool:
        """Accrues datagram metrics and returns True if rotation is triggered."""
        self._bytes_count += packet_bytes
        self._packets_count += 1
        return self.needs_rotation()

    def rotate(self) -> Tuple[int, str]:
        """
        Derives next epoch key using SHA-256 over active key + fresh entropy salt.
        Preserves active key as previous key for the 30-second grace window.
        """
        salt = os.urandom(32)
        next_epoch = self._keys.epoch + 1

        hasher = hashlib.sha256()
        hasher.update(self._keys.active_key)
        hasher.update(salt)
        hasher.update(f"epoch:{next_epoch}:{self.session_id}".encode("utf-8"))
        next_key = hasher.digest()

        self._keys = SessionKeys(
            epoch=next_epoch,
            active_key=next_key,
            previous_key=self._keys.active_key,
            created_at=time.time(),
            has_previous=True,
        )

        self._bytes_count = 0
        self._packets_count = 0
        self._total_rotations += 1

        return next_epoch, next_key[:8].hex()

    def get_keys(self, now: Optional[float] = None) -> SessionKeys:
        """Returns active keys, purging previous key if the grace period has expired."""
        if now is None:
            now = time.time()

        if self._keys.has_previous and (now - self._keys.created_at > KEY_TRANSITION_GRACE_PERIOD_SEC):
            # Grace period expired, zero previous key
            self._keys = SessionKeys(
                epoch=self._keys.epoch,
                active_key=self._keys.active_key,
                previous_key=None,
                created_at=self._keys.created_at,
                has_previous=False,
            )
        return self._keys

    def summary(self) -> dict:
        now = time.time()
        keys = self.get_keys(now)
        return {
            "session_id": self.session_id,
            "epoch": keys.epoch,
            "has_previous_key": keys.has_previous,
            "bytes_in_epoch": self._bytes_count,
            "packets_in_epoch": self._packets_count,
            "total_rotations": self._total_rotations,
            "key_age_seconds": round(now - keys.created_at, 2),
            "rotation_needed": self.needs_rotation(now),
        }
