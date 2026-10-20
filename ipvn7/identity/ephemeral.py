"""
IPVN 7 Ephemeral Identity Derivation & Rotation
Implements 24-Hour Rotating Device Identifiers to eliminate wire-level fingerprinting,
while preserving deterministic Petname and Root DID resolution.
"""

from __future__ import annotations
import hmac
import hashlib
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


SECONDS_PER_DAY = 86400


@dataclass
class EphemeralDIDRecord:
    """Represents an active ephemeral DID for a given daily epoch."""
    ephemeral_did: str
    root_did: str
    epoch_day: int
    expires_at: float


class EphemeralIdentityManager:
    """
    Manages daily 24-hour rotating ephemeral DIDs for an IPVN 7 node.
    
    Provides:
    1. Deterministic generation of daily ephemeral DIDs (did:ipvn7:ephemeral:<hex>)
    2. Clock-drift tolerance (validates current epoch day and previous epoch day)
    3. Bidirectional mapping from ephemeral DID to permanent Root DID for petname lookups.
    """

    def __init__(self, root_did: str, secret_seed: Optional[bytes] = None):
        self.root_did = root_did
        self.secret_seed = secret_seed or hashlib.sha256(root_did.encode("utf-8")).digest()
        self._cache: Dict[int, EphemeralDIDRecord] = {}

    def get_current_epoch_day(self, timestamp: Optional[float] = None) -> int:
        """Returns the integer epoch day since Unix epoch."""
        ts = time.time() if timestamp is None else timestamp
        return int(ts // SECONDS_PER_DAY)

    def derive_ephemeral_did(self, epoch_day: Optional[int] = None) -> EphemeralDIDRecord:
        """
        Derives the deterministic ephemeral DID for a given epoch day.
        If epoch_day is omitted, derives for the current day.
        """
        day = self.get_current_epoch_day() if epoch_day is None else epoch_day
        if day in self._cache:
            return self._cache[day]

        msg = f"{self.root_did}:{day}".encode("utf-8")
        h = hmac.new(self.secret_seed, msg, hashlib.sha256).hexdigest()[:32]
        ephemeral_did = f"did:ipvn7:ephemeral:{h}"
        expires_at = (day + 1) * SECONDS_PER_DAY

        record = EphemeralDIDRecord(
            ephemeral_did=ephemeral_did,
            root_did=self.root_did,
            epoch_day=day,
            expires_at=expires_at,
        )
        self._cache[day] = record
        return record

    def get_active_ephemeral_did(self) -> str:
        """Returns the active daily ephemeral DID for wire transmission."""
        return self.derive_ephemeral_did().ephemeral_did

    def verify_peer_ephemeral_did(
        self,
        ephemeral_did: str,
        peer_root_did: str,
        peer_seed: Optional[bytes] = None,
        clock_drift_days: int = 1,
    ) -> bool:
        """
        Verifies if an incoming ephemeral DID matches a peer's root DID within
        the current day or +/- clock_drift_days.
        """
        seed = peer_seed or hashlib.sha256(peer_root_did.encode("utf-8")).digest()
        current_day = self.get_current_epoch_day()

        for delta in range(-clock_drift_days, clock_drift_days + 1):
            check_day = current_day + delta
            msg = f"{peer_root_did}:{check_day}".encode("utf-8")
            h = hmac.new(seed, msg, hashlib.sha256).hexdigest()[:32]
            candidate = f"did:ipvn7:ephemeral:{h}"
            if hmac.compare_digest(candidate, ephemeral_did):
                return True
        return False
