"""
Universal Intent & Identity Network (UIN) Engine.
Rescued from ip7uin_MVP_Spec and IPv7_UIN_Arquitectura_Unificada.

Decouples sovereign root identity (256-bit root_id, did:ipvn7:uin:<hex16>)
from ephemeral rotating operational keys via canonical cryptographic Binding Records.
"""

from __future__ import annotations
import hashlib
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class IdentityMode(str, Enum):
    LEGACY = "legacy"  # Direct public key usage
    HYBRID = "hybrid"  # Valid BindingRecord takes precedence; fallback to direct key
    ROOT = "root"      # Strict sovereign root_id authenticated via active BindingRecord


class BindingScope(int, Enum):
    GENERAL = 0x00
    TELEMETRY = 0x01
    CONTROL = 0x02
    AI_AGENT = 0x03
    SETTLEMENT = 0x04


@dataclass
class BindingRecord:
    version: int
    root_id: str
    key_id: str
    algo: int  # 1=Ed25519, 2=ExperimentalSig
    scope: BindingScope
    public_key_hex: str
    valid_from: float
    valid_until: float
    prev_key_id: str
    sig_root_hex: str = ""

    def digest(self) -> bytes:
        """Computes deterministic canonical digest over binding payload for signature verification."""
        hasher = hashlib.sha256()
        hasher.update(self.version.to_bytes(1, "big"))
        hasher.update(bytes.fromhex(self.root_id))
        hasher.update(bytes.fromhex(self.key_id))
        hasher.update(self.algo.to_bytes(1, "big"))
        hasher.update(int(self.scope).to_bytes(1, "big"))
        hasher.update(bytes.fromhex(self.public_key_hex))
        hasher.update(int(self.valid_from).to_bytes(8, "big"))
        hasher.update(int(self.valid_until).to_bytes(8, "big"))
        if self.prev_key_id:
            hasher.update(bytes.fromhex(self.prev_key_id))
        else:
            hasher.update(b"\x00" * 16)
        return hasher.digest()

    def is_valid_at(self, timestamp: float) -> bool:
        return self.valid_from <= timestamp <= self.valid_until


@dataclass
class UINPassport:
    root_id_hex: str
    entity_did: str
    mode: IdentityMode
    created_at: float
    active_bindings: List[BindingRecord] = field(default_factory=list)
    revoked_bindings: List[str] = field(default_factory=list)


class UINIdentityManager:
    """
    Manages sovereign entity root identity, subordinate key delegations,
    and real-time cryptographic revocation.
    """

    def __init__(self, mode: IdentityMode = IdentityMode.HYBRID, root_private_key: Optional[Ed25519PrivateKey] = None):
        self.mode = mode
        if root_private_key is None:
            self._root_priv = Ed25519PrivateKey.generate()
        else:
            self._root_priv = root_private_key

        self._root_pub = self._root_priv.public_key()
        root_pub_bytes = self._root_pub.public_bytes_raw()

        # root_id = SHA-256(root_pubkey || b"ip7uin:root:v1")
        hasher = hashlib.sha256()
        hasher.update(root_pub_bytes)
        hasher.update(b"ip7uin:root:v1")
        self._root_id = hasher.digest()
        self.created_at = time.time()

        self._bindings: Dict[str, BindingRecord] = {}       # key_id_hex -> BindingRecord
        self._revocations: Dict[str, float] = {}            # key_id_hex -> revocation_timestamp

    @property
    def root_id_hex(self) -> str:
        return self._root_id.hex()

    @property
    def entity_did(self) -> str:
        return f"did:ipvn7:uin:{self._root_id[:16].hex()}"

    @property
    def root_public_key_hex(self) -> str:
        return self._root_pub.public_bytes_raw().hex()

    def issue_binding(
        self,
        subordinate_public_key_hex: str,
        scope: BindingScope = BindingScope.GENERAL,
        duration_seconds: float = 86400.0,
        prev_key_id: str = "",
        algo: int = 1,
    ) -> BindingRecord:
        """Issues and signs a cryptographic BindingRecord delegating authority to a subordinate key."""
        key_id = os.urandom(16).hex()
        now = time.time()
        record = BindingRecord(
            version=1,
            root_id=self.root_id_hex,
            key_id=key_id,
            algo=algo,
            scope=scope,
            public_key_hex=subordinate_public_key_hex,
            valid_from=now,
            valid_until=now + duration_seconds,
            prev_key_id=prev_key_id,
        )

        payload_digest = record.digest()
        signature = self._root_priv.sign(payload_digest)
        record.sig_root_hex = signature.hex()

        self._bindings[key_id] = record
        return record

    def revoke_binding(self, key_id: str) -> bool:
        """Immediately revokes a subordinate binding."""
        if key_id in self._bindings:
            self._revocations[key_id] = time.time()
            return True
        return False

    def verify_binding(self, record: BindingRecord, timestamp: Optional[float] = None) -> bool:
        """Verifies integrity, signature and non-revocation of a BindingRecord."""
        if timestamp is None:
            timestamp = time.time()

        if not record.is_valid_at(timestamp):
            return False

        if record.key_id in self._revocations:
            return False

        if record.root_id != self.root_id_hex:
            return False

        try:
            payload_digest = record.digest()
            sig_bytes = bytes.fromhex(record.sig_root_hex)
            self._root_pub.verify(sig_bytes, payload_digest)
            return True
        except Exception:
            return False

    def get_passport(self) -> UINPassport:
        now = time.time()
        active = [
            b for k_id, b in self._bindings.items()
            if b.is_valid_at(now) and k_id not in self._revocations
        ]
        return UINPassport(
            root_id_hex=self.root_id_hex,
            entity_did=self.entity_did,
            mode=self.mode,
            created_at=self.created_at,
            active_bindings=active,
            revoked_bindings=list(self._revocations.keys()),
        )

    def summary(self) -> dict:
        now = time.time()
        active_count = sum(1 for k, b in self._bindings.items() if b.is_valid_at(now) and k not in self._revocations)
        return {
            "entity_did": self.entity_did,
            "root_id": self.root_id_hex,
            "mode": self.mode.value,
            "active_bindings_count": active_count,
            "total_bindings_issued": len(self._bindings),
            "revoked_bindings_count": len(self._revocations),
        }
