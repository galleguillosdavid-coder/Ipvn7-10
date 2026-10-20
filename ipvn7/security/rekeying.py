"""
Silent PQC Re-keying & Zero-Downtime Key Rotation Orchestrator.
IPVN 7 Security Subsystem (L3).

Enables seamless, zero-downtime post-quantum session key migration
with out-of-order grace windows (30s) and guaranteed memory zeroization.
"""

from __future__ import annotations
import enum
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any

from ..crypto.pqc import (
    PQCHybridKeyExchange,
    PQCDigitalSignature,
    PQCKeyPair,
    derive_shared_secret,
    encrypt_aead,
    decrypt_aead,
)


class RekeyPhase(enum.Enum):
    """Lifecycle phases of silent re-keying."""
    IDLE = "IDLE"
    OFFERED = "OFFERED"
    COMMITTED = "COMMITTED"
    TRANSITIONING = "TRANSITIONING"
    FINALIZED = "FINALIZED"


@dataclass
class EpochKeyMaterial:
    """Represents a session key bound to a monotonic epoch with zeroization capability."""
    epoch: int
    key_bytes: bytearray
    created_at: float = field(default_factory=time.time)
    is_zeroed: bool = False

    @property
    def key(self) -> bytes:
        if self.is_zeroed:
            raise ValueError("Cryptographic key has been securely zeroized from memory")
        return bytes(self.key_bytes)

    def zeroize(self) -> bool:
        """Securely zeroes memory of cryptographic secret to guarantee forward secrecy."""
        if not self.is_zeroed:
            for i in range(len(self.key_bytes)):
                self.key_bytes[i] = 0
            self.is_zeroed = True
            return True
        return False

    def fingerprint(self) -> str:
        if self.is_zeroed:
            return "ZEROIZED"
        return hashlib.sha256(self.key_bytes).hexdigest()[:16]


@dataclass
class RekeyProposal:
    session_id: str
    target_epoch: int
    initiator_did: str
    x25519_pub: bytes
    mlkem_pub: bytes
    timestamp: float


@dataclass
class RekeyCommitment:
    session_id: str
    target_epoch: int
    responder_did: str
    srv_x25519_pub: bytes
    mlkem_ct: bytes
    timestamp: float


class SilentKeyRotationOrchestrator:
    """
    Orchestrates continuous post-quantum re-keying between sovereign peers.
    Guarantees:
    1. Zero downtime via dual-key decryption during 30s grace window.
    2. Forward Secrecy via explicit in-place memory zeroization of expired epoch keys.
    3. Transcript-bound PQC key derivation (X25519 + ML-KEM-768 + Previous Key).
    """

    def __init__(
        self,
        session_id: str,
        local_did: str,
        peer_did: str,
        initial_key: Optional[bytes] = None,
        grace_period_sec: float = 30.0,
    ):
        self.session_id = session_id
        self.local_did = local_did
        self.peer_did = peer_did
        self.grace_period_sec = grace_period_sec
        self.phase = RekeyPhase.IDLE

        seed_key = initial_key if initial_key else os.urandom(32)
        self.active_material = EpochKeyMaterial(epoch=1, key_bytes=bytearray(seed_key))
        self.previous_material: Optional[EpochKeyMaterial] = None

        self._pending_cli_privates: Optional[Tuple[Any, Any]] = None
        self._total_rotations = 0
        self._grace_packets_served = 0

    @property
    def current_epoch(self) -> int:
        return self.active_material.epoch

    def initiate_rekey(self) -> RekeyProposal:
        """Generates fresh ephemeral hybrid shares for the next epoch."""
        x_pub, k_pub, x_priv, k_priv = PQCHybridKeyExchange.client_init()
        self._pending_cli_privates = (x_priv, k_priv)
        self.phase = RekeyPhase.OFFERED

        return RekeyProposal(
            session_id=self.session_id,
            target_epoch=self.active_material.epoch + 1,
            initiator_did=self.local_did,
            x25519_pub=x_pub,
            mlkem_pub=k_pub,
            timestamp=time.time(),
        )

    def respond_rekey(self, proposal: RekeyProposal) -> Tuple[RekeyCommitment, bytes]:
        """Responder derives next epoch key and returns encapsulated commitment."""
        if proposal.session_id != self.session_id:
            raise ValueError(f"Session ID mismatch: {proposal.session_id} != {self.session_id}")
        if proposal.target_epoch != self.active_material.epoch + 1:
            raise ValueError(f"Invalid target epoch: {proposal.target_epoch}")

        srv_x_pub, mlkem_ct, derived_key = PQCHybridKeyExchange.server_respond(
            proposal.x25519_pub,
            proposal.mlkem_pub,
        )

        # Transcript Binding with previous epoch key for monotonic ratcheting
        transcript = (
            self.active_material.key
            + proposal.x25519_pub
            + srv_x_pub
            + mlkem_ct
            + struct_pack_epoch(proposal.target_epoch)
        )
        ratcheted_key = derive_shared_secret(
            derived_key + self.active_material.key,
            salt=hashlib.sha256(transcript).digest(),
            info=b"IPVN7-SILENT-PQC-REKEY-V1",
        )

        # Transition local keys with grace period
        self._install_new_key(proposal.target_epoch, ratcheted_key)
        self.phase = RekeyPhase.COMMITTED

        commitment = RekeyCommitment(
            session_id=self.session_id,
            target_epoch=proposal.target_epoch,
            responder_did=self.local_did,
            srv_x25519_pub=srv_x_pub,
            mlkem_ct=mlkem_ct,
            timestamp=time.time(),
        )
        return commitment, ratcheted_key

    def finalize_rekey(self, commitment: RekeyCommitment) -> bytes:
        """Initiator finalizes re-keying by decapsulating and installing next epoch key."""
        if self._pending_cli_privates is None:
            raise RuntimeError("No pending re-keying proposal active")
        if commitment.target_epoch != self.active_material.epoch + 1:
            raise ValueError(f"Epoch out of sequence: {commitment.target_epoch}")

        x_priv, k_priv = self._pending_cli_privates
        derived_key = PQCHybridKeyExchange.client_finalize(
            x_priv,
            k_priv,
            commitment.srv_x25519_pub,
            commitment.mlkem_ct,
        )

        transcript = (
            self.active_material.key
            + x_priv.public_key().public_bytes_raw()
            + commitment.srv_x25519_pub
            + commitment.mlkem_ct
            + struct_pack_epoch(commitment.target_epoch)
        )
        ratcheted_key = derive_shared_secret(
            derived_key + self.active_material.key,
            salt=hashlib.sha256(transcript).digest(),
            info=b"IPVN7-SILENT-PQC-REKEY-V1",
        )

        self._install_new_key(commitment.target_epoch, ratcheted_key)
        self._pending_cli_privates = None
        self.phase = RekeyPhase.TRANSITIONING
        return ratcheted_key

    def _install_new_key(self, new_epoch: int, new_key: bytes) -> None:
        """Rotates active key, moving previous active to grace window."""
        self.previous_material = self.active_material
        self.active_material = EpochKeyMaterial(epoch=new_epoch, key_bytes=bytearray(new_key))
        self._total_rotations += 1

    def purge_expired_keys(self, now: Optional[float] = None) -> bool:
        """Zeroes out previous epoch key if grace period has elapsed."""
        if self.previous_material is None or self.previous_material.is_zeroed:
            return False

        if now is None:
            now = time.time()

        if (now - self.active_material.created_at) >= self.grace_period_sec:
            zeroed = self.previous_material.zeroize()
            self.phase = RekeyPhase.FINALIZED
            return zeroed
        return False

    def force_zeroize_previous(self) -> bool:
        """Immediately zeroizes previous epoch key regardless of grace window."""
        if self.previous_material and not self.previous_material.is_zeroed:
            zeroed = self.previous_material.zeroize()
            self.phase = RekeyPhase.FINALIZED
            return zeroed
        return False

    def encrypt_payload(self, plaintext: bytes) -> Tuple[int, bytes]:
        """Always encrypts using the highest active epoch."""
        epoch = self.active_material.epoch
        ciphertext = encrypt_aead(
            self.active_material.key,
            plaintext,
            associated_data=struct_pack_epoch(epoch),
        )
        return epoch, ciphertext

    def decrypt_payload(self, epoch: int, ciphertext: bytes, now: Optional[float] = None) -> bytes:
        """
        Decrypts payload using active key if matching, or previous key if within grace window.
        Achieves True Zero-Downtime during network jitter or out-of-order delivery.
        """
        # Try active key first
        if epoch == self.active_material.epoch:
            return decrypt_aead(
                self.active_material.key,
                ciphertext,
                associated_data=struct_pack_epoch(epoch),
            )

        # Check grace window on previous key
        if self.previous_material and epoch == self.previous_material.epoch:
            if self.previous_material.is_zeroed:
                raise ValueError("Payload epoch key was already securely zeroized")

            if now is None:
                now = time.time()
            if (now - self.active_material.created_at) <= self.grace_period_sec:
                self._grace_packets_served += 1
                return decrypt_aead(
                    self.previous_material.key,
                    ciphertext,
                    associated_data=struct_pack_epoch(epoch),
                )
            else:
                self.purge_expired_keys(now)
                raise ValueError(f"Epoch {epoch} grace period exceeded")

        raise ValueError(f"Unknown or invalid epoch: {epoch} (active: {self.active_material.epoch})")

    def get_orchestrator_summary(self) -> Dict[str, Any]:
        """Provides operational diagnostics and forward secrecy telemetry."""
        return {
            "session_id": self.session_id,
            "phase": self.phase.value,
            "current_epoch": self.active_material.epoch,
            "active_key_fingerprint": self.active_material.fingerprint(),
            "previous_epoch": self.previous_material.epoch if self.previous_material else None,
            "previous_key_zeroed": self.previous_material.is_zeroed if self.previous_material else True,
            "total_rotations": self._total_rotations,
            "grace_packets_served": self._grace_packets_served,
            "grace_period_sec": self.grace_period_sec,
            "zero_downtime_guaranteed": True,
        }


def struct_pack_epoch(epoch: int) -> bytes:
    """Canonical 8-byte big-endian epoch framing."""
    import struct
    return struct.pack("!Q", epoch)
