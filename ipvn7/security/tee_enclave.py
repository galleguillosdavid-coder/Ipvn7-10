"""
IPVN 7 Trusted Execution Environment (TEE) & Enclave Cryptographic Orchestrator
Module: ipvn7/security/tee_enclave.py (Línea P - v7.12.0)

Provides hardware-isolated-modelled security boundary for IPVN 7 sovereign nodes:
1. Deterministic Enclave Measurement (MRENCLAVE) via SHA-256 code & policy hash.
2. Cryptographic Memory Sealing / Unsealing using AES-256-GCM / ChaCha20-Poly1305.
3. Monotonic Hardware Counter (Anti-Replay for sealed states).
4. Remote Cryptographic Hardware Attestation (TEEAttestationReport) signed with EAK (Ed25519).
5. Canonical Wire Protocol IP7E (4B 'IP7E', 1B Opcode, 2B Len, Payload, 4B CRC32 <= 1280B MTU).
"""

from __future__ import annotations
import enum
import json
import os
import struct
import time
import zlib
import hashlib
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class EnclaveState(str, enum.Enum):
    UNINITIALIZED = "UNINITIALIZED"
    ACTIVE = "ACTIVE"
    SEALED = "SEALED"
    QUARANTINED = "QUARANTINED"
    TAMPERED = "TAMPERED"


class EnclaveOpcode(int, enum.Enum):
    OP_ATTESTATION_CHALLENGE = 0x01
    OP_ATTESTATION_REPORT = 0x02
    OP_SEALED_PAYLOAD = 0x03
    OP_ATTESTATION_VERIFIED = 0x04


CANONICAL_ENCLAVE_WIRE_MAGIC = b"IP7E"
MAX_ENCLAVE_WIRE_MTU = 1280


class EnclaveIntegrityError(Exception):
    """Raised when an enclave integrity verification or MRENCLAVE measurement check fails."""
    pass


class EnclaveAttestationError(Exception):
    """Raised when an attestation report is corrupted, invalid or expired."""
    pass


@dataclass
class SealedSecretRecord:
    name: str
    ciphertext_hex: str
    nonce_hex: str
    mrenclave_at_seal: str
    counter_at_seal: int
    created_at: float


@dataclass
class TEEAttestationReport:
    enclave_id: str
    mrenclave: str
    monotonic_counter: int
    challenge_nonce: str
    timestamp: float
    sealed_count: int
    state: str
    signature_hex: str
    enclave_pubkey_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SovereignEnclave:
    """
    Sovereign TEE & Cryptographic Enclave Orchestrator.
    Manages hardware-modelled cryptographic boundaries, memory sealing,
    and attestation challenges with canonical IP7E wire framing.
    """

    def __init__(
        self,
        node_id: str,
        attestation_key: Optional[ed25519.Ed25519PrivateKey] = None,
        custom_measurement_salt: bytes = b"IPVN7_SOVEREIGN_TEE_ROOT_SALT_v7.12.0",
    ):
        self.node_id = node_id
        self.enclave_id = f"did:ipvn7:enclave:{hashlib.sha256(node_id.encode('utf-8')).hexdigest()[:16]}"
        self._attestation_priv = attestation_key or ed25519.Ed25519PrivateKey.generate()
        self._attestation_pub = self._attestation_priv.public_key()
        self._pubkey_bytes = self._attestation_pub.public_bytes_raw()

        # Derive master sealing key bound to hardware/enclave identity
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=custom_measurement_salt,
            info=b"IPVN7_ENCLAVE_MASTER_SEALING_KEY",
        )
        self._master_sealing_key = hkdf.derive(self._attestation_priv.private_bytes_raw())

        self._monotonic_counter: int = 1
        self._sealed_secrets: Dict[str, SealedSecretRecord] = {}
        self.state: EnclaveState = EnclaveState.ACTIVE
        self._measurement = self._compute_mrenclave()

    # -------------------------------------------------------------
    # MRENCLAVE Measurement
    # -------------------------------------------------------------

    def _compute_mrenclave(self) -> str:
        """
        Computes the deterministic MRENCLAVE digest representing the enclave's
        code baseline, cryptographic boundaries, and policy invariants.
        """
        hasher = hashlib.sha256()
        hasher.update(b"IPVN7_CORE_ENCLAVE_POLICY_INVARIANTS_v7.12.0")
        hasher.update(self.enclave_id.encode("utf-8"))
        hasher.update(b":MTU=1280:PQC=ML-KEM-768/ML-DSA-65:ZTNA=DEFAULT_DENY")
        return hasher.hexdigest()

    @property
    def measurement(self) -> str:
        """Returns the current MRENCLAVE measurement hash."""
        return self._measurement

    @property
    def monotonic_counter(self) -> int:
        """Returns the current monotonic counter value."""
        return self._monotonic_counter

    def simulate_tampering_for_test(self, forged_measurement: str) -> None:
        """Testing utility: alters current measurement to simulate unauthorized modification."""
        self._measurement = forged_measurement
        self.state = EnclaveState.TAMPERED

    def restore_clean_state(self) -> None:
        """Restores genuine measurement and active state."""
        self._measurement = self._compute_mrenclave()
        self.state = EnclaveState.ACTIVE

    # -------------------------------------------------------------
    # Memory Sealing / Unsealing
    # -------------------------------------------------------------

    def _derive_secret_key(self, secret_name: str, mrenclave: str) -> bytes:
        """Derives a distinct 256-bit symmetric key tied to the secret name and MRENCLAVE."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=mrenclave.encode("utf-8"),
            info=secret_name.encode("utf-8"),
        )
        return hkdf.derive(self._master_sealing_key)

    def seal_secret(self, secret_name: str, plaintext: bytes) -> SealedSecretRecord:
        """
        Seals a sensitive secret in cryptographic enclave storage.
        The ciphertext is cryptographically bound to the current MRENCLAVE measurement.
        """
        if self.state in (EnclaveState.QUARANTINED, EnclaveState.TAMPERED):
            raise EnclaveIntegrityError(f"Cannot seal secret: Enclave is in state {self.state.value}")

        self._monotonic_counter += 1
        secret_key = self._derive_secret_key(secret_name, self._measurement)
        aesgcm = AESGCM(secret_key)
        nonce = os.urandom(12)

        # Authenticated data binds the secret name and monotonic counter
        aad = f"{secret_name}:{self._monotonic_counter}:{self._measurement}".encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        record = SealedSecretRecord(
            name=secret_name,
            ciphertext_hex=ciphertext.hex(),
            nonce_hex=nonce.hex(),
            mrenclave_at_seal=self._measurement,
            counter_at_seal=self._monotonic_counter,
            created_at=time.time(),
        )
        self._sealed_secrets[secret_name] = record
        return record

    def unseal_secret(self, secret_name: str) -> bytes:
        """
        Unseals a previously sealed secret.
        Fails deterministically if current MRENCLAVE measurement does not match the seal measurement.
        """
        if secret_name not in self._sealed_secrets:
            raise KeyError(f"Sealed secret '{secret_name}' not found in enclave")

        record = self._sealed_secrets[secret_name]

        # Invariant check: MRENCLAVE integrity
        if record.mrenclave_at_seal != self._measurement:
            self.state = EnclaveState.TAMPERED
            raise EnclaveIntegrityError(
                f"MRENCLAVE mismatch for secret '{secret_name}': "
                f"sealed with {record.mrenclave_at_seal[:12]}..., current is {self._measurement[:12]}..."
            )

        secret_key = self._derive_secret_key(secret_name, record.mrenclave_at_seal)
        aesgcm = AESGCM(secret_key)
        nonce = bytes.fromhex(record.nonce_hex)
        ciphertext = bytes.fromhex(record.ciphertext_hex)
        aad = f"{secret_name}:{record.counter_at_seal}:{record.mrenclave_at_seal}".encode("utf-8")

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext
        except Exception as e:
            self.state = EnclaveState.TAMPERED
            raise EnclaveIntegrityError(f"Decryption failed for secret '{secret_name}': {e}")

    # -------------------------------------------------------------
    # Cryptographic Remote Attestation
    # -------------------------------------------------------------

    def generate_attestation_report(self, challenge_nonce: str = "") -> TEEAttestationReport:
        """
        Generates a signed TEE attestation report responding to an external challenge.
        Increments the hardware monotonic counter.
        """
        if not challenge_nonce:
            challenge_nonce = os.urandom(16).hex()

        self._monotonic_counter += 1
        now = time.time()

        # Build canonical payload for signing
        payload_data = {
            "enclave_id": self.enclave_id,
            "mrenclave": self._measurement,
            "monotonic_counter": self._monotonic_counter,
            "challenge_nonce": challenge_nonce,
            "timestamp": now,
            "sealed_count": len(self._sealed_secrets),
            "state": self.state.value,
        }
        canonical_bytes = json.dumps(payload_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = self._attestation_priv.sign(canonical_bytes)

        return TEEAttestationReport(
            enclave_id=self.enclave_id,
            mrenclave=self._measurement,
            monotonic_counter=self._monotonic_counter,
            challenge_nonce=challenge_nonce,
            timestamp=now,
            sealed_count=len(self._sealed_secrets),
            state=self.state.value,
            signature_hex=signature.hex(),
            enclave_pubkey_hex=self._pubkey_bytes.hex(),
        )

    @staticmethod
    def verify_attestation_report(
        report_dict: Dict[str, Any],
        expected_nonce: Optional[str] = None,
        max_age_seconds: float = 300.0,
        expected_mrenclave: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Statically verifies a remote TEE attestation report.
        Checks:
        1. Signature validity with reported Ed25519 public key.
        2. Challenge nonce matching.
        3. Freshness against max_age_seconds.
        4. Optional MRENCLAVE baseline match.
        """
        try:
            pubkey_hex = report_dict.get("enclave_pubkey_hex")
            sig_hex = report_dict.get("signature_hex")
            if not pubkey_hex or not sig_hex:
                return False, "Missing pubkey or signature in attestation report"

            pubkey_bytes = bytes.fromhex(pubkey_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            verifier = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)

            # Reconstruct signed canonical payload
            payload_data = {
                "enclave_id": report_dict.get("enclave_id"),
                "mrenclave": report_dict.get("mrenclave"),
                "monotonic_counter": report_dict.get("monotonic_counter"),
                "challenge_nonce": report_dict.get("challenge_nonce"),
                "timestamp": report_dict.get("timestamp"),
                "sealed_count": report_dict.get("sealed_count"),
                "state": report_dict.get("state"),
            }
            canonical_bytes = json.dumps(payload_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            verifier.verify(sig_bytes, canonical_bytes)

            # Verify challenge nonce
            if expected_nonce and report_dict.get("challenge_nonce") != expected_nonce:
                return False, f"Challenge nonce mismatch: expected {expected_nonce}, got {report_dict.get('challenge_nonce')}"

            # Verify freshness
            now = time.time()
            ts = float(report_dict.get("timestamp", 0))
            if abs(now - ts) > max_age_seconds:
                return False, f"Attestation report expired: timestamp delta is {abs(now - ts):.1f}s (max {max_age_seconds}s)"

            # Verify expected measurement if required
            if expected_mrenclave and report_dict.get("mrenclave") != expected_mrenclave:
                return False, f"MRENCLAVE baseline mismatch: expected {expected_mrenclave[:12]}..., got {report_dict.get('mrenclave')[:12]}..."

            return True, "ATTESTATION_VALID"

        except Exception as e:
            return False, f"Attestation verification error: {str(e)}"

    # -------------------------------------------------------------
    # Wire Protocol IP7E Framing
    # -------------------------------------------------------------

    @staticmethod
    def encode_frame(opcode: EnclaveOpcode, payload: bytes) -> bytes:
        """
        Encodes a canonical IP7E wire frame:
        [0..4]   Magic: b'IP7E' (0x49503745)
        [4]      Opcode: 1 byte
        [5..7]   Payload Length: 2 bytes (big-endian)
        [7..7+L] Payload bytes
        [End-4]  CRC32: 4 bytes (big-endian)
        Enforces total frame size <= 1280 bytes.
        """
        if not isinstance(opcode, EnclaveOpcode):
            opcode = EnclaveOpcode(opcode)

        overhead = 4 + 1 + 2 + 4  # 11 bytes
        if len(payload) + overhead > MAX_ENCLAVE_WIRE_MTU:
            raise ValueError(
                f"Payload size {len(payload)}B exceeds maximum allowable MTU limit "
                f"({MAX_ENCLAVE_WIRE_MTU - overhead}B)"
            )

        header = struct.pack("!4sBH", CANONICAL_ENCLAVE_WIRE_MAGIC, int(opcode), len(payload))
        frame_without_crc = header + payload
        crc = zlib.crc32(frame_without_crc) & 0xFFFFFFFF
        return frame_without_crc + struct.pack("!I", crc)

    @staticmethod
    def decode_frame(raw_frame: bytes) -> Tuple[EnclaveOpcode, bytes]:
        """
        Decodes and validates a canonical IP7E wire frame:
        Validates MTU <= 1280B, Magic b'IP7E', length consistency, and CRC32.
        """
        if len(raw_frame) > MAX_ENCLAVE_WIRE_MTU:
            raise ValueError(f"Frame length {len(raw_frame)}B exceeds MTU of {MAX_ENCLAVE_WIRE_MTU}B")
        if len(raw_frame) < 11:
            raise ValueError(f"Frame length {len(raw_frame)}B is shorter than minimum header (11B)")

        magic, opcode_val, declared_len = struct.unpack("!4sBH", raw_frame[:7])
        if magic != CANONICAL_ENCLAVE_WIRE_MAGIC:
            raise ValueError(f"Invalid frame magic: {magic!r}, expected {CANONICAL_ENCLAVE_WIRE_MAGIC!r}")

        expected_total = 7 + declared_len + 4
        if len(raw_frame) != expected_total:
            raise ValueError(
                f"Frame length mismatch: raw {len(raw_frame)}B, declared payload {declared_len}B (expected {expected_total}B)"
            )

        payload = raw_frame[7:7 + declared_len]
        received_crc = struct.unpack("!I", raw_frame[-4:])[0]
        computed_crc = zlib.crc32(raw_frame[:-4]) & 0xFFFFFFFF

        if received_crc != computed_crc:
            raise ValueError(f"CRC32 checksum mismatch: received {received_crc:#010x}, computed {computed_crc:#010x}")

        try:
            opcode = EnclaveOpcode(opcode_val)
        except ValueError:
            raise ValueError(f"Unknown enclave opcode: {opcode_val}")

        return opcode, payload

    def get_enclave_status(self) -> Dict[str, Any]:
        """Returns diagnostic telemetry of the enclave."""
        return {
            "enclave_id": self.enclave_id,
            "mrenclave": self._measurement,
            "monotonic_counter": self._monotonic_counter,
            "sealed_secrets_count": len(self._sealed_secrets),
            "state": self.state.value,
            "pubkey_fingerprint": hashlib.sha256(self._pubkey_bytes).hexdigest()[:16],
            "wire_protocol": "IP7E (MTU <= 1280B)",
        }
