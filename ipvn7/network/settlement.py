"""
IPVN 7 Sovereign Reciprocity Tokens & Micro-Economic Settlement Subsystem.
Enforces verifiable P2P bandwidth credit exchange and quota governance (Line O).
Nodes exchange cryptographically signed Proof-of-Transit receipts (IP7R)
to clear routing deficits and upgrade QoS tiers without central clearinghouses.
"""

from __future__ import annotations
import time
import struct
import zlib
import hashlib
import threading
from typing import Dict, Any, Optional, Tuple, List, Set, Callable
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from .accounting import TransitAccounting, ServiceTier

# Canonical Wire Framing for Reciprocity Settlement
MAGIC_RECIPROCITY = b"IP7R"
CANONICAL_RECIPROCITY_MTU = 1280

OP_TOKEN_ISSUE        = 0x01
OP_SETTLEMENT_CLAIM   = 0x02
OP_SETTLEMENT_RECEIPT = 0x03
OP_AUDIT_BALANCE      = 0x04

MAX_CREDITS_PER_TOKEN = 100 * 1024 * 1024 * 1024  # 100 GiB maximum credit cap per token
MAX_EPOCH_AGE_DAYS    = 30                        # Valid for 30 epochs (30 days)


@dataclass
class ReciprocityToken:
    """
    Cryptographically verifiable Proof-of-Transit token.
    Issued by a bandwidth-consuming peer to credit a relay node for routed bytes.
    """
    token_id: str
    issuer_did: str
    beneficiary_did: str
    bandwidth_credits: int
    epoch: int
    nonce: int
    issued_at: float
    signature_hex: str

    def canonical_bytes(self) -> bytes:
        """
        Computes the canonical deterministically serialized bytes over which
        the Ed25519 digital signature is evaluated.
        """
        header = b"IP7R-TOKEN-V1:"
        dids = f"{self.issuer_did}:{self.beneficiary_did}:".encode("utf-8")
        num_fields = struct.pack(
            "!QQQQ",
            self.bandwidth_credits,
            self.epoch,
            self.nonce,
            int(self.issued_at),
        )
        return header + dids + num_fields

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "issuer_did": self.issuer_did,
            "beneficiary_did": self.beneficiary_did,
            "bandwidth_credits": self.bandwidth_credits,
            "epoch": self.epoch,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "signature_hex": self.signature_hex,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReciprocityToken:
        return cls(
            token_id=str(data["token_id"]),
            issuer_did=str(data["issuer_did"]),
            beneficiary_did=str(data["beneficiary_did"]),
            bandwidth_credits=int(data["bandwidth_credits"]),
            epoch=int(data["epoch"]),
            nonce=int(data["nonce"]),
            issued_at=float(data["issued_at"]),
            signature_hex=str(data["signature_hex"]),
        )


class SovereignReciprocitySettlement:
    """
    Autonomous Micro-Economic Settlement & Quota Governance Engine.
    Manages issuance, verification, double-spend prevention, and Tit-for-Tat
    quota remediation using verifiable reciprocity tokens.
    """

    def __init__(
        self,
        local_did: str,
        accounting: Optional[TransitAccounting] = None,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    ):
        self.local_did = local_did
        self.accounting = accounting or TransitAccounting()
        self.private_key = private_key
        self._lock = threading.Lock()

        # Nonce tracking per issuer to enforce strict monotonic sequence
        self.issuer_nonces: Dict[str, int] = {}
        # Set of redeemed token IDs to prevent double settlement
        self.spent_token_ids: Set[str] = set()
        # Cumulative balance of unspent credits per DID
        self.credit_balances: Dict[str, int] = {}
        # History of issued and settled receipts
        self.settlement_history: List[Dict[str, Any]] = []

        self.stats = {
            "tokens_issued": 0,
            "tokens_settled": 0,
            "tokens_rejected": 0,
            "total_credits_settled_bytes": 0,
            "remediations_applied": 0,
        }

    @staticmethod
    def current_epoch() -> int:
        """Returns the current daily epoch counter since Unix epoch."""
        return int(time.time() // 86400)

    def issue_token(
        self,
        beneficiary_did: str,
        bandwidth_credits: int,
        privkey: Optional[ed25519.Ed25519PrivateKey] = None,
    ) -> ReciprocityToken:
        """
        Issues a signed ReciprocityToken to reward a peer for routed transit.
        """
        signing_key = privkey or self.private_key
        if signing_key is None:
            raise ValueError("No Ed25519 private key provided for issuing reciprocity token")

        if beneficiary_did == self.local_did:
            raise ValueError("Self-issuance of reciprocity tokens is strictly prohibited")

        if bandwidth_credits <= 0:
            raise ValueError("Bandwidth credits must be strictly positive")

        if bandwidth_credits > MAX_CREDITS_PER_TOKEN:
            raise ValueError(f"Bandwidth credits exceed maximum cap of {MAX_CREDITS_PER_TOKEN} bytes")

        with self._lock:
            current_nonce = self.issuer_nonces.get(self.local_did, 0) + 1
            self.issuer_nonces[self.local_did] = current_nonce
            now = time.time()
            epoch = self.current_epoch()

            # Pre-compute token payload without signature to derive digest
            temp_token = ReciprocityToken(
                token_id="",
                issuer_did=self.local_did,
                beneficiary_did=beneficiary_did,
                bandwidth_credits=bandwidth_credits,
                epoch=epoch,
                nonce=current_nonce,
                issued_at=now,
                signature_hex="",
            )
            canonical = temp_token.canonical_bytes()
            sig = signing_key.sign(canonical)
            token_id = hashlib.sha256(canonical + sig).hexdigest()[:32]

            token = ReciprocityToken(
                token_id=token_id,
                issuer_did=self.local_did,
                beneficiary_did=beneficiary_did,
                bandwidth_credits=bandwidth_credits,
                epoch=epoch,
                nonce=current_nonce,
                issued_at=now,
                signature_hex=sig.hex(),
            )

            self.stats["tokens_issued"] += 1
            return token

    def verify_token(
        self,
        token: ReciprocityToken,
        issuer_pubkey_bytes: bytes,
    ) -> Tuple[bool, str]:
        """
        Cryptographically verifies the authenticity and structural validity of a ReciprocityToken.
        """
        # 1. Structural bounds check
        if token.bandwidth_credits <= 0 or token.bandwidth_credits > MAX_CREDITS_PER_TOKEN:
            return False, f"Invalid bandwidth credit amount: {token.bandwidth_credits}"

        if token.issuer_did == token.beneficiary_did:
            return False, "Self-issued tokens are invalid"

        # 2. Expiration check
        curr_ep = self.current_epoch()
        if token.epoch > curr_ep + 1:
            return False, "Token epoch is in the future"
        if curr_ep - token.epoch > MAX_EPOCH_AGE_DAYS:
            return False, f"Token has expired (> {MAX_EPOCH_AGE_DAYS} epochs old)"

        # 3. Signature verification
        try:
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(issuer_pubkey_bytes)
            sig_bytes = bytes.fromhex(token.signature_hex)
            canonical = token.canonical_bytes()
            pubkey.verify(sig_bytes, canonical)
        except (ValueError, InvalidSignature, Exception) as e:
            return False, f"Cryptographic signature verification failed: {str(e)}"

        return True, "Token signature and bounds valid"

    def settle_token(
        self,
        token: ReciprocityToken,
        issuer_pubkey_bytes: bytes,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Redeems a ReciprocityToken, preventing double-spend and adding credits to beneficiary.
        """
        with self._lock:
            # 1. Double-spend prevention via token_id tracking
            if token.token_id in self.spent_token_ids:
                self.stats["tokens_rejected"] += 1
                return False, "Token has already been redeemed (Double-spend detected)", {}

            # 2. Cryptographic and structural verification
            is_valid, reason = self.verify_token(token, issuer_pubkey_bytes)
            if not is_valid:
                self.stats["tokens_rejected"] += 1
                return False, f"Token verification rejected: {reason}", {}

            # 3. Check monotonic nonce progression for issuer
            last_nonce = self.issuer_nonces.get(token.issuer_did, 0)
            if token.nonce <= last_nonce and token.issuer_did in self.issuer_nonces:
                # Reject replayed or out-of-order lower nonce from same issuer
                self.stats["tokens_rejected"] += 1
                return False, f"Nonce replay detected (expected > {last_nonce}, got {token.nonce})", {}

            # Mark token spent and record sequence
            self.spent_token_ids.add(token.token_id)
            self.issuer_nonces[token.issuer_did] = token.nonce

            # Credit beneficiary's unspent balance
            beneficiary = token.beneficiary_did
            self.credit_balances[beneficiary] = self.credit_balances.get(beneficiary, 0) + token.bandwidth_credits

            self.stats["tokens_settled"] += 1
            self.stats["total_credits_settled_bytes"] += token.bandwidth_credits

            receipt = {
                "settlement_id": hashlib.sha256(f"{token.token_id}:{time.time()}".encode()).hexdigest()[:16],
                "token_id": token.token_id,
                "beneficiary_did": beneficiary,
                "credits_applied": token.bandwidth_credits,
                "new_credit_balance": self.credit_balances[beneficiary],
                "timestamp": time.time(),
            }
            self.settlement_history.append(receipt)
            return True, "Token successfully settled and credits applied", receipt

    def apply_quota_remediation(
        self,
        did: str,
        credits_to_redeem: Optional[int] = None,
    ) -> Tuple[bool, str, ServiceTier]:
        """
        Remediates a throttled or best-effort peer's Tit-for-Tat tier in TransitAccounting
        by burning unspent reciprocity credits to offset bandwidth deficits.
        """
        with self._lock:
            available = self.credit_balances.get(did, 0)
            if available <= 0:
                tier = self.accounting.get_tier(did)
                return False, f"No reciprocity credits available for DID {did}", tier

            redeem = available if credits_to_redeem is None else min(credits_to_redeem, available)
            if redeem <= 0:
                tier = self.accounting.get_tier(did)
                return False, "Redemption amount must be positive", tier

            self.credit_balances[did] -= redeem
            # Offset deficit in accounting: crediting bytes_rx improves Rx/Tx Tit-for-Tat ratio
            new_tier = self.accounting.record_rx(did, redeem)
            self.stats["remediations_applied"] += 1

            return (
                True,
                f"Successfully redeemed {redeem} reciprocity credits. New tier: {new_tier.value}",
                new_tier,
            )

    def get_balance(self, did: str) -> int:
        """Returns the unspent credit balance in bytes for target DID."""
        with self._lock:
            return self.credit_balances.get(did, 0)

    def get_summary(self) -> Dict[str, Any]:
        """Provides a comprehensive telemetry snapshot of micro-economic settlement."""
        with self._lock:
            return {
                "local_did": self.local_did,
                "current_epoch": self.current_epoch(),
                "spent_tokens_count": len(self.spent_token_ids),
                "active_credit_accounts": len(self.credit_balances),
                "total_outstanding_credits_bytes": sum(self.credit_balances.values()),
                "stats": dict(self.stats),
                "recent_settlements": self.settlement_history[-10:],
            }

    @staticmethod
    def serialize_frame(opcode: int, payload: bytes) -> bytes:
        """
        Serializes a wire settlement frame (IP7R) respecting the 1280 bytes MTU.
        Format: [4B MAGIC][1B OPCODE][2B LENGTH][PAYLOAD][4B CRC32]
        """
        if len(payload) > CANONICAL_RECIPROCITY_MTU - 11:
            raise ValueError(f"Settlement frame payload exceeds MTU ({len(payload)} bytes)")

        header = MAGIC_RECIPROCITY + bytes([opcode]) + struct.pack("!H", len(payload))
        crc = zlib.crc32(header + payload) & 0xFFFFFFFF
        return header + payload + struct.pack("!I", crc)

    @staticmethod
    def deserialize_frame(data: bytes) -> Tuple[int, bytes]:
        """
        Deserializes and validates an IP7R wire settlement frame.
        """
        if len(data) < 11:
            raise ValueError("Truncated IP7R wire frame (< 11 bytes)")

        if not data.startswith(MAGIC_RECIPROCITY):
            raise ValueError("Invalid magic bytes for IP7R settlement frame")

        opcode = data[4]
        payload_len = struct.unpack("!H", data[5:7])[0]

        if len(data) < 7 + payload_len + 4:
            raise ValueError("Frame length mismatch with declared payload length")

        payload = data[7: 7 + payload_len]
        expected_crc = struct.unpack("!I", data[7 + payload_len: 11 + payload_len])[0]
        actual_crc = zlib.crc32(data[: 7 + payload_len]) & 0xFFFFFFFF

        if actual_crc != expected_crc:
            raise ValueError("CRC32 integrity check failed for IP7R frame")

        return opcode, payload
