"""
WebAssembly & Browser Sandbox Sovereign Cryptographic Bridge.
Rescued from 0.7/src/pkg/wasm/engine.go.

Provides sovereign cryptographic primitives, Micro-PoW computation for cold start / Sybil defense,
and 1280B canonical frame validation optimized for browser and edge clients.
"""

from __future__ import annotations
import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass
class WasmIdentityDTO:
    did: str
    public_key_hex: str
    private_key_hex: str

    def to_dict(self) -> dict:
        return {
            "did": self.did,
            "public_key": self.public_key_hex,
            "private_key": self.private_key_hex,
        }


class WasmSovereignEngine:
    """
    Sovereign cryptographic and frame processing engine designed for WebAssembly
    and browser/edge client interoperability.
    """

    def __init__(self, version: str = "0.7.0-wasm"):
        self.version = version

    def generate_identity(self) -> WasmIdentityDTO:
        """Generates a sovereign Ed25519 cryptographic keypair and derived DID."""
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes_raw()
        priv_bytes = priv.private_bytes_raw()
        did = f"did:ipvn7:{pub_bytes.hex()[:32]}"
        return WasmIdentityDTO(
            did=did,
            public_key_hex=pub_bytes.hex(),
            private_key_hex=priv_bytes.hex(),
        )

    def sign_message(self, priv_hex: str, message: bytes) -> str:
        """Signs arbitrary bytes using private Ed25519 key (32 bytes raw in hex)."""
        priv_bytes = bytes.fromhex(priv_hex)
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig = priv.sign(message)
        return sig.hex()

    def verify_signature(self, pub_hex: str, message: bytes, sig_hex: str) -> bool:
        """Verifies Ed25519 signature against public key hex."""
        try:
            pub_bytes = bytes.fromhex(pub_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(sig_bytes, message)
            return True
        except Exception:
            return False

    def compute_proof_of_work(self, did: str, seq: int, difficulty_bits: int = 8) -> Tuple[int, str]:
        """
        Computes a Micro-PoW nonce for anti-Sybil admission and cold-boot resync.
        Returns (nonce, digest_hex).
        """
        if difficulty_bits <= 0 or difficulty_bits > 16:
            difficulty_bits = 8
        mask = 0xFF << (8 - (difficulty_bits % 9)) & 0xFF
        if difficulty_bits > 8:
            mask = 0xFF

        seq_bytes = struct.pack(">Q", seq)
        max_attempts = 1_000_000

        for nonce in range(1, max_attempts):
            nonce_bytes = struct.pack(">Q", nonce)
            h = hashlib.sha256()
            h.update(did.encode("utf-8"))
            h.update(seq_bytes)
            h.update(nonce_bytes)
            digest = h.digest()

            if (digest[0] & mask) == 0x00:
                if difficulty_bits <= 8 or (digest[1] & 0xF0) == 0x00:
                    return nonce, digest.hex()

        raise RuntimeError("wasm_engine: límite de iteraciones Micro-PoW excedido")

    def validate_packet_frame(self, raw_bytes: bytes) -> bool:
        """Validates canonical wire constraints of an IPVN 7 1280B frame."""
        if len(raw_bytes) != 1280:
            return False
        # Magic byte check: 0x07 (Native IPVN7) or 0x17 (TLS ApplicationData masquerade)
        if raw_bytes[0] not in (0x07, 0x17):
            return False
        return True

    def timestamp_now(self) -> int:
        """Returns epoch seconds."""
        return int(time.time())
