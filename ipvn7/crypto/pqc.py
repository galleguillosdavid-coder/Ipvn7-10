"""
IPVN 7 Post-Quantum Cryptography Primitives
Implements NIST FIPS 203 (ML-KEM-768 / Kyber) and NIST FIPS 204 (ML-DSA-65 / Dilithium)
combined with classical X25519 / Ed25519 for dual-layer hybrid security.
"""

from __future__ import annotations
import os
import base64
import hashlib
from typing import Tuple, Dict, Any, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class PQCKeyPair:
    """Complete cryptographic key bundle for an IPVN 7 endpoint."""
    # Key Encapsulation (PQC & Classical)
    mlkem_priv: mlkem.MLKEM768PrivateKey
    mlkem_pub: mlkem.MLKEM768PublicKey
    x25519_priv: x25519.X25519PrivateKey
    x25519_pub: x25519.X25519PublicKey

    # Digital Signatures (PQC & Classical)
    mldsa_priv: mldsa.MLDSA65PrivateKey
    mldsa_pub: mldsa.MLDSA65PublicKey
    ed25519_priv: ed25519.Ed25519PrivateKey
    ed25519_pub: ed25519.Ed25519PublicKey

    @classmethod
    def generate(cls) -> PQCKeyPair:
        """Generates a complete post-quantum hybrid key bundle."""
        mlkem_priv = mlkem.MLKEM768PrivateKey.generate()
        x25519_priv = x25519.X25519PrivateKey.generate()
        mldsa_priv = mldsa.MLDSA65PrivateKey.generate()
        ed25519_priv = ed25519.Ed25519PrivateKey.generate()

        return cls(
            mlkem_priv=mlkem_priv,
            mlkem_pub=mlkem_priv.public_key(),
            x25519_priv=x25519_priv,
            x25519_pub=x25519_priv.public_key(),
            mldsa_priv=mldsa_priv,
            mldsa_pub=mldsa_priv.public_key(),
            ed25519_priv=ed25519_priv,
            ed25519_pub=ed25519_priv.public_key(),
        )

    def public_bundle_dict(self) -> Dict[str, str]:
        """Returns base64-encoded public keys for transport and DID documents."""
        return {
            "mlkem_pub": base64.b64encode(self.mlkem_pub.public_bytes_raw()).decode("utf-8"),
            "x25519_pub": base64.b64encode(self.x25519_pub.public_bytes_raw()).decode("utf-8"),
            "mldsa_pub": base64.b64encode(self.mldsa_pub.public_bytes_raw()).decode("utf-8"),
            "ed25519_pub": base64.b64encode(self.ed25519_pub.public_bytes_raw()).decode("utf-8"),
        }

    def compute_fingerprint(self) -> str:
        """
        Computes a deterministic cryptographic fingerprint representing the identity.
        Hash: SHA3-256 over concatenated public keys (ML-KEM, ML-DSA, X25519, Ed25519).
        """
        hasher = hashlib.sha3_256()
        hasher.update(self.mldsa_pub.public_bytes_raw())
        hasher.update(self.mlkem_pub.public_bytes_raw())
        hasher.update(self.ed25519_pub.public_bytes_raw())
        hasher.update(self.x25519_pub.public_bytes_raw())
        digest = hasher.digest()
        # Return base58-like hex string prefixed for IPVN 7
        return digest.hex()[:32]


@dataclass
class HybridHandshakeContext:
    """Maintains state of a post-quantum hybrid key exchange."""
    client_x25519_priv: Optional[x25519.X25519PrivateKey] = None
    client_x25519_pub: Optional[bytes] = None
    client_mlkem_pub: Optional[bytes] = None
    shared_key: Optional[bytes] = None


class PQCHybridKeyExchange:
    """
    Implements RFC 10024 hybrid key agreement:
    X25519MLKEM768 combines classical Elliptic Curve Diffie-Hellman with ML-KEM-768.
    """

    @staticmethod
    def client_init() -> Tuple[bytes, bytes, x25519.X25519PrivateKey]:
        """
        Generates ephemeral hybrid key share for ClientHello.
        Returns:
            (x25519_pub_bytes, mlkem_pub_bytes, x25519_priv)
        """
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub_bytes = x_priv.public_key().public_bytes_raw()

        # Ephemeral ML-KEM key for this session
        k_priv = mlkem.MLKEM768PrivateKey.generate()
        k_pub_bytes = k_priv.public_key().public_bytes_raw()

        # We return k_priv bundled into context or handle via direct encapsulation
        return x_pub_bytes, k_pub_bytes, x_priv, k_priv

    @staticmethod
    def server_respond(
        peer_x25519_pub_bytes: bytes,
        peer_mlkem_pub_bytes: bytes,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Server encapsulates against client's ML-KEM public key and generates ephemeral X25519.
        Returns:
            (server_x25519_pub_bytes, mlkem_ciphertext, derived_shared_key_32bytes)
        """
        # 1. Ephemeral X25519 exchange
        srv_x_priv = x25519.X25519PrivateKey.generate()
        srv_x_pub_bytes = srv_x_priv.public_key().public_bytes_raw()

        peer_x_pub = x25519.X25519PublicKey.from_public_bytes(peer_x25519_pub_bytes)
        classical_secret = srv_x_priv.exchange(peer_x_pub)

        # 2. ML-KEM Encapsulation
        peer_k_pub = mlkem.MLKEM768PublicKey.from_public_bytes(peer_mlkem_pub_bytes)
        pqc_secret, mlkem_ct = peer_k_pub.encapsulate()

        # 3. Hybrid Key Derivation via HKDF-SHA3-256
        combined_secret = classical_secret + pqc_secret
        derived_key = derive_shared_secret(combined_secret, info=b"IPVN7-PQ-QUIC-HANDSHAKE-V1")

        return srv_x_pub_bytes, mlkem_ct, derived_key

    @staticmethod
    def client_finalize(
        client_x_priv: x25519.X25519PrivateKey,
        client_k_priv: mlkem.MLKEM768PrivateKey,
        server_x25519_pub_bytes: bytes,
        mlkem_ciphertext: bytes,
    ) -> bytes:
        """
        Client completes handshake by decapsulating ML-KEM and calculating ECDH.
        Returns:
            derived_shared_key_32bytes
        """
        # 1. Classical ECDH
        srv_x_pub = x25519.X25519PublicKey.from_public_bytes(server_x25519_pub_bytes)
        classical_secret = client_x_priv.exchange(srv_x_pub)

        # 2. PQC Decapsulation
        pqc_secret = client_k_priv.decapsulate(mlkem_ciphertext)

        # 3. Hybrid Key Derivation
        combined_secret = classical_secret + pqc_secret
        return derive_shared_secret(combined_secret, info=b"IPVN7-PQ-QUIC-HANDSHAKE-V1")


class PQCDigitalSignature:
    """
    Implements digital signatures using NIST FIPS 204 (ML-DSA-65) with dual
    Ed25519 cross-signing for full post-quantum & classical authenticity.
    """

    @staticmethod
    def sign_hybrid(
        message: bytes,
        mldsa_priv: mldsa.MLDSA65PrivateKey,
        ed25519_priv: ed25519.Ed25519PrivateKey,
    ) -> Dict[str, bytes]:
        """Signs a message with both ML-DSA and Ed25519."""
        sig_mldsa = mldsa_priv.sign(message)
        sig_ed25519 = ed25519_priv.sign(message)
        return {
            "mldsa_sig": sig_mldsa,
            "ed25519_sig": sig_ed25519,
        }

    @staticmethod
    def verify_hybrid(
        message: bytes,
        mldsa_sig: bytes,
        ed25519_sig: bytes,
        mldsa_pub_bytes: bytes,
        ed25519_pub_bytes: bytes,
    ) -> bool:
        """Verifies both signatures."""
        try:
            mldsa_pub = mldsa.MLDSA65PublicKey.from_public_bytes(mldsa_pub_bytes)
            mldsa_pub.verify(mldsa_sig, message)

            ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(ed25519_pub_bytes)
            ed_pub.verify(ed25519_sig, message)
            return True
        except Exception:
            return False


def derive_shared_secret(combined_secret: bytes, salt: Optional[bytes] = None, info: bytes = b"IPVN7") -> bytes:
    """HKDF derivation producing a 32-byte high-entropy session key."""
    if salt is None:
        salt = b"IPVN7-PQC-SALT-2026"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(combined_secret)


def encrypt_aead(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM.
    Returns: nonce (12 bytes) + ciphertext + tag.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt_aead(key: bytes, payload: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypts AEAD payload (nonce 12 bytes + ciphertext + tag).
    """
    if len(payload) < 28:
        raise ValueError("Payload too short for AEAD ciphertext")
    nonce = payload[:12]
    ciphertext = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)
