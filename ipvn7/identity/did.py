"""
IPVN 7 Decentralized Identifiers (DIDs) Implementation
Complies with W3C DID Core 1.0 recommendations, enriched with Post-Quantum Verification Methods.
"""

from __future__ import annotations
import json
import time
import base64
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from ..crypto.pqc import PQCKeyPair, PQCDigitalSignature


@dataclass
class DIDDocument:
    """W3C-compliant Decentralized Identifier Document for IPVN 7."""
    context: list[str]
    id: str
    created: str
    updated: str
    verification_method: list[Dict[str, Any]]
    authentication: list[str]
    key_agreement: list[str]
    service: list[Dict[str, Any]]
    proof: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "@context": self.context,
            "id": self.id,
            "created": self.created,
            "updated": self.updated,
            "verificationMethod": self.verification_method,
            "authentication": self.authentication,
            "keyAgreement": self.key_agreement,
            "service": self.service,
            "proof": self.proof,
        }

    def canonical_bytes(self) -> bytes:
        """Produces canonical JSON serialization (excluding proof) for signing and verification."""
        data = self.to_dict()
        data.pop("proof", None)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class IPVN7Identity:
    """
    Represents an autonomous IPVN 7 Universal Client/Node Identity.
    Holds persistent cryptographic key material and generates certified DID documents.
    """

    def __init__(self, keypair: Optional[PQCKeyPair] = None, alias: str = "node-alpha"):
        self.keypair = keypair or PQCKeyPair.generate()
        self.fingerprint = self.keypair.compute_fingerprint()
        self.did = f"did:ipvn7:{self.fingerprint}"
        self.alias = alias
        self._doc: Optional[DIDDocument] = None

    @classmethod
    def create(cls, alias: str = "node-alpha") -> IPVN7Identity:
        return cls(keypair=PQCKeyPair.generate(), alias=alias)

    def get_document(self, service_endpoint: Optional[str] = None) -> DIDDocument:
        """Generates, signs, and returns the certified DID Document for this identity."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        endpoint = service_endpoint or f"ipvn7://{self.did}"

        pub_bundle = self.keypair.public_bundle_dict()

        vm = [
            {
                "id": f"{self.did}#mldsa-1",
                "type": "MLDSA65VerificationKey2026",
                "controller": self.did,
                "publicKeyMultibase": "u" + pub_bundle["mldsa_pub"],
            },
            {
                "id": f"{self.did}#mlkem-1",
                "type": "MLKEM768KeyAgreementKey2026",
                "controller": self.did,
                "publicKeyMultibase": "u" + pub_bundle["mlkem_pub"],
            },
            {
                "id": f"{self.did}#ed25519-1",
                "type": "Ed25519VerificationKey2020",
                "controller": self.did,
                "publicKeyMultibase": "u" + pub_bundle["ed25519_pub"],
            },
            {
                "id": f"{self.did}#x25519-1",
                "type": "X25519KeyAgreementKey2020",
                "controller": self.did,
                "publicKeyMultibase": "u" + pub_bundle["x25519_pub"],
            },
        ]

        services = [
            {
                "id": f"{self.did}#transport",
                "type": "IPVN7TransportEndpoint",
                "serviceEndpoint": endpoint,
            }
        ]

        doc = DIDDocument(
            context=["https://www.w3.org/ns/did/v1", "https://w3id.org/ipvn7/v1"],
            id=self.did,
            created=now,
            updated=now,
            verification_method=vm,
            authentication=[f"{self.did}#mldsa-1", f"{self.did}#ed25519-1"],
            key_agreement=[f"{self.did}#mlkem-1", f"{self.did}#x25519-1"],
            service=services,
        )

        # Cryptographically sign the canonical document
        canonical = doc.canonical_bytes()
        signatures = PQCDigitalSignature.sign_hybrid(
            canonical,
            self.keypair.mldsa_priv,
            self.keypair.ed25519_priv,
        )

        doc.proof = {
            "type": "IPVN7HybridPQCProof2026",
            "created": now,
            "verificationMethod": f"{self.did}#mldsa-1",
            "proofPurpose": "assertionMethod",
            "mldsaSignature": base64.b64encode(signatures["mldsa_sig"]).decode("utf-8"),
            "ed25519Signature": base64.b64encode(signatures["ed25519_sig"]).decode("utf-8"),
        }

        self._doc = doc
        return doc


class DIDResolver:
    """
    Universal DID Resolver for IPVN 7 identities.
    Validates cryptographic authenticity of DID documents.
    """

    def __init__(self):
        self._cache: Dict[str, DIDDocument] = {}

    def register(self, doc: DIDDocument) -> None:
        """Caches a verified DID document."""
        self._cache[doc.id] = doc

    def resolve(self, did: str) -> Optional[DIDDocument]:
        return self._cache.get(did)

    @staticmethod
    def verify_document(doc: DIDDocument) -> bool:
        """
        Validates that the DID Document is authentic, unmodified, and genuinely
        signed by the keys specified in its verification methods.
        """
        if not doc.proof:
            return False

        proof = doc.proof
        mldsa_sig = base64.b64decode(proof.get("mldsaSignature", ""))
        ed25519_sig = base64.b64decode(proof.get("ed25519Signature", ""))

        # Locate public keys from verification methods
        mldsa_pub_bytes = None
        ed25519_pub_bytes = None

        for vm in doc.verification_method:
            mb = vm.get("publicKeyMultibase", "")
            if mb.startswith("u"):
                raw_bytes = base64.b64decode(mb[1:])
                if vm.get("type") == "MLDSA65VerificationKey2026":
                    mldsa_pub_bytes = raw_bytes
                elif vm.get("type") == "Ed25519VerificationKey2020":
                    ed25519_pub_bytes = raw_bytes

        if not mldsa_pub_bytes or not ed25519_pub_bytes:
            return False

        canonical = doc.canonical_bytes()
        return PQCDigitalSignature.verify_hybrid(
            canonical,
            mldsa_sig,
            ed25519_sig,
            mldsa_pub_bytes,
            ed25519_pub_bytes,
        )
