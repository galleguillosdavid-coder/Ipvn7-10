"""
IPVN 7 Decentralized Web-of-Trust (WoT) & Transitive Reputation Engine
Calculates attenuated trust scores across degrees of separation to prevent Sybil attacks
and provide decentralized identity attestation for Zero-Trust authorization.
Inspired by ipvn7 vX7 pkg/l1/wot.go.
"""

from __future__ import annotations
import hashlib
import time
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

from ..crypto.pqc import PQCKeyPair


@dataclass
class Vouch:
    issuer_did: str
    subject_did: str
    trust_level: float   # 0.0 to 1.0
    reason: str
    issued_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    signature: Optional[bytes] = None

    def compute_hash(self) -> bytes:
        h = hashlib.sha256()
        h.update(self.issuer_did.encode())
        h.update(self.subject_did.encode())
        h.update(f"{self.trust_level:.4f}".encode())
        h.update(self.reason.encode())
        h.update(str(int(self.issued_at)).encode())
        if self.expires_at:
            h.update(str(int(self.expires_at)).encode())
        return h.digest()

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class WebOfTrust:
    """
    Decentralized Web of Trust graph.
    Computes transitive trust paths up to max_hops with attenuation factor.
    """

    def __init__(self, attenuation: float = 0.85, max_hops: int = 3):
        self.attenuation = attenuation
        self.max_hops = max_hops
        # issuer_did -> list of vouches issued
        self.vouches_by_issuer: Dict[str, List[Vouch]] = {}
        # subject_did -> list of vouches received
        self.vouches_by_subject: Dict[str, List[Vouch]] = {}

    def issue_vouch(
        self,
        issuer_keypair: PQCKeyPair,
        issuer_did: str,
        subject_did: str,
        trust_level: float,
        reason: str,
        ttl_seconds: Optional[float] = 86400.0 * 30,  # 30 days
    ) -> Vouch:
        """Issues and signs a cryptographic vouch."""
        if not (0.0 <= trust_level <= 1.0):
            raise ValueError("trust_level must be between 0.0 and 1.0")

        now = time.time()
        exp = now + ttl_seconds if ttl_seconds else None

        v = Vouch(
            issuer_did=issuer_did,
            subject_did=subject_did,
            trust_level=trust_level,
            reason=reason,
            issued_at=now,
            expires_at=exp,
        )
        h = v.compute_hash()
        # Sign with Ed25519
        v.signature = issuer_keypair.ed25519_priv.sign(h)

        self.add_vouch(v)
        return v

    def add_vouch(self, vouch: Vouch) -> bool:
        """Validates and stores a signed vouch."""
        if vouch.is_expired():
            return False

        if vouch.issuer_did not in self.vouches_by_issuer:
            self.vouches_by_issuer[vouch.issuer_did] = []
        self.vouches_by_issuer[vouch.issuer_did].append(vouch)

        if vouch.subject_did not in self.vouches_by_subject:
            self.vouches_by_subject[vouch.subject_did] = []
        self.vouches_by_subject[vouch.subject_did].append(vouch)

        return True

    def compute_trust(self, root_did: str, target_did: str) -> float:
        """
        Computes transitive trust score from root_did to target_did.
        Uses BFS with geometric attenuation: Trust(d) = BaseTrust * (attenuation ^ distance).
        Returns float in range [0.0, 1.0].
        """
        if root_did == target_did:
            return 1.0

        # Queue: (current_did, current_trust, distance, visited_set)
        queue: List[tuple[str, float, int, Set[str]]] = [(root_did, 1.0, 0, {root_did})]
        max_trust = 0.0

        while queue:
            curr_did, curr_trust, dist, visited = queue.pop(0)

            if dist >= self.max_hops:
                continue

            vouches = self.vouches_by_issuer.get(curr_did, [])
            for v in vouches:
                if v.is_expired() or v.subject_did in visited:
                    continue

                attenuated_score = curr_trust * v.trust_level * (self.attenuation if dist > 0 else 1.0)

                if v.subject_did == target_did:
                    if attenuated_score > max_trust:
                        max_trust = attenuated_score
                else:
                    new_visited = set(visited)
                    new_visited.add(v.subject_did)
                    queue.append((v.subject_did, attenuated_score, dist + 1, new_visited))

        return round(min(1.0, max_trust), 4)

    def get_vouches_received(self, subject_did: str) -> List[Dict[str, Any]]:
        """Returns all active vouches received by subject_did."""
        vouches = self.vouches_by_subject.get(subject_did, [])
        return [
            {
                "issuer": v.issuer_did,
                "trust_level": v.trust_level,
                "reason": v.reason,
                "issued_at": v.issued_at,
                "expired": v.is_expired(),
            }
            for v in vouches if not v.is_expired()
        ]
