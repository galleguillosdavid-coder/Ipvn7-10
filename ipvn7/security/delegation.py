"""
IPVN 7 Agentic Principal Chain (APC) & Adaptive Authorization
Implementa delegación criptográfica jerárquica de permisos conforme al borrador
IETF draft-das-agentic-adaptive-authorization-00. Permite a una identidad raíz
subordinar permisos graduados a sub-agentes, satélites y microservicios mediante
firmas digitales Ed25519 con atenuación monotónica estricta.
Inspirado en ipvn7 vX7 pkg/l0/delegation.go.
"""

from __future__ import annotations
import time
import hashlib
from enum import Enum
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey


class ExecutionTier(str, Enum):
    ORDINARY = "ordinary"       # Lectura, telemetría, estado de red
    ESCALATED = "escalated"     # Control de VPN, enrutamiento, puentes LAN, firewall
    QUARANTINE = "quarantine"   # No verificado / aislado
    DENY = "deny"               # Acceso bloqueado o revocado


# Jerarquía estricta para atenuación monotónica
TIER_PRIORITY = {
    ExecutionTier.DENY: 0,
    ExecutionTier.QUARANTINE: 1,
    ExecutionTier.ORDINARY: 2,
    ExecutionTier.ESCALATED: 3,
}


@dataclass
class DelegationLink:
    issuer_did: str
    subject_did: str
    scope: str
    tier: ExecutionTier
    expires_at: float
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Produce la representación canónica determinista para la firma Ed25519."""
        raw = f"{self.issuer_did}|{self.subject_did}|{self.scope}|{self.tier.value}|{int(self.expires_at)}"
        return hashlib.sha256(raw.encode("utf-8")).digest()

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        """Firma el eslabón con la clave privada Ed25519 del emisor."""
        sig = private_key.sign(self.canonical_bytes())
        self.signature = sig.hex()

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        """Comprueba la firma digital Ed25519 del emisor."""
        if not self.signature:
            return False
        try:
            sig_bytes = bytes.fromhex(self.signature)
            public_key.verify(sig_bytes, self.canonical_bytes())
            return True
        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issuer_did": self.issuer_did,
            "subject_did": self.subject_did,
            "scope": self.scope,
            "tier": self.tier.value,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }


@dataclass
class AgenticPrincipalChain:
    """
    Cadena de custodia verificable de delegación de capacidades para agentes y procesos.
    """
    root_did: str
    links: List[DelegationLink] = field(default_factory=list)

    def add_link(self, link: DelegationLink) -> None:
        self.links.append(link)

    def verify_chain(self, public_keys_by_did: Dict[str, Ed25519PublicKey]) -> Tuple[bool, ExecutionTier, str]:
        """
        Valida la cadena de custodia completa, firmas Ed25519 y atenuación monotónica de privilegios.
        """
        if not self.links:
            return False, ExecutionTier.QUARANTINE, "Cadena de delegación vacía"

        now = time.time()
        effective_tier = ExecutionTier.ESCALATED

        for i, link in enumerate(self.links):
            # 1. Validación de cadena de custodia (primer eslabón coincide con RootDID)
            if i == 0:
                if link.issuer_did != self.root_did:
                    return False, ExecutionTier.DENY, f"Primer eslabón no coincide con RootDID {self.root_did}"
            else:
                if link.issuer_did != self.links[i - 1].subject_did:
                    return False, ExecutionTier.DENY, f"Ruptura de custodia en eslabón {i}: {link.issuer_did} != {self.links[i-1].subject_did}"

            # 2. Expiración TTL
            if now > link.expires_at:
                return False, ExecutionTier.DENY, f"Eslabón {i} expirado por TTL"

            # 3. Comprobación de firma Ed25519
            pub = public_keys_by_did.get(link.issuer_did)
            if not pub or not link.verify(pub):
                return False, ExecutionTier.DENY, f"Firma criptográfica inválida en eslabón {i} para {link.issuer_did}"

            # 4. Atenuación Monotónica estricta: el nivel solo puede descender o mantenerse
            if TIER_PRIORITY[link.tier] < TIER_PRIORITY[effective_tier]:
                effective_tier = link.tier

        return True, effective_tier, f"Cadena válida con nivel efectivo: {effective_tier.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_did": self.root_did,
            "links_count": len(self.links),
            "links": [l.to_dict() for l in self.links],
        }
