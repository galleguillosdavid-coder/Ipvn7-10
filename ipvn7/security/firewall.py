"""
IPVN 7 Zero-Trust Network Access (ZTNA) Firewall Engine
Implements strict Default-Deny micro-segmentation per Decentralized Identity (DID).
Key possession proves identity, never authorization.
Inspired by ipvn7 vX7 pkg/l1/firewall.go.
"""

from __future__ import annotations
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class FirewallDecision(Enum):
    ACCEPT = "ACCEPT"
    DROP_DEFAULT_DENY = "DROP_DEFAULT_DENY"
    DROP_ACL = "DROP_ACL"
    DROP_EXPIRED = "DROP_EXPIRED"


@dataclass
class DIDPolicy:
    did: str
    allow_inbound: bool = True
    allow_outbound: bool = True
    allow_relay: bool = False
    allowed_ports: List[int] = field(default_factory=list)  # Empty allows all virtual ports
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None  # None = permanent

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class ZTNAFirewall:
    """
    Zero-Trust Microsegmentation Engine.
    Filters datagrams based on explicit cryptographic DID authorization.
    """

    def __init__(self, default_deny: bool = True):
        self.default_deny = default_deny
        self.policies: Dict[str, DIDPolicy] = {}
        self.stats = {
            "packets_evaluated": 0,
            "packets_accepted": 0,
            "packets_dropped_default_deny": 0,
            "packets_dropped_acl": 0,
            "packets_dropped_expired": 0,
        }

    def set_default_deny(self, enabled: bool) -> None:
        self.default_deny = enabled

    def authorize_did(self, policy: DIDPolicy) -> None:
        """Grants explicit granular permissions to a DID."""
        self.policies[policy.did] = policy

    def set_policy(
        self,
        did: str,
        allow_inbound: bool = True,
        allow_outbound: bool = True,
        allow_relay: bool = False,
        allowed_ports: Optional[List[int]] = None,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        """Sets or updates granular permissions for a DID."""
        exp = (time.time() + ttl_seconds) if ttl_seconds else None
        self.authorize_did(
            DIDPolicy(
                did=did,
                allow_inbound=allow_inbound,
                allow_outbound=allow_outbound,
                allow_relay=allow_relay,
                allowed_ports=allowed_ports or [],
                expires_at=exp,
            )
        )

    def revoke_did(self, did: str) -> None:
        """Removes explicit policy for a DID."""
        self.policies.pop(did, None)

    def get_policy(self, did: str) -> Optional[DIDPolicy]:
        return self.policies.get(did)

    def evaluate_inbound(self, src_did: str, port: int = 0) -> FirewallDecision:
        """Evaluates whether an inbound packet from src_did should be accepted."""
        self.stats["packets_evaluated"] += 1

        policy = self.policies.get(src_did)
        if policy is None:
            if self.default_deny:
                self.stats["packets_dropped_default_deny"] += 1
                return FirewallDecision.DROP_DEFAULT_DENY
            self.stats["packets_accepted"] += 1
            return FirewallDecision.ACCEPT

        if policy.is_expired():
            self.stats["packets_dropped_expired"] += 1
            return FirewallDecision.DROP_EXPIRED

        if not policy.allow_inbound:
            self.stats["packets_dropped_acl"] += 1
            return FirewallDecision.DROP_ACL

        if policy.allowed_ports and port != 0 and port not in policy.allowed_ports:
            self.stats["packets_dropped_acl"] += 1
            return FirewallDecision.DROP_ACL

        self.stats["packets_accepted"] += 1
        return FirewallDecision.ACCEPT

    def evaluate_outbound(self, dst_did: str, port: int = 0) -> FirewallDecision:
        """Evaluates whether an outbound packet to dst_did should be sent."""
        self.stats["packets_evaluated"] += 1

        policy = self.policies.get(dst_did)
        if policy is None:
            if self.default_deny:
                self.stats["packets_dropped_default_deny"] += 1
                return FirewallDecision.DROP_DEFAULT_DENY
            self.stats["packets_accepted"] += 1
            return FirewallDecision.ACCEPT

        if policy.is_expired():
            self.stats["packets_dropped_expired"] += 1
            return FirewallDecision.DROP_EXPIRED

        if not policy.allow_outbound:
            self.stats["packets_dropped_acl"] += 1
            return FirewallDecision.DROP_ACL

        if policy.allowed_ports and port != 0 and port not in policy.allowed_ports:
            self.stats["packets_dropped_acl"] += 1
            return FirewallDecision.DROP_ACL

        self.stats["packets_accepted"] += 1
        return FirewallDecision.ACCEPT

    def evaluate_relay(self, transit_did: str) -> FirewallDecision:
        """Evaluates whether this node should relay transit traffic for transit_did."""
        self.stats["packets_evaluated"] += 1

        policy = self.policies.get(transit_did)
        if policy is None:
            if self.default_deny:
                self.stats["packets_dropped_default_deny"] += 1
                return FirewallDecision.DROP_DEFAULT_DENY
            self.stats["packets_accepted"] += 1
            return FirewallDecision.ACCEPT

        if policy.is_expired():
            self.stats["packets_dropped_expired"] += 1
            return FirewallDecision.DROP_EXPIRED

        if not policy.allow_relay:
            self.stats["packets_dropped_acl"] += 1
            return FirewallDecision.DROP_ACL

        self.stats["packets_accepted"] += 1
        return FirewallDecision.ACCEPT
