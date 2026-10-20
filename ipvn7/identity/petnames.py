"""
IPVN 7 Decentralized DNS (dDNS) & Petnames Resolver
Implements local mnemonic human-readable name mapping (.ipv7) to Decentralized Identifiers (DIDs)
and synthetic virtual IPs without central authorities (ICANN-free Zooko's Triangle resolution).
Inspired by ipvn7 vX7 pkg/l4/ddns_petnames.go.
"""

from __future__ import annotations
import hashlib
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field


@dataclass
class PetnameRecord:
    name: str              # Normalized name ending in .ipv7 (e.g., laptop.ipv7)
    did: str               # Target sovereign DID (did:ipvn7:...)
    virtual_ipv6: str      # Associated sovereign IPv6 (e.g., fd07::...)
    virtual_ipv4: str      # Synthetic local IPv4 (e.g., 10.7.0.x)
    context_root: str = "" # Optional local namespace/context isolation
    assigned_at: float = field(default_factory=time.time)
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "did": self.did,
            "virtual_ipv6": self.virtual_ipv6,
            "virtual_ipv4": self.virtual_ipv4,
            "context_root": self.context_root,
            "assigned_at": self.assigned_at,
            "comment": self.comment,
        }


def normalize_name(name: str) -> str:
    """Ensures name is lowercase and ends with .ipv7 suffix."""
    clean = name.strip().lower()
    if not clean.endswith(".ipv7"):
        clean += ".ipv7"
    return clean


def build_lookup_key(name: str, context_root: str = "") -> str:
    """Builds lookup key scoped by context hash if provided."""
    clean = normalize_name(name)
    if context_root:
        h = hashlib.sha256(context_root.encode("utf-8")).hexdigest()[:8]
        stripped = clean[len(h) + 1:] if clean.startswith(h + ".") else clean
        return f"{h}.{stripped}"
    return clean


class PetnameResolver:
    """
    Decentralized Petname address book and local dDNS engine.
    Allows human users and apps to address nodes via memorable names.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.records: Dict[str, PetnameRecord] = {}
        self.reverse_index: Dict[str, str] = {}  # DID -> canonical petname

    def register_petname(
        self,
        name: str,
        did: str,
        virtual_ipv6: str = "",
        virtual_ipv4: str = "",
        context_root: str = "",
        comment: str = "",
    ) -> PetnameRecord:
        """Registers or updates a local petname record."""
        if not did:
            raise ValueError("Target DID cannot be empty")

        key = build_lookup_key(name, context_root)

        # Auto-synthesize IPs if omitted
        if not virtual_ipv6:
            did_hash = hashlib.sha256(did.encode()).hexdigest()
            virtual_ipv6 = f"fd07:{did_hash[:4]}:{did_hash[4:8]}::{did_hash[8:12]}"
        if not virtual_ipv4:
            b = hashlib.sha256(did.encode()).digest()
            virtual_ipv4 = f"10.7.{b[0]}.{b[1]}"

        with self._lock:
            rec = PetnameRecord(
                name=key,
                did=did,
                virtual_ipv6=virtual_ipv6,
                virtual_ipv4=virtual_ipv4,
                context_root=context_root,
                assigned_at=time.time(),
                comment=comment,
            )
            self.records[key] = rec
            self.reverse_index[did] = key
            return rec

    def resolve(self, name: str, context_root: str = "") -> Optional[PetnameRecord]:
        """Resolves a human name to a PetnameRecord."""
        key = build_lookup_key(name, context_root)
        with self._lock:
            return self.records.get(key)

    def reverse_lookup(self, did: str) -> Optional[str]:
        """Looks up the human name assigned to a DID."""
        with self._lock:
            return self.reverse_index.get(did)

    def unregister(self, name: str, context_root: str = "") -> bool:
        """Removes a petname entry."""
        key = build_lookup_key(name, context_root)
        with self._lock:
            rec = self.records.pop(key, None)
            if rec:
                self.reverse_index.pop(rec.did, None)
                return True
            return False

    def list_records(self) -> List[Dict[str, Any]]:
        """Returns all registered records."""
        with self._lock:
            return [r.to_dict() for r in self.records.values()]
