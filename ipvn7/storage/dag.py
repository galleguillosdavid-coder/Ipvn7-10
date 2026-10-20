"""
IPVN 7 Content-Addressed DAG Store & Delay-Tolerant Networking (DTN)
Immutable content-addressed data blocks linked by causal CIDs and signed with DIDs.
Enables asynchronous store-and-forward messaging across intermittent mesh partitions.
Inspired by ipvn7 vX7 pkg/l1/dag_store.go.
"""

from __future__ import annotations
import hashlib
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from ..crypto.pqc import PQCKeyPair


@dataclass
class DAGBlock:
    cid: str               # "cid:ipvn7:<sha256>"
    author_did: str
    target_did: str        # Empty string for global broadcast/mesh publication
    parents: List[str]     # CIDs of causal ancestor blocks
    timestamp: float
    data: bytes
    signature: bytes       # Ed25519 signature over CID

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cid": self.cid,
            "author_did": self.author_did,
            "target_did": self.target_did,
            "parents": self.parents,
            "timestamp": self.timestamp,
            "data_bytes": len(self.data),
            "data_preview": self.data.decode("utf-8", errors="replace")[:120],
        }


def compute_cid(author_did: str, parents: List[str], data: bytes, ts: float) -> str:
    """Calculates immutable content identifier (CID) for a DAG block."""
    h = hashlib.sha256()
    h.update(author_did.encode("utf-8"))
    for p in sorted(parents):
        h.update(p.encode("utf-8"))
    h.update(str(int(ts * 1e6)).encode("utf-8"))
    h.update(data)
    return f"cid:ipvn7:{h.hexdigest()}"


class DAGStore:
    """
    Decentralized DAG Store and DTN Bundle Queue.
    Manages content persistence and asynchronous delivery to intermittent nodes.
    """

    def __init__(self, local_did: str, keypair: PQCKeyPair):
        self.local_did = local_did
        self.keypair = keypair
        self.blocks: Dict[str, DAGBlock] = {}
        self.heads: List[str] = []
        # target_did -> list of pending blocks for store-and-forward DTN delivery
        self.pending_dtn_queue: Dict[str, List[DAGBlock]] = {}

        self.stats = {
            "blocks_stored": 0,
            "bundles_queued_dtn": 0,
            "bundles_delivered_dtn": 0,
        }

    def put_block(
        self,
        data: bytes,
        parents: Optional[List[str]] = None,
        target_did: str = "",
    ) -> DAGBlock:
        """Creates, signs and commits a new immutable block to the DAG."""
        if parents is None or len(parents) == 0:
            parents = list(self.heads)

        now = time.time()
        cid = compute_cid(self.local_did, parents, data, now)
        sig = self.keypair.ed25519_priv.sign(cid.encode("utf-8"))

        block = DAGBlock(
            cid=cid,
            author_did=self.local_did,
            target_did=target_did,
            parents=parents,
            timestamp=now,
            data=data,
            signature=sig,
        )

        self.blocks[cid] = block
        self.heads = [cid]
        self.stats["blocks_stored"] += 1

        # If designated for a remote peer, queue in DTN store-and-forward
        if target_did and target_did != self.local_did:
            if target_did not in self.pending_dtn_queue:
                self.pending_dtn_queue[target_did] = []
            self.pending_dtn_queue[target_did].append(block)
            self.stats["bundles_queued_dtn"] += 1

        return block

    def get_block(self, cid: str) -> Optional[DAGBlock]:
        return self.blocks.get(cid)

    def flush_dtn_queue(self, target_did: str) -> List[DAGBlock]:
        """Flushes and returns all pending DTN blocks when target node reconnects."""
        pending = self.pending_dtn_queue.pop(target_did, [])
        self.stats["bundles_delivered_dtn"] += len(pending)
        return pending

    def get_recent_blocks(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Returns metadata for recent blocks."""
        all_blocks = list(self.blocks.values())
        all_blocks.sort(key=lambda b: b.timestamp, reverse=True)
        return [b.to_dict() for b in all_blocks[:limit]]
