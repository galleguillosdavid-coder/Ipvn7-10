"""
IPVN 7 Plumtree Epidemic Gossip Protocol (L2 Mesh Dissemination)
Deterministic spanning tree broadcast with Eager Push, Lazy Metadata Announcement,
PRUNE for tree optimization, and GRAFT for self-healing.
Inspired by ipvn7 vX7 pkg/l2/plumtree_gossip.go.
"""

from __future__ import annotations
import hashlib
import time
import threading
from typing import Dict, Set, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field


@dataclass
class PlumtreeMessage:
    msg_id: str
    origin_did: str
    payload: bytes
    hop_count: int
    timestamp_ns: int


class PlumtreeEngine:
    """
    Manages epidemic broadcast across the small-world mesh.
    Divides peers into:
      - eager_peers: immediate push of full payload (tree branches)
      - lazy_peers: periodic IHAVE announcements (mesh redundancy)
    """

    def __init__(
        self,
        local_did: str,
        graft_timeout_sec: float = 0.25,
        cache_ttl_sec: float = 300.0,
        send_func: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
        deliver_func: Optional[Callable[[PlumtreeMessage], None]] = None,
    ):
        self.local_did = local_did
        self.graft_timeout = graft_timeout_sec
        self.cache_ttl = cache_ttl_sec
        self.send_func = send_func or (lambda target_did, msg_type, data: None)
        self.deliver_func = deliver_func or (lambda msg: None)

        self.eager_peers: Set[str] = set()
        self.lazy_peers: Set[str] = set()
        self.seen_cache: Dict[str, float] = {}
        self.payload_store: Dict[str, PlumtreeMessage] = {}
        self.pending_ihave: Dict[str, Dict[str, float]] = {}  # msg_id -> {peer_did: timestamp}

        self.stats = {
            "broadcasts_initiated": 0,
            "messages_delivered": 0,
            "ihave_received": 0,
            "grafts_sent": 0,
            "prunes_sent": 0,
            "duplicates_suppressed": 0,
        }
        self._lock = threading.Lock()

    def add_peer(self, peer_did: str) -> None:
        """Adds a peer, defaulting to eager set."""
        if not peer_did or peer_did == self.local_did:
            return
        with self._lock:
            if peer_did not in self.lazy_peers:
                self.eager_peers.add(peer_did)

    def remove_peer(self, peer_did: str) -> None:
        """Removes a peer from all sets."""
        with self._lock:
            self.eager_peers.discard(peer_did)
            self.lazy_peers.discard(peer_did)

    def broadcast(self, payload: bytes) -> PlumtreeMessage:
        """Initiates a network-wide epidemic broadcast from this node."""
        h = hashlib.sha256(self.local_did.encode() + payload).hexdigest()[:16]
        msg = PlumtreeMessage(
            msg_id=h,
            origin_did=self.local_did,
            payload=payload,
            hop_count=0,
            timestamp_ns=time.time_ns(),
        )

        with self._lock:
            self.seen_cache[h] = time.time()
            self.payload_store[h] = msg
            self.stats["broadcasts_initiated"] += 1
            eagers = list(self.eager_peers)
            lazies = list(self.lazy_peers)

        # 1. Push payload eagerly to tree neighbors
        for p in eagers:
            self.send_func(p, "GOSSIP_EAGER", {
                "msg_id": msg.msg_id,
                "origin_did": msg.origin_did,
                "payload": msg.payload.hex(),
                "hop_count": 0,
            })

        # 2. Announce metadata lazily
        for p in lazies:
            self.send_func(p, "GOSSIP_IHAVE", {
                "msg_id": msg.msg_id,
                "origin_did": msg.origin_did,
            })

        return msg

    def handle_eager_message(
        self,
        sender_did: str,
        msg_id: str,
        origin_did: str,
        payload_bytes: bytes,
        hop_count: int,
    ) -> bool:
        """
        Processes incoming full message. If already seen, PRUNE sender.
        If first time, deliver locally and push down to remaining eager peers.
        """
        with self._lock:
            now = time.time()
            if msg_id in self.seen_cache and (now - self.seen_cache[msg_id]) < self.cache_ttl:
                # Duplicate! Send PRUNE to optimize tree and move sender to lazy set
                self.stats["duplicates_suppressed"] += 1
                self.stats["prunes_sent"] += 1
                self.eager_peers.discard(sender_did)
                self.lazy_peers.add(sender_did)
                need_prune = True
                forward = False
            else:
                self.seen_cache[msg_id] = now
                msg = PlumtreeMessage(
                    msg_id=msg_id,
                    origin_did=origin_did,
                    payload=payload_bytes,
                    hop_count=hop_count + 1,
                    timestamp_ns=time.time_ns(),
                )
                self.payload_store[msg_id] = msg
                self.stats["messages_delivered"] += 1
                self.pending_ihave.pop(msg_id, None)
                need_prune = False
                forward = True
                eagers = [p for p in self.eager_peers if p != sender_did]
                lazies = [p for p in self.lazy_peers if p != sender_did]

        if need_prune:
            self.send_func(sender_did, "GOSSIP_PRUNE", {"msg_id": msg_id})
            return False

        if forward:
            self.deliver_func(msg)
            # Forward eager
            for p in eagers:
                self.send_func(p, "GOSSIP_EAGER", {
                    "msg_id": msg.msg_id,
                    "origin_did": msg.origin_did,
                    "payload": payload_bytes.hex(),
                    "hop_count": msg.hop_count,
                })
            # Announce lazy
            for p in lazies:
                self.send_func(p, "GOSSIP_IHAVE", {
                    "msg_id": msg.msg_id,
                    "origin_did": msg.origin_did,
                })
            return True
        return False

    def handle_prune(self, sender_did: str) -> None:
        """Sender requested to be pruned from eager tree into lazy set."""
        with self._lock:
            self.eager_peers.discard(sender_did)
            self.lazy_peers.add(sender_did)

    def handle_graft(self, sender_did: str, msg_id: str) -> Optional[bytes]:
        """Sender needs the payload because they didn't receive it eagerly. Graft back."""
        with self._lock:
            self.lazy_peers.discard(sender_did)
            self.eager_peers.add(sender_did)
            msg = self.payload_store.get(msg_id)
            if msg:
                return msg.payload
        return None

    def handle_ihave(self, sender_did: str, msg_id: str) -> None:
        """Received metadata announcement."""
        with self._lock:
            self.stats["ihave_received"] += 1
            if msg_id in self.seen_cache:
                return  # Already delivered
            if msg_id not in self.pending_ihave:
                self.pending_ihave[msg_id] = {}
            self.pending_ihave[msg_id][sender_did] = time.time()

    def check_pending_grafts(self) -> List[Tuple[str, str]]:
        """
        Finds messages announced via IHAVE that haven't arrived eagerly before timeout.
        Returns list of (target_peer_did, msg_id) to GRAFT.
        """
        now = time.time()
        grafts_to_send = []
        with self._lock:
            for msg_id, senders in list(self.pending_ihave.items()):
                if msg_id in self.seen_cache:
                    del self.pending_ihave[msg_id]
                    continue
                # Pick first peer that offered it
                for peer, t in senders.items():
                    if (now - t) >= self.graft_timeout:
                        grafts_to_send.append((peer, msg_id))
                        self.stats["grafts_sent"] += 1
                        self.lazy_peers.discard(peer)
                        self.eager_peers.add(peer)
                        break
        return grafts_to_send
