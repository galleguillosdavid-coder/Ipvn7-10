"""
IPVN 7 Sphinx Onion Routing Engine (3-Hop Privacy Preserving Datagrams)
Deterministic 1280-byte wire framing, iterative cryptographic peeling,
and O(1) anti-replay protection.
Inspired by ipvn7 vX7 pkg/l1/sphinx_onion.go and sphinx_builder.go.
"""

from __future__ import annotations
import hashlib
import time
from typing import List, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

SPHINX_PACKET_SIZE = 1280
SPHINX_HOPS_COUNT = 3
SPHINX_HOP_KEY_SIZE = 64     # 32-byte ephemeral key + 32-byte auth tag/seed
SPHINX_KEY_HEADER_SIZE = SPHINX_HOPS_COUNT * SPHINX_HOP_KEY_SIZE  # 192 bytes
SPHINX_HOP_DESC_SIZE = 96    # Descriptor per hop (next DID locator + flags)
SPHINX_ROUTING_INFO_SIZE = SPHINX_HOPS_COUNT * SPHINX_HOP_DESC_SIZE  # 288 bytes
SPHINX_PAYLOAD_SIZE = SPHINX_PACKET_SIZE - SPHINX_KEY_HEADER_SIZE - SPHINX_ROUTING_INFO_SIZE  # 800 bytes

ACTION_FORWARD = "FORWARD"
ACTION_DELIVER = "DELIVER"
ACTION_DROP = "DROP"


def _chacha20_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Symmetric stream encryption/decryption using pure ChaCha20 (exact wire length preserved)."""
    cipher = Cipher(algorithms.ChaCha20(key[:32], nonce[:16]), None)
    encryptor = cipher.encryptor()
    return encryptor.update(data)


@dataclass
class SphinxHop:
    node_did: str
    locator: str
    shared_secret: bytes


@dataclass
class SphinxPacket:
    key_header: bytes      # 192 bytes
    routing_info: bytes    # 288 bytes
    payload: bytes         # 800 bytes

    def serialize(self) -> bytes:
        data = self.key_header + self.routing_info + self.payload
        if len(data) < SPHINX_PACKET_SIZE:
            data += b"\x00" * (SPHINX_PACKET_SIZE - len(data))
        return data[:SPHINX_PACKET_SIZE]

    @classmethod
    def deserialize(cls, raw: bytes) -> "SphinxPacket":
        if len(raw) < SPHINX_PACKET_SIZE:
            raw = raw.ljust(SPHINX_PACKET_SIZE, b"\x00")
        k_hdr = raw[:SPHINX_KEY_HEADER_SIZE]
        r_info = raw[SPHINX_KEY_HEADER_SIZE:SPHINX_KEY_HEADER_SIZE + SPHINX_ROUTING_INFO_SIZE]
        pay = raw[SPHINX_KEY_HEADER_SIZE + SPHINX_ROUTING_INFO_SIZE:SPHINX_PACKET_SIZE]
        return cls(key_header=k_hdr, routing_info=r_info, payload=pay)


@dataclass
class PeelResult:
    action: str
    next_hop_did: Optional[str]
    next_locator: Optional[str]
    next_packet: Optional[SphinxPacket]
    delivered_payload: Optional[bytes]
    tag_hash: str
    elapsed_us: float


class SphinxRouter:
    """
    Manages circuit establishment, 3-hop onion packet synthesis,
    and single-pass cryptographic peeling with O(1) replay prevention.
    """

    def __init__(self, node_did: str):
        self.node_did = node_did
        self.replay_cache: dict[str, float] = {}
        self.replay_order: list[str] = []
        self.max_cache = 10000

    def clean_expired(self) -> None:
        now = time.time()
        while self.replay_order:
            oldest = self.replay_order[0]
            if self.replay_cache.get(oldest, 0) < now:
                self.replay_order.pop(0)
                self.replay_cache.pop(oldest, None)
            else:
                break

    def build_packet(
        self,
        hops: List[SphinxHop],
        final_payload: bytes,
    ) -> SphinxPacket:
        """
        Builds a 3-hop layered Sphinx onion packet from inside out.
        hops: list of 3 hops [Hop1, Hop2, Hop3 (Destination)].
        """
        if len(hops) != SPHINX_HOPS_COUNT:
            raise ValueError(f"Sphinx circuit requires exactly {SPHINX_HOPS_COUNT} hops")

        # 1. Pad final payload to SPHINX_PAYLOAD_SIZE (800 bytes)
        raw_payload = len(final_payload).to_bytes(4, "big") + final_payload
        current_payload = raw_payload.ljust(SPHINX_PAYLOAD_SIZE, b"\x00")
        routing_layers: List[bytes] = []

        # Build routing descriptors backwards (Exit to Hop 1)
        for i in range(SPHINX_HOPS_COUNT - 1, -1, -1):
            hop = hops[i]
            is_exit = (i == SPHINX_HOPS_COUNT - 1)
            next_hop = hops[i + 1] if not is_exit else None

            desc = bytearray(SPHINX_HOP_DESC_SIZE)
            desc[0] = 0x01 if is_exit else 0x00
            if next_hop:
                did_bytes = next_hop.node_did.encode("utf-8")[:48]
                desc[1:1 + len(did_bytes)] = did_bytes
                loc_bytes = next_hop.locator.encode("utf-8")[:32]
                desc[50:50 + len(loc_bytes)] = loc_bytes

            # Encrypt descriptor with hop's key
            d_key = hashlib.sha256(hop.shared_secret + b"desc_key").digest()
            d_nonce = hashlib.sha256(hop.shared_secret + b"desc_nonce").digest()[:16]
            enc_desc = _chacha20_crypt(d_key, d_nonce, bytes(desc))
            routing_layers.insert(0, enc_desc)

            # Layer payload encryption backwards
            p_key = hashlib.sha256(hop.shared_secret + b"payload_key").digest()
            p_nonce = hashlib.sha256(hop.shared_secret + b"payload_nonce").digest()[:16]
            current_payload = _chacha20_crypt(p_key, p_nonce, current_payload)

        # Key headers
        key_headers = bytearray()
        for i, hop in enumerate(hops):
            eph_key = hashlib.sha256(hop.shared_secret + f"eph{i}".encode()).digest()
            key_tag = hashlib.sha256(hop.shared_secret + f"tag{i}".encode()).digest()
            key_headers.extend(eph_key + key_tag)

        routing_info = b"".join(routing_layers)
        return SphinxPacket(
            key_header=bytes(key_headers),
            routing_info=routing_info,
            payload=current_payload,
        )

    def peel_layer(self, packet: SphinxPacket, hop_secret: bytes) -> PeelResult:
        """
        Unwraps one layer of onion encryption using hop_secret.
        Detects replays, decodes action, shifts headers, and returns peeled packet or payload.
        """
        t0 = time.perf_counter()
        self.clean_expired()

        # 1. Anti-replay tag
        tag_slot = packet.key_header[:SPHINX_HOP_KEY_SIZE]
        tag_hash = hashlib.sha256(tag_slot).hexdigest()

        now = time.time()
        if tag_hash in self.replay_cache and self.replay_cache[tag_hash] > now:
            elapsed = (time.perf_counter() - t0) * 1e6
            return PeelResult(
                action=ACTION_DROP,
                next_hop_did=None,
                next_locator=None,
                next_packet=None,
                delivered_payload=None,
                tag_hash=tag_hash,
                elapsed_us=elapsed,
            )

        self.replay_cache[tag_hash] = now + 300.0  # 5 min TTL
        self.replay_order.append(tag_hash)

        # 2. Decrypt current routing descriptor
        desc_slot = packet.routing_info[:SPHINX_HOP_DESC_SIZE]
        d_key = hashlib.sha256(hop_secret + b"desc_key").digest()
        d_nonce = hashlib.sha256(hop_secret + b"desc_nonce").digest()[:16]
        plain_desc = _chacha20_crypt(d_key, d_nonce, desc_slot)

        is_exit = plain_desc[0] == 0x01
        next_did = plain_desc[1:49].decode("utf-8", errors="ignore").rstrip("\x00")
        next_loc = plain_desc[50:82].decode("utf-8", errors="ignore").rstrip("\x00")

        # 3. Decrypt payload layer
        p_key = hashlib.sha256(hop_secret + b"payload_key").digest()
        p_nonce = hashlib.sha256(hop_secret + b"payload_nonce").digest()[:16]
        dec_payload = _chacha20_crypt(p_key, p_nonce, packet.payload)

        elapsed = (time.perf_counter() - t0) * 1e6

        if is_exit:
            # Final delivery
            payload_len = int.from_bytes(dec_payload[:4], "big")
            final_data = dec_payload[4:4 + payload_len] if payload_len > 0 else dec_payload[4:]
            return PeelResult(
                action=ACTION_DELIVER,
                next_hop_did=None,
                next_locator=None,
                next_packet=None,
                delivered_payload=final_data,
                tag_hash=tag_hash,
                elapsed_us=elapsed,
            )

        # Forwarding: Shift key header and routing info
        new_k_hdr = packet.key_header[SPHINX_HOP_KEY_SIZE:] + (b"\x00" * SPHINX_HOP_KEY_SIZE)
        new_r_info = packet.routing_info[SPHINX_HOP_DESC_SIZE:] + (b"\x00" * SPHINX_HOP_DESC_SIZE)
        next_pkt = SphinxPacket(
            key_header=new_k_hdr,
            routing_info=new_r_info,
            payload=dec_payload,
        )

        return PeelResult(
            action=ACTION_FORWARD,
            next_hop_did=next_did or None,
            next_locator=next_loc or None,
            next_packet=next_pkt,
            delivered_payload=None,
            tag_hash=tag_hash,
            elapsed_us=elapsed,
        )
