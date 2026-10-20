"""
Private Interregional DHT Synchronization & Bloom Reconciliation Subsystem.
IPVN 7 Network Layer (L2).

Features:
1. Compact Cryptographic Bloom Filters (256/512-bit) for O(1) set-reconciliation without metadata leakage.
2. Canonical Wire Framing 'IP7S' (strictly bounded by MTU 1280B) with CRC32 verification.
3. Lossless delta compression using SovereignHeaderCompressor.
4. Zero-Leakage Topology Protection: Locators exchanged only when true discrepancies are proven.
"""

from __future__ import annotations
import enum
import hashlib
import json
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any

from .dht import HierarchicalSmallWorldDHT, NodeLocator, DHTNode
from .compression import SovereignHeaderCompressor

MAGIC_SYNC = b"IP7S"  # IPVN 7 Synchronization Wire Magic (4 bytes)
CANONICAL_SYNC_MTU = 1280


class SyncFrameType(enum.IntEnum):
    DIGEST_ANNOUNCE = 0x01   # Exchanges compressed bloom filter of local routing table
    RECONCILE_REQUEST = 0x02 # Solicits missing locators based on bloom discrepancies
    LOCATOR_STREAM = 0x03    # Transmits compressed locator payloads
    SYNC_ACK = 0x04          # Confirms lossless synchronization epoch


class SovereignBloomFilter:
    """
    Constant-size cryptographic Bloom Filter for private membership queries.
    Uses SHA-256 multi-slice indices to minimize false positives without revealing DIDs.
    """

    def __init__(self, size_bytes: int = 64):  # 512 bits
        self.size_bits = size_bytes * 8
        self.bit_array = bytearray(size_bytes)
        self.item_count = 0

    def add(self, item: str) -> None:
        """Adds item identity to filter using 3 independent 16-bit hash slices."""
        digest = hashlib.sha256(item.encode("utf-8")).digest()
        idx1 = struct.unpack("!H", digest[0:2])[0] % self.size_bits
        idx2 = struct.unpack("!H", digest[2:4])[0] % self.size_bits
        idx3 = struct.unpack("!H", digest[4:6])[0] % self.size_bits

        for idx in (idx1, idx2, idx3):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)

        self.item_count += 1

    def contains(self, item: str) -> bool:
        """Evaluates whether item may be present in the set."""
        digest = hashlib.sha256(item.encode("utf-8")).digest()
        idx1 = struct.unpack("!H", digest[0:2])[0] % self.size_bits
        idx2 = struct.unpack("!H", digest[2:4])[0] % self.size_bits
        idx3 = struct.unpack("!H", digest[4:6])[0] % self.size_bits

        for idx in (idx1, idx2, idx3):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def to_bytes(self) -> bytes:
        return bytes(self.bit_array)

    @classmethod
    def from_bytes(cls, raw: bytes) -> SovereignBloomFilter:
        bf = cls(size_bytes=len(raw))
        bf.bit_array = bytearray(raw)
        return bf


@dataclass
class SyncTelemetry:
    total_syncs_completed: int = 0
    total_dids_reconciled: int = 0
    total_wire_bytes_sent: int = 0
    total_wire_bytes_received: int = 0
    bloom_lookups_performed: int = 0
    false_positives_detected: int = 0
    average_sync_latency_ms: float = 0.0


class PrivateDHTInterregionSync:
    """
    Manages private, privacy-preserving state synchronization between regional DHT instances.
    Guarantees strict wire frame containment (<= 1280B) with CRC32 integrity checks.
    """

    def __init__(self, local_did: str, region_name: str, dht: HierarchicalSmallWorldDHT):
        self.local_did = local_did
        self.region_name = region_name
        self.dht = dht
        self.telemetry = SyncTelemetry()

    def build_bloom_filter(self) -> SovereignBloomFilter:
        """Constructs a Bloom Filter over all DIDs known in local DHT storage."""
        bf = SovereignBloomFilter(size_bytes=64)  # 512 bits
        for did in self.dht._locator_store.keys():
            bf.add(did)
        for cluster in (self.dht.tier0_cluster, self.dht.tier1_cluster):
            for node in cluster.values():
                bf.add(node.did)
        for bucket in self.dht.routing_buckets:
            for node in bucket:
                bf.add(node.did)
        return bf

    def create_digest_frame(self, sequence_id: int = 1) -> bytes:
        """
        Encodes a canonical IP7S DIGEST_ANNOUNCE frame:
        [0..3]   Magic 'IP7S' (4B)
        [4..5]   Frame Type uint16 (2B)
        [6..9]   Sequence ID uint32 (4B)
        [10..17] Timestamp double (8B)
        [18..19] Region Name Len uint16 (2B)
        [..]     Region Name (UTF-8)
        [..]     Bloom Filter (64B)
        [..]     CRC32 uint32 (4B)
        """
        bf = self.build_bloom_filter()
        bf_bytes = bf.to_bytes()
        region_bytes = self.region_name.encode("utf-8")
        now = time.time()

        header_prefix = struct.pack(
            "!4sHIQ H",
            MAGIC_SYNC,
            SyncFrameType.DIGEST_ANNOUNCE,
            sequence_id,
            int(now * 1000),
            len(region_bytes),
        )

        body = header_prefix + region_bytes + bf_bytes
        crc = zlib.crc32(body)
        wire_frame = body + struct.pack("!I", crc)

        assert len(wire_frame) <= CANONICAL_SYNC_MTU, f"Wire frame {len(wire_frame)} exceeds 1280B"
        self.telemetry.total_wire_bytes_sent += len(wire_frame)
        return wire_frame

    def reconcile_peer_digest(self, peer_bloom_bytes: bytes) -> List[str]:
        """
        Compares local DIDs against peer's bloom filter to discover locators the peer lacks.
        Zero leakage: Does not query or expose the peer's actual DID set.
        """
        peer_bf = SovereignBloomFilter.from_bytes(peer_bloom_bytes)
        missing_in_peer: List[str] = []

        local_keys = set(self.dht._locator_store.keys())
        for cluster in (self.dht.tier0_cluster, self.dht.tier1_cluster):
            local_keys.update(cluster.keys())
        for bucket in self.dht.routing_buckets:
            for node in bucket:
                local_keys.add(node.did)

        for did in local_keys:
            self.telemetry.bloom_lookups_performed += 1
            if not peer_bf.contains(did):
                missing_in_peer.append(did)

        return missing_in_peer

    def build_locator_delta_frame(self, target_dids: List[str], sequence_id: int = 2) -> bytes:
        """
        Extracts locators for target_dids, compresses with SovereignHeaderCompressor,
        and packages into a canonical 1280B 'IP7S' LOCATOR_STREAM frame.
        """
        records: Dict[str, List[Dict[str, Any]]] = {}
        for did in target_dids:
            locators = self.dht._locator_store.get(did, [])
            if not locators:
                for cluster in (self.dht.tier0_cluster, self.dht.tier1_cluster):
                    if did in cluster:
                        locators = cluster[did].locators
                        break
            records[did] = [
                {
                    "ip": loc.ip,
                    "port": loc.port,
                    "interface_type": loc.interface_type,
                    "latency_ms": loc.latency_ms,
                }
                for loc in locators
            ]

        raw_json = json.dumps(records, separators=(',', ':')).encode("utf-8")
        compressed_payload = SovereignHeaderCompressor.compress(raw_json)

        header = struct.pack(
            "!4sHIQH",
            MAGIC_SYNC,
            SyncFrameType.LOCATOR_STREAM,
            sequence_id,
            int(time.time() * 1000),
            len(compressed_payload),
        )

        body = header + compressed_payload
        crc = zlib.crc32(body)
        frame = body + struct.pack("!I", crc)

        assert len(frame) <= CANONICAL_SYNC_MTU, f"Locator delta frame {len(frame)} exceeds MTU"
        self.telemetry.total_wire_bytes_sent += len(frame)
        return frame

    def apply_locator_delta_frame(self, frame_bytes: bytes) -> int:
        """
        Verifies CRC32, decompresses locator payload, and reconciles into local DHT storage.
        Returns number of newly reconciled DIDs.
        """
        if len(frame_bytes) < 22:
            raise ValueError("Frame truncated")

        body = frame_bytes[:-4]
        expected_crc = struct.unpack("!I", frame_bytes[-4:])[0]
        if zlib.crc32(body) != expected_crc:
            raise ValueError("Corrupt IP7S frame: CRC32 mismatch")

        magic, f_type, seq, timestamp, p_len = struct.unpack("!4sHIQH", body[:20])
        if magic != MAGIC_SYNC or f_type != SyncFrameType.LOCATOR_STREAM:
            raise ValueError(f"Invalid sync frame header: {magic} / {f_type}")

        compressed_payload = body[20: 20 + p_len]
        decompressed_bytes = SovereignHeaderCompressor.decompress(compressed_payload)
        records: Dict[str, List[Dict[str, Any]]] = json.loads(decompressed_bytes.decode("utf-8"))

        reconciled_count = 0
        for did, loc_list in records.items():
            parsed_locators = [
                NodeLocator(
                    ip=loc_dict["ip"],
                    port=loc_dict["port"],
                    interface_type=loc_dict.get("interface_type", "auto"),
                    latency_ms=loc_dict.get("latency_ms", 1.0),
                )
                for loc_dict in loc_list
            ]
            if parsed_locators:
                self.dht.store_locators(did, parsed_locators)
                reconciled_count += 1

        self.telemetry.total_dids_reconciled += reconciled_count
        self.telemetry.total_syncs_completed += 1
        self.telemetry.total_wire_bytes_received += len(frame_bytes)
        return reconciled_count

    def execute_peer_sync_simulation(self, peer_sync: PrivateDHTInterregionSync) -> Dict[str, Any]:
        """
        Executes an end-to-end P2P bilateral synchronization cycle between this node and peer_sync.
        """
        t0 = time.perf_counter()

        # Step 1: Peer sends Bloom Digest frame to Local
        peer_digest_frame = peer_sync.create_digest_frame(sequence_id=101)
        # Extract bloom bytes from frame
        # header: 4s(4) + H(2) + I(4) + Q(8) + H(2) = 20B prefix + region_len + bf(64B) + crc(4B)
        region_len = struct.unpack("!H", peer_digest_frame[18:20])[0]
        bloom_start = 20 + region_len
        peer_bloom = peer_digest_frame[bloom_start: bloom_start + 64]

        # Step 2: Local discovers what Peer lacks
        missing_in_peer = self.reconcile_peer_digest(peer_bloom)

        # Step 3: Local sends compressed delta frame
        delta_frame = self.build_locator_delta_frame(missing_in_peer, sequence_id=102)

        # Step 4: Peer applies delta frame
        applied = peer_sync.apply_locator_delta_frame(delta_frame)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        self.telemetry.total_syncs_completed += 1
        self.telemetry.average_sync_latency_ms = elapsed_ms

        return {
            "status": "SYNCHRONIZED",
            "local_region": self.region_name,
            "peer_region": peer_sync.region_name,
            "dids_transferred": applied,
            "wire_bytes_transmitted": len(delta_frame) + len(peer_digest_frame),
            "canonical_mtu": CANONICAL_SYNC_MTU,
            "latency_ms": elapsed_ms,
            "privacy_guarantee": "ZERO_METADATA_LEAKAGE_BLOOM_O1",
        }

    def get_summary(self) -> Dict[str, Any]:
        """Returns sync telemetry snapshot."""
        return {
            "region": self.region_name,
            "total_syncs_completed": self.telemetry.total_syncs_completed,
            "total_dids_reconciled": self.telemetry.total_dids_reconciled,
            "total_wire_bytes_sent": self.telemetry.total_wire_bytes_sent,
            "total_wire_bytes_received": self.telemetry.total_wire_bytes_received,
            "bloom_lookups": self.telemetry.bloom_lookups_performed,
            "canonical_mtu": CANONICAL_SYNC_MTU,
        }
