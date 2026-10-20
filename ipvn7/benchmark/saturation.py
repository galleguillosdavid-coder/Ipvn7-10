"""
IPVN 7 - Local Datapath Saturation & 1280B Fragmentation Benchmark Engine
Measures maximum theoretical and loopback throughput (Gbps/Mpps)
of the canonical 1280-byte fragmentation, wire packaging, and reassembly pipeline.
"""

from __future__ import annotations
import time
import socket
import struct
import zlib
import hashlib
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass


MAGIC_FRAG = b"IP7F"  # 4 bytes
HEADER_SIZE = 24       # Magic(4) + MsgId(8) + FragIdx(2) + TotalFrags(2) + Offset(4) + CRC32(4)
CANONICAL_MTU = 1280
PAYLOAD_CAPACITY = CANONICAL_MTU - HEADER_SIZE  # 1256 bytes per packet


@dataclass
class FragmentPacket:
    msg_id: int
    frag_idx: int
    total_frags: int
    offset: int
    crc32: int
    payload: bytes

    def serialize(self) -> bytes:
        header = struct.pack(
            "!4sQHHII",
            MAGIC_FRAG,
            self.msg_id,
            self.frag_idx,
            self.total_frags,
            self.offset,
            self.crc32,
        )
        return header + self.payload

    @staticmethod
    def deserialize(raw: bytes) -> FragmentPacket:
        if len(raw) < HEADER_SIZE or not raw.startswith(MAGIC_FRAG):
            raise ValueError("Invalid canonical fragmentation header or truncated buffer")
        magic, msg_id, frag_idx, total_frags, offset, crc32 = struct.unpack(
            "!4sQHHII", raw[:HEADER_SIZE]
        )
        payload = raw[HEADER_SIZE:]
        if zlib.crc32(payload) & 0xFFFFFFFF != crc32:
            raise ValueError(f"CRC32 integrity failure on fragment {frag_idx}/{total_frags}")
        return FragmentPacket(
            msg_id=msg_id,
            frag_idx=frag_idx,
            total_frags=total_frags,
            offset=offset,
            crc32=crc32,
            payload=payload,
        )


class SovereignFragmentationEngine:
    """
    Handles fragmentation and wire reconstruction of arbitrarily large data streams
    into strictly compliant 1280-byte MTU canonical IPVN 7 datagrams.
    """

    @staticmethod
    def fragment_stream(data: bytes, msg_id: Optional[int] = None) -> List[bytes]:
        """Fragments arbitrary byte stream into a sequence of <=1280B wire datagrams."""
        if msg_id is None:
            msg_id = int(time.time_ns()) & 0xFFFFFFFFFFFFFFFF

        total_len = len(data)
        if total_len == 0:
            frag = FragmentPacket(
                msg_id=msg_id, frag_idx=0, total_frags=1, offset=0, crc32=0, payload=b""
            )
            return [frag.serialize()]

        num_frags = (total_len + PAYLOAD_CAPACITY - 1) // PAYLOAD_CAPACITY
        fragments: List[bytes] = []

        offset = 0
        for idx in range(num_frags):
            chunk = data[offset : offset + PAYLOAD_CAPACITY]
            crc = zlib.crc32(chunk) & 0xFFFFFFFF
            frag = FragmentPacket(
                msg_id=msg_id,
                frag_idx=idx,
                total_frags=num_frags,
                offset=offset,
                crc32=crc,
                payload=chunk,
            )
            wire_bytes = frag.serialize()
            fragments.append(wire_bytes)
            offset += len(chunk)

        return fragments

    @staticmethod
    def reassemble_stream(wire_fragments: List[bytes]) -> bytes:
        """Parses, verifies CRC32, sorts, and reassembles fragmented wire datagrams."""
        if not wire_fragments:
            return b""

        parsed: List[FragmentPacket] = []
        for raw in wire_fragments:
            parsed.append(FragmentPacket.deserialize(raw))

        parsed.sort(key=lambda f: f.frag_idx)
        total_frags = parsed[0].total_frags

        if len(parsed) != total_frags:
            raise ValueError(f"Missing fragments: received {len(parsed)} of {total_frags}")

        buffer = bytearray()
        for idx, frag in enumerate(parsed):
            if frag.frag_idx != idx:
                raise ValueError(f"Fragment sequence gap at index {idx}")
            buffer.extend(frag.payload)

        return bytes(buffer)


class DatapathSaturationBenchmark:
    """
    Continuous saturation benchmarking suite for the IPVN 7 local fragmentation,
    wire encoding, and UDP/memory datapath.
    """

    @staticmethod
    def run_benchmark(
        megabytes: float = 8.0,
        use_udp_loopback: bool = False,
        seed_pattern: bytes = b"IPVN7_SATURATION_VECTOR_",
    ) -> Dict[str, Any]:
        """
        Executes end-to-end saturation test:
        1. Generates test payload buffer.
        2. Measures fragmentation and wire packing throughput.
        3. Optionally transmits fragments through local UDP loopback socket pair.
        4. Measures reassembly, CRC32 verification, and bit-level integrity.
        """
        total_target_bytes = int(megabytes * 1024 * 1024)
        repeat_count = (total_target_bytes + len(seed_pattern) - 1) // len(seed_pattern)
        raw_payload = (seed_pattern * repeat_count)[:total_target_bytes]
        expected_sha256 = hashlib.sha256(raw_payload).hexdigest()

        # Step 1: Fragmentation Bench
        t0 = time.perf_counter()
        wire_packets = SovereignFragmentationEngine.fragment_stream(raw_payload)
        t_fragment = time.perf_counter() - t0

        packet_count = len(wire_packets)
        total_wire_bytes = sum(len(p) for p in wire_packets)

        # Step 2: Transmission (Memory vs UDP Loopback)
        t_transport = 0.0
        transmitted_packets = wire_packets

        if use_udp_loopback:
            t0 = time.perf_counter()
            # Setup local non-blocking loopback UDP sockets
            rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rx_sock.bind(("127.0.0.1", 0))
            rx_port = rx_sock.getsockname()[1]
            rx_sock.settimeout(0.5)

            tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rx_packets = []

            for p in wire_packets:
                tx_sock.sendto(p, ("127.0.0.1", rx_port))
                try:
                    data, _ = rx_sock.recvfrom(2048)
                    rx_packets.append(data)
                except socket.timeout:
                    break

            tx_sock.close()
            rx_sock.close()
            t_transport = time.perf_counter() - t0
            transmitted_packets = rx_packets

        # Step 3: Reassembly & Verification Bench
        t0 = time.perf_counter()
        reconstructed = SovereignFragmentationEngine.reassemble_stream(transmitted_packets)
        t_reassemble = time.perf_counter() - t0

        actual_sha256 = hashlib.sha256(reconstructed).hexdigest()
        integrity_ok = actual_sha256 == expected_sha256

        total_elapsed = t_fragment + t_reassemble + t_transport
        throughput_mb_s = (total_wire_bytes / (1024 * 1024)) / max(1e-6, total_elapsed)
        throughput_gbps = (total_wire_bytes * 8 / 1e9) / max(1e-6, total_elapsed)
        packets_per_sec = packet_count / max(1e-6, total_elapsed)

        return {
            "mode": "UDP_LOOPBACK_SOCKET" if use_udp_loopback else "IN_MEMORY_PIPELINE",
            "total_payload_mb": round(megabytes, 2),
            "total_payload_bytes": total_target_bytes,
            "total_wire_bytes": total_wire_bytes,
            "canonical_mtu": CANONICAL_MTU,
            "payload_per_packet": PAYLOAD_CAPACITY,
            "total_packets": packet_count,
            "fragmentation_time_ms": round(t_fragment * 1000, 2),
            "reassembly_time_ms": round(t_reassemble * 1000, 2),
            "transport_time_ms": round(t_transport * 1000, 2),
            "total_elapsed_sec": round(total_elapsed, 4),
            "packets_per_second": round(packets_per_sec, 1),
            "throughput_mb_s": round(throughput_mb_s, 2),
            "throughput_gbps": round(throughput_gbps, 3),
            "integrity_verified": integrity_ok,
            "sha256_match": integrity_ok,
            "avg_fragment_latency_us": round((total_elapsed / max(1, packet_count)) * 1e6, 2),
        }
