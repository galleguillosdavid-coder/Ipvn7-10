"""
IPVN 7 Unified Network Packet Framing Specification
Defines binary packet structure for native IPVN 7 datagrams.
"""

from __future__ import annotations
import struct
import zlib
from enum import IntEnum
from dataclasses import dataclass
from typing import Tuple


class HeaderType(IntEnum):
    """Protocol numbers for IPVN 7 Next Header field."""
    PQ_QUIC = 0x3C       # 60: Post-Quantum QUIC Transport Protocol
    DHT_ROUTING = 0x3D   # 61: Hierarchical Small-World DHT Control
    ICMP7 = 0x3E         # 62: IPVN 7 Control & Diagnostic Messages
    RAW_ENCAP = 0x3F     # 63: Raw L2/L3 Encapsulated Frame


class TrafficClass(IntEnum):
    """QoS and Traffic Priority."""
    BEST_EFFORT = 0x00
    REAL_TIME = 0x10
    EXPEDITED = 0x20
    NETWORK_CONTROL = 0x30


@dataclass
class IPVN7Packet:
    """
    Standard IPVN 7 Datagram.
    Header format (38 bytes fixed header):
    - [0:1]   Version (4 bits = 7) | Traffic Class (4 bits)
    - [1:2]   Traffic Class High (4 bits) | Reserved (4 bits) -> packed as 8-bit traffic_class
    - [2:3]   Next Header (8 bits)
    - [3:4]   Hop Limit / TTL (8 bits)
    - [4:20]  Source DID Fingerprint (16 bytes)
    - [20:36] Destination DID Fingerprint (16 bytes)
    - [36:38] Payload Length (16 bits)
    - [38:40] Header & Payload CRC Checksum (16 bits)
    - [40:]   Payload
    """
    src_did_fp: bytes          # 16 bytes
    dst_did_fp: bytes          # 16 bytes
    payload: bytes
    next_header: HeaderType = HeaderType.PQ_QUIC
    traffic_class: int = TrafficClass.BEST_EFFORT
    hop_limit: int = 64
    version: int = 7

    HEADER_SIZE = 40

    def serialize(self) -> bytes:
        """Serializes packet into wire format."""
        if len(self.src_did_fp) != 16:
            raise ValueError(f"src_did_fp must be 16 bytes, got {len(self.src_did_fp)}")
        if len(self.dst_did_fp) != 16:
            raise ValueError(f"dst_did_fp must be 16 bytes, got {len(self.dst_did_fp)}")

        payload_len = len(self.payload)
        # First 4 bytes: version (4 bits) + traffic_class (12 bits), next_header (8 bits), hop_limit (8 bits)
        ver_tc = ((self.version & 0x0F) << 12) | (self.traffic_class & 0x0FFF)

        # Header without checksum
        pre_hdr = struct.pack(
            ">HBB16s16sH",
            ver_tc,
            int(self.next_header),
            self.hop_limit,
            self.src_did_fp,
            self.dst_did_fp,
            payload_len,
        )

        # Compute checksum over header + payload
        crc = zlib.crc32(pre_hdr + self.payload) & 0xFFFF
        chk_bytes = struct.pack(">H", crc)

        return pre_hdr + chk_bytes + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> IPVN7Packet:
        """Deserializes bytes into an IPVN7Packet."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(data)} < {cls.HEADER_SIZE}")

        pre_hdr = data[:38]
        chk_bytes = data[38:40]
        expected_crc = struct.unpack(">H", chk_bytes)[0]

        ver_tc, next_hdr_val, hop_limit, src_fp, dst_fp, payload_len = struct.unpack(
            ">HBB16s16sH", pre_hdr
        )

        version = (ver_tc >> 12) & 0x0F
        if version != 7:
            raise ValueError(f"Invalid IPVN version: {version} (expected 7)")

        traffic_class = ver_tc & 0x0FFF
        payload = data[40: 40 + payload_len]

        actual_crc = zlib.crc32(pre_hdr + payload) & 0xFFFF
        if actual_crc != expected_crc:
            raise ValueError(f"Checksum mismatch: {actual_crc} != {expected_crc}")

        return cls(
            version=version,
            traffic_class=traffic_class,
            next_header=HeaderType(next_hdr_val),
            hop_limit=hop_limit,
            src_did_fp=src_fp,
            dst_did_fp=dst_fp,
            payload=payload,
        )

    def decrement_hop(self) -> bool:
        """Decrements hop limit; returns True if still alive, False if expired."""
        self.hop_limit -= 1
        return self.hop_limit > 0
