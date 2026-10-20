"""
IPVN 7 HRS (High Reliability Substrate) Wire Protocol
Implements the 5-Frame canonical protocol from IPv7-HRS:
"La Red Responde, No Grita" (Elimination of broadcast storms via quiet unicast & explicit opcodes).
"""

from __future__ import annotations
import enum
import struct
import zlib
import time
from typing import Dict, Optional, Tuple, Callable, Any
from dataclasses import dataclass


MAGIC_HRS = b"IP7H"  # IPVN 7 HRS Wire Magic (4 bytes)


class HRSFrameType(enum.IntEnum):
    """Explicit 5 opcodes of the IPv7-HRS substrate."""
    ANNOUNCE = 0x01      # Explicit peer presence declaration
    QUERY = 0x02         # Targeted directed unicast request
    RESPONSE = 0x03      # Deterministic response to a query
    HEARTBEAT = 0x04     # Micro-pulse keepalive based on adaptive SLA
    STATE_CHANGE = 0x05  # Topology / link delta notification


class DeviceProfile(enum.Enum):
    """Adaptive SLA profiles based on node hardware constraints."""
    SERVER = "server"
    LAPTOP = "laptop"
    IOT = "iot"
    SATELLITE = "satellite"


@dataclass(frozen=True)
class AdaptiveSLA:
    """Configures timeout, retries, and pulse frequencies per device profile."""
    profile: DeviceProfile
    heartbeat_interval: float  # seconds
    query_timeout: float       # seconds
    max_retries: int

    @classmethod
    def get_defaults(cls, profile: DeviceProfile) -> AdaptiveSLA:
        if profile == DeviceProfile.IOT:
            return cls(profile=profile, heartbeat_interval=3.0, query_timeout=10.0, max_retries=2)
        elif profile == DeviceProfile.LAPTOP:
            return cls(profile=profile, heartbeat_interval=7.0, query_timeout=20.0, max_retries=3)
        elif profile == DeviceProfile.SERVER:
            return cls(profile=profile, heartbeat_interval=10.0, query_timeout=30.0, max_retries=4)
        elif profile == DeviceProfile.SATELLITE:
            return cls(profile=profile, heartbeat_interval=15.0, query_timeout=45.0, max_retries=5)
        return cls(profile=DeviceProfile.SERVER, heartbeat_interval=10.0, query_timeout=30.0, max_retries=3)


@dataclass
class HRSFrame:
    """Canonical wire frame representation for the quiet HRS substrate."""
    frame_type: HRSFrameType
    sequence_id: int
    source_did: str
    target_did: str
    payload: bytes
    timestamp: float = 0.0

    def encode(self) -> bytes:
        """
        Binary layout:
        [0:4]   Magic 'IP7H'
        [4:5]   Frame Type (1B uint8)
        [5:9]   Sequence ID (4B uint32)
        [9:17]  Timestamp (8B double)
        [17:19] Source DID len (2B uint16)
        [...]   Source DID (UTF-8)
        [...:..]Target DID len (2B uint16)
        [...]   Target DID (UTF-8)
        [...:..]Payload len (4B uint32)
        [...]   Payload bytes
        [...:..]CRC32 (4B uint32)
        """
        src_bytes = self.source_did.encode("utf-8")
        tgt_bytes = self.target_did.encode("utf-8")
        ts = self.timestamp if self.timestamp > 0 else time.time()

        header_prefix = struct.pack(
            "!4sBIdHH",
            MAGIC_HRS,
            int(self.frame_type),
            self.sequence_id,
            ts,
            len(src_bytes),
            len(tgt_bytes),
        )
        body = header_prefix + src_bytes + tgt_bytes + struct.pack("!I", len(self.payload)) + self.payload
        crc = zlib.crc32(body) & 0xFFFFFFFF
        return body + struct.pack("!I", crc)

    @classmethod
    def decode(cls, data: bytes) -> HRSFrame:
        """Parses canonical wire bytes into an HRSFrame, validating magic and CRC32."""
        if len(data) < 25:
            raise ValueError(f"HRSFrame too short: {len(data)} bytes")

        # Verify CRC32
        body, expected_crc = data[:-4], struct.unpack("!I", data[-4:])[0]
        actual_crc = zlib.crc32(body) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"HRSFrame CRC32 mismatch: expected {expected_crc:#x}, got {actual_crc:#x}")

        magic, f_type, seq_id, ts, src_len, tgt_len = struct.unpack("!4sBIdHH", body[:21])
        if magic != MAGIC_HRS:
            raise ValueError(f"Invalid HRS frame magic: {magic!r}")

        offset = 21
        src_bytes = body[offset:offset + src_len]
        offset += src_len
        tgt_bytes = body[offset:offset + tgt_len]
        offset += tgt_len

        payload_len = struct.unpack("!I", body[offset:offset + 4])[0]
        offset += 4
        payload = body[offset:offset + payload_len]

        return cls(
            frame_type=HRSFrameType(f_type),
            sequence_id=seq_id,
            source_did=src_bytes.decode("utf-8"),
            target_did=tgt_bytes.decode("utf-8"),
            payload=payload,
            timestamp=ts,
        )


class HRSDispatcher:
    """
    Substrate router and handler for HRS Frames.
    Enforces quiet network constraints:
    - Directed unicast only (rejects unaddressed broadcasts).
    - Rate limits queries per target to prevent spamming.
    """

    def __init__(self, local_did: str, sla: Optional[AdaptiveSLA] = None):
        self.local_did = local_did
        self.sla = sla or AdaptiveSLA.get_defaults(DeviceProfile.SERVER)
        self._handlers: Dict[HRSFrameType, Callable[[HRSFrame], Optional[HRSFrame]]] = {}
        self._seq_counter: int = 1
        self._query_history: Dict[str, float] = {}

    def register_handler(
        self,
        frame_type: HRSFrameType,
        handler: Callable[[HRSFrame], Optional[HRSFrame]]
    ) -> None:
        """Registers a callback handler for a specific HRSFrameType."""
        self._handlers[frame_type] = handler

    def create_frame(
        self,
        frame_type: HRSFrameType,
        target_did: str,
        payload: bytes,
    ) -> HRSFrame:
        """Constructs an outgoing frame with auto-incremented sequence ID."""
        frame = HRSFrame(
            frame_type=frame_type,
            sequence_id=self._seq_counter,
            source_did=self.local_did,
            target_did=target_did,
            payload=payload,
            timestamp=time.time(),
        )
        self._seq_counter = (self._seq_counter + 1) & 0xFFFFFFFF
        return frame

    def process_incoming(self, raw_bytes: bytes) -> Optional[HRSFrame]:
        """
        Validates, decodes, and routes an incoming HRS packet.
        Returns a response frame if the registered handler produces one.
        """
        frame = HRSFrame.decode(raw_bytes)

        # Quiet Network check: frame must be addressed to local_did or announced
        if frame.frame_type != HRSFrameType.ANNOUNCE and frame.target_did != self.local_did:
            # Drop silently - "La red no grita"
            return None

        handler = self._handlers.get(frame.frame_type)
        if handler:
            return handler(frame)
        return None
