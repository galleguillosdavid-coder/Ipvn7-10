"""
IPVN 7 Post-Quantum QUIC Transport Protocol (PQ-QUIC)
Implements multiplexed stream transport, BBR-inspired congestion control,
connection migration over changing network interfaces, and NIST FIPS 203/204
quantum-resistant cryptographic handshakes.
"""

from __future__ import annotations
import os
import time
import json
import struct
import base64
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Callable, Any
from dataclasses import dataclass, field

from ..crypto.pqc import (
    PQCKeyPair,
    PQCHybridKeyExchange,
    PQCDigitalSignature,
    encrypt_aead,
    decrypt_aead,
)


class QUICPacketType(IntEnum):
    INITIAL = 0x01
    HANDSHAKE = 0x02
    ONE_RTT_DATA = 0x03
    CONNECTION_MIGRATION = 0x04
    ACK = 0x05
    CLOSE = 0x06


class ConnectionState(IntEnum):
    IDLE = 0
    INITIAL_SENT = 1
    HANDSHAKE_RECEIVED = 2
    ESTABLISHED = 3
    MIGRATING = 4
    CLOSED = 5


@dataclass
class PQQUICPacket:
    """Wire representation of a PQ-QUIC packet."""
    packet_type: QUICPacketType
    dcid: bytes        # 8 bytes Destination Connection ID
    scid: bytes        # 8 bytes Source Connection ID
    packet_number: int # 32-bit integer
    payload: bytes     # Raw payload or AEAD-encrypted ciphertext

    HEADER_SIZE = 21   # 1 byte type + 8 bytes dcid + 8 bytes scid + 4 bytes pkt_num

    def serialize(self) -> bytes:
        if len(self.dcid) != 8 or len(self.scid) != 8:
            raise ValueError("Connection IDs must be 8 bytes each")

        header = struct.pack(
            ">B8s8sI",
            int(self.packet_type),
            self.dcid,
            self.scid,
            self.packet_number & 0xFFFFFFFF,
        )
        return header + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> PQQUICPacket:
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"QUIC packet too short: {len(data)} < {cls.HEADER_SIZE}")

        pkt_type_val, dcid, scid, pkt_num = struct.unpack(">B8s8sI", data[:cls.HEADER_SIZE])
        payload = data[cls.HEADER_SIZE:]

        return cls(
            packet_type=QUICPacketType(pkt_type_val),
            dcid=dcid,
            scid=scid,
            packet_number=pkt_num,
            payload=payload,
        )


@dataclass
class QUICStream:
    """Individual multiplexed stream avoiding Head-of-Line blocking."""
    stream_id: int
    is_bidirectional: bool = True
    send_buffer: bytearray = field(default_factory=bytearray)
    recv_buffer: bytearray = field(default_factory=bytearray)
    is_closed: bool = False

    def write(self, data: bytes) -> None:
        self.send_buffer.extend(data)

    def read(self, max_bytes: int = 4096) -> bytes:
        chunk = bytes(self.recv_buffer[:max_bytes])
        del self.recv_buffer[:max_bytes]
        return chunk


class BBRCongestionControl:
    """BBR-inspired rate and window controller for QUIC transport."""
    def __init__(self):
        self.cwnd: int = 14720        # 10 initial standard packets
        self.min_rtt_ms: float = 20.0
        self.smoothed_rtt_ms: float = 20.0
        self.pacing_rate_bps: float = 10_000_000  # 10 Mbps default pacing
        self.bytes_in_flight: int = 0
        self.packets_acked: int = 0
        self.packets_lost: int = 0

    def on_ack(self, rtt_sample_ms: float, bytes_acked: int) -> None:
        self.packets_acked += 1
        self.bytes_in_flight = max(0, self.bytes_in_flight - bytes_acked)

        # Update RTT estimates
        if rtt_sample_ms < self.min_rtt_ms or self.min_rtt_ms == 0:
            self.min_rtt_ms = rtt_sample_ms
        self.smoothed_rtt_ms = 0.875 * self.smoothed_rtt_ms + 0.125 * rtt_sample_ms

        # Increase congestion window dynamically
        self.cwnd += bytes_acked

    def on_loss(self, bytes_lost: int) -> None:
        self.packets_lost += 1
        self.bytes_in_flight = max(0, self.bytes_in_flight - bytes_lost)
        # BBR gentle window backoff
        self.cwnd = max(2940, int(self.cwnd * 0.75))


class PQQUICConnection:
    """
    Manages an active Post-Quantum QUIC session between two endpoints.
    Handles cryptographic handshake, multiplexed streams, and seamless connection migration.
    """

    def __init__(
        self,
        local_did: str,
        keypair: PQCKeyPair,
        is_client: bool = True,
        peer_did: Optional[str] = None,
    ):
        self.local_did = local_did
        self.peer_did = peer_did
        self.keypair = keypair
        self.is_client = is_client

        # Connection IDs
        self.scid = os.urandom(8)
        self.dcid = os.urandom(8) if is_client else b"\x00" * 8

        # State machine
        self.state = ConnectionState.IDLE
        self.packet_number_seq = 0
        self.peer_packet_number_max = 0

        # Cryptography
        self.session_key: Optional[bytes] = None
        self._client_handshake_state: Optional[Tuple] = None

        # Streams
        self.streams: Dict[int, QUICStream] = {}
        self.next_stream_id = 0 if is_client else 1

        # Congestion controller
        self.cc = BBRCongestionControl()

        # Network attachment (allows connection migration)
        self.current_remote_endpoint: Optional[Tuple[str, int]] = None
        self.migration_counter = 0

    def create_stream(self, bidirectional: bool = True) -> QUICStream:
        """Spawns a new independent multiplexed stream."""
        sid = self.next_stream_id
        self.next_stream_id += 2
        stream = QUICStream(stream_id=sid, is_bidirectional=bidirectional)
        self.streams[sid] = stream
        return stream

    def _next_pkt_num(self) -> int:
        self.packet_number_seq += 1
        return self.packet_number_seq

    # -------------------------------------------------------------
    # Post-Quantum Handshake Execution
    # -------------------------------------------------------------

    def create_client_initial(self) -> PQQUICPacket:
        """Generates the QUIC INITIAL packet containing hybrid PQC key share."""
        if not self.is_client:
            raise RuntimeError("Only clients generate ClientInitial")

        x_pub, k_pub, x_priv, k_priv = PQCHybridKeyExchange.client_init()
        self._client_handshake_state = (x_priv, k_priv)

        payload_obj = {
            "version": "IPVN7-PQ-QUIC-1.0",
            "client_did": self.local_did,
            "x25519_pub": base64.b64encode(x_pub).decode("utf-8"),
            "mlkem_pub": base64.b64encode(k_pub).decode("utf-8"),
            "timestamp": time.time(),
        }
        payload_bytes = json.dumps(payload_obj).encode("utf-8")

        pkt = PQQUICPacket(
            packet_type=QUICPacketType.INITIAL,
            dcid=self.dcid,
            scid=self.scid,
            packet_number=self._next_pkt_num(),
            payload=payload_bytes,
        )
        self.state = ConnectionState.INITIAL_SENT
        return pkt

    def handle_client_initial(self, packet: PQQUICPacket) -> PQQUICPacket:
        """Server processes ClientInitial, encapsulating PQC keys and issuing Handshake response."""
        if self.is_client:
            raise RuntimeError("Clients cannot handle ClientInitial")

        data = json.loads(packet.payload.decode("utf-8"))
        self.peer_did = data["client_did"]
        self.dcid = packet.scid  # Save client's SCID as server's DCID

        peer_x_pub = base64.b64decode(data["x25519_pub"])
        peer_k_pub = base64.b64decode(data["mlkem_pub"])

        # Server hybrid response
        srv_x_pub, mlkem_ct, derived_key = PQCHybridKeyExchange.server_respond(peer_x_pub, peer_k_pub)
        self.session_key = derived_key

        # Sign handshake transcript with Server's ML-DSA private key
        transcript = peer_x_pub + peer_k_pub + srv_x_pub + mlkem_ct
        sig_bundle = PQCDigitalSignature.sign_hybrid(
            transcript,
            self.keypair.mldsa_priv,
            self.keypair.ed25519_priv,
        )

        response_payload = {
            "server_did": self.local_did,
            "x25519_pub": base64.b64encode(srv_x_pub).decode("utf-8"),
            "mlkem_ct": base64.b64encode(mlkem_ct).decode("utf-8"),
            "mldsa_sig": base64.b64encode(sig_bundle["mldsa_sig"]).decode("utf-8"),
            "ed25519_sig": base64.b64encode(sig_bundle["ed25519_sig"]).decode("utf-8"),
            "server_mldsa_pub": base64.b64encode(self.keypair.mldsa_pub.public_bytes_raw()).decode("utf-8"),
            "server_ed25519_pub": base64.b64encode(self.keypair.ed25519_pub.public_bytes_raw()).decode("utf-8"),
        }
        resp_bytes = json.dumps(response_payload).encode("utf-8")

        resp_pkt = PQQUICPacket(
            packet_type=QUICPacketType.HANDSHAKE,
            dcid=self.dcid,
            scid=self.scid,
            packet_number=self._next_pkt_num(),
            payload=resp_bytes,
        )
        self.state = ConnectionState.ESTABLISHED
        return resp_pkt

    def handle_server_handshake(self, packet: PQQUICPacket) -> bool:
        """Client processes ServerHandshake, decapsulates PQC key, verifies signature, and establishes session."""
        if not self.is_client or self._client_handshake_state is None:
            raise RuntimeError("Invalid state for ServerHandshake processing")

        data = json.loads(packet.payload.decode("utf-8"))
        self.peer_did = data["server_did"]
        self.dcid = packet.scid  # Adopt server's SCID as client's DCID

        srv_x_pub = base64.b64decode(data["x25519_pub"])
        mlkem_ct = base64.b64decode(data["mlkem_ct"])
        mldsa_sig = base64.b64decode(data["mldsa_sig"])
        ed25519_sig = base64.b64decode(data["ed25519_sig"])
        srv_mldsa_pub = base64.b64decode(data["server_mldsa_pub"])
        srv_ed25519_pub = base64.b64decode(data["server_ed25519_pub"])

        x_priv, k_priv = self._client_handshake_state

        # Decapsulate and derive hybrid key
        derived_key = PQCHybridKeyExchange.client_finalize(x_priv, k_priv, srv_x_pub, mlkem_ct)

        # Verify signature over handshake transcript
        client_x_pub = x_priv.public_key().public_bytes_raw()
        client_k_pub = k_priv.public_key().public_bytes_raw()
        transcript = client_x_pub + client_k_pub + srv_x_pub + mlkem_ct

        sig_ok = PQCDigitalSignature.verify_hybrid(
            transcript,
            mldsa_sig,
            ed25519_sig,
            srv_mldsa_pub,
            srv_ed25519_pub,
        )
        if not sig_ok:
            self.state = ConnectionState.CLOSED
            raise PermissionError("Server PQC signature verification failed!")

        self.session_key = derived_key
        self.state = ConnectionState.ESTABLISHED
        self._client_handshake_state = None
        return True

    # -------------------------------------------------------------
    # 1-RTT Post-Quantum Protected Data Exchange
    # -------------------------------------------------------------

    def send_stream_data(self, stream_id: int, data: bytes) -> PQQUICPacket:
        """Encrypts stream payload with session key and wraps in 1-RTT QUIC packet."""
        if self.state != ConnectionState.ESTABLISHED or not self.session_key:
            raise ConnectionError("Connection not established")

        stream_frame = struct.pack(">IQ", stream_id, len(data)) + data
        ciphertext = encrypt_aead(self.session_key, stream_frame, associated_data=self.dcid)

        pkt = PQQUICPacket(
            packet_type=QUICPacketType.ONE_RTT_DATA,
            dcid=self.dcid,
            scid=self.scid,
            packet_number=self._next_pkt_num(),
            payload=ciphertext,
        )
        self.cc.bytes_in_flight += len(ciphertext)
        return pkt

    def receive_stream_data(self, packet: PQQUICPacket) -> Tuple[int, bytes]:
        """Decrypts 1-RTT data and routes payload to the appropriate multiplexed stream."""
        if self.state != ConnectionState.ESTABLISHED or not self.session_key:
            raise ConnectionError("Connection not established")

        plaintext = decrypt_aead(self.session_key, packet.payload, associated_data=self.scid)
        stream_id, data_len = struct.unpack(">IQ", plaintext[:12])
        data = plaintext[12: 12 + data_len]

        if stream_id not in self.streams:
            self.streams[stream_id] = QUICStream(stream_id=stream_id)

        self.streams[stream_id].recv_buffer.extend(data)
        return stream_id, data

    # -------------------------------------------------------------
    # Connection Migration (Seamless Mobile / Multi-Interface Handoff)
    # -------------------------------------------------------------

    def initiate_migration(self, new_ip: str, new_port: int, interface_name: str) -> PQQUICPacket:
        """
        Executes connection migration when switching physical networks (e.g., Wi-Fi -> 5G).
        Maintains TLS/QUIC session without teardown or re-handshake.
        """
        self.migration_counter += 1
        migration_token = os.urandom(16)

        migration_payload = {
            "migration_seq": self.migration_counter,
            "new_ip": new_ip,
            "new_port": new_port,
            "interface": interface_name,
            "token": base64.b64encode(migration_token).decode("utf-8"),
            "timestamp": time.time(),
        }
        encoded = json.dumps(migration_payload).encode("utf-8")
        encrypted_token = encrypt_aead(self.session_key, encoded, associated_data=self.dcid)

        return PQQUICPacket(
            packet_type=QUICPacketType.CONNECTION_MIGRATION,
            dcid=self.dcid,
            scid=self.scid,
            packet_number=self._next_pkt_num(),
            payload=encrypted_token,
        )

    def handle_migration(self, packet: PQQUICPacket, source_endpoint: Tuple[str, int]) -> Dict[str, Any]:
        """Validates and adopts peer's migrated network endpoint."""
        decrypted = decrypt_aead(self.session_key, packet.payload, associated_data=self.scid)
        info = json.loads(decrypted.decode("utf-8"))
        self.current_remote_endpoint = source_endpoint
        self.state = ConnectionState.ESTABLISHED
        return info
