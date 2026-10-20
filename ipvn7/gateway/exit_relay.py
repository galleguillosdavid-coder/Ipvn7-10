"""
IPVN 7 Sovereign Exit Relay Subsystem (True Overlay Datapath Forwarder)
Implements true overlay encrypted datapath forwarding through an Exit Node.
Traffic is encapsulated into PQ-QUIC streams across the mesh overlay,
eliminating direct egress connections from the local client process.
"""

from __future__ import annotations
import os
import sys
import time
import socket
import struct
import select
import threading
import logging
from typing import Dict, Any, Optional, Callable, Tuple

from ipvn7.security.egress_policy import EgressSecurityPolicy

logger = logging.getLogger("ipvn7.exit_relay")

# Canonical Wire Framing for Exit Relay
MAGIC_EXIT_RELAY = b"IP7X"

CMD_CONNECT   = 0x01
CMD_CONNECTED = 0x02
CMD_DATA      = 0x03
CMD_CLOSE     = 0x04

STATUS_OK             = 0x00
STATUS_SSRF_BLOCKED   = 0x01
STATUS_CONNECT_FAILED = 0x02


class SovereignExitRelayServer:
    """
    Runs on the Exit Node. Listens for IP7X frames across the PQ-QUIC overlay,
    validates outbound egress targets against EgressSecurityPolicy,
    connects to real Internet hosts on behalf of the client node,
    and streams encrypted responses back through the overlay.
    """

    def __init__(self, node: Any):
        self.node = node
        self.active_sockets: Dict[bytes, socket.socket] = {}
        self.stream_owners: Dict[bytes, str] = {}
        self.reader_threads: Dict[bytes, threading.Thread] = {}
        self.stats = {
            "connections_handled": 0,
            "bytes_forwarded_outbound": 0,
            "bytes_forwarded_inbound": 0,
            "ssrf_rejected": 0,
            "active_relays": 0,
        }
        self._lock = threading.Lock()

        # Register message handler with node
        if hasattr(self.node, "register_message_handler"):
            self.node.register_message_handler(self._on_overlay_message)

    def _on_overlay_message(self, src_did: str, payload: bytes) -> None:
        """Processes IP7X frames arriving over PQ-QUIC 1-RTT encrypted streams."""
        if not payload.startswith(MAGIC_EXIT_RELAY) or len(payload) < 21:
            return

        cmd = payload[4]
        stream_id = payload[5:21]

        if cmd == CMD_CONNECT:
            self._handle_connect(src_did, stream_id, payload[21:])
        elif cmd == CMD_DATA:
            self._handle_data(stream_id, payload[21:])
        elif cmd == CMD_CLOSE:
            self._handle_close(stream_id)

    def _handle_connect(self, src_did: str, stream_id: bytes, body: bytes) -> None:
        """Handles CMD_CONNECT: validates target and creates outbound TCP connection."""
        if len(body) < 4:
            return

        port, host_len = struct.unpack("!HH", body[:4])
        target_host = body[4: 4 + host_len].decode("utf-8", errors="replace")

        # Security Boundary: Enforce EgressSecurityPolicy on Exit Node
        is_allowed, reason, valid_ips = EgressSecurityPolicy.resolve_and_validate_host(target_host, port)
        if not is_allowed:
            self.stats["ssrf_rejected"] += 1
            logger.warning(f"Exit Node rejected egress request to {target_host}:{port}: {reason}")
            resp = MAGIC_EXIT_RELAY + bytes([CMD_CONNECTED]) + stream_id + struct.pack("!H", STATUS_SSRF_BLOCKED)
            self.node.send_message_sync(src_did, resp)
            return

        # Open socket from Exit Node to validated public IP
        target_ip = valid_ips[0]
        try:
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_sock.settimeout(6.0)
            out_sock.connect((target_ip, port))

            with self._lock:
                self.active_sockets[stream_id] = out_sock
                self.stream_owners[stream_id] = src_did
                self.stats["connections_handled"] += 1
                self.stats["active_relays"] = len(self.active_sockets)

            # Reply CONNECTED OK
            resp = MAGIC_EXIT_RELAY + bytes([CMD_CONNECTED]) + stream_id + struct.pack("!H", STATUS_OK)
            self.node.send_message_sync(src_did, resp)

            # Spawn reader thread to stream return data back to client over mesh
            t = threading.Thread(
                target=self._reader_loop,
                args=(stream_id, out_sock, src_did),
                daemon=True,
            )
            self.reader_threads[stream_id] = t
            t.start()
        except Exception as e:
            logger.error(f"Exit Node failed to connect to {target_ip}:{port}: {e}")
            resp = MAGIC_EXIT_RELAY + bytes([CMD_CONNECTED]) + stream_id + struct.pack("!H", STATUS_CONNECT_FAILED)
            self.node.send_message_sync(src_did, resp)

    def _reader_loop(self, stream_id: bytes, sock: socket.socket, client_did: str) -> None:
        """Continuously reads from Internet socket and transmits chunks over PQ-QUIC to client."""
        try:
            sock.setblocking(True)
            sock.settimeout(5.0)
            while True:
                try:
                    data = sock.recv(16384)
                    if not data:
                        break
                    with self._lock:
                        self.stats["bytes_forwarded_inbound"] += len(data)

                    # Frame data in IP7X chunks of max 1200B to respect MTU
                    chunk_size = 1100
                    for offset in range(0, len(data), chunk_size):
                        chunk = data[offset: offset + chunk_size]
                        frame = (
                            MAGIC_EXIT_RELAY
                            + bytes([CMD_DATA])
                            + stream_id
                            + struct.pack("!I", len(chunk))
                            + chunk
                        )
                        self.node.send_message_sync(client_did, frame)
                except socket.timeout:
                    # Check if stream still alive
                    with self._lock:
                        if stream_id not in self.active_sockets:
                            break
                    continue
        except Exception:
            pass
        finally:
            self._handle_close(stream_id, notify_client=True, client_did=client_did)

    def _handle_data(self, stream_id: bytes, body: bytes) -> None:
        """Handles CMD_DATA: writes payload received from client over overlay to Internet socket."""
        if len(body) < 4:
            return
        data_len = struct.unpack("!I", body[:4])[0]
        data = body[4: 4 + data_len]

        with self._lock:
            sock = self.active_sockets.get(stream_id)

        if sock:
            try:
                sock.sendall(data)
                with self._lock:
                    self.stats["bytes_forwarded_outbound"] += len(data)
            except Exception:
                self._handle_close(stream_id)

    def _handle_close(self, stream_id: bytes, notify_client: bool = False, client_did: Optional[str] = None) -> None:
        """Closes outbound socket and releases resources."""
        with self._lock:
            sock = self.active_sockets.pop(stream_id, None)
            owner = self.stream_owners.pop(stream_id, None)
            self.reader_threads.pop(stream_id, None)
            self.stats["active_relays"] = len(self.active_sockets)

        if sock:
            try:
                sock.close()
            except Exception:
                pass

        if notify_client and (client_did or owner):
            target = client_did or owner
            frame = MAGIC_EXIT_RELAY + bytes([CMD_CLOSE]) + stream_id
            try:
                self.node.send_message_sync(target, frame)
            except Exception:
                pass


class SovereignExitRelayClient:
    """
    Runs on the local node within proxy.py or socks5.py.
    Provides transparent stream piping over the PQ-QUIC mesh to the Exit Node.
    """

    def __init__(self, local_node: Any, exit_node_did: str):
        self.node = local_node
        self.exit_node_did = exit_node_did
        self.pending_streams: Dict[bytes, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        if hasattr(self.node, "register_message_handler"):
            self.node.register_message_handler(self._on_reply_message)

    def _on_reply_message(self, src_did: str, payload: bytes) -> None:
        """Handles IP7X reply frames from Exit Node."""
        if not payload.startswith(MAGIC_EXIT_RELAY) or len(payload) < 21:
            return

        cmd = payload[4]
        stream_id = payload[5:21]

        with self._lock:
            stream_ctx = self.pending_streams.get(stream_id)

        if not stream_ctx:
            return

        if cmd == CMD_CONNECTED:
            if len(payload) >= 23:
                status = struct.unpack("!H", payload[21:23])[0]
                stream_ctx["status"] = status
                stream_ctx["connected_event"].set()
        elif cmd == CMD_DATA:
            if len(payload) >= 25:
                data_len = struct.unpack("!I", payload[21:25])[0]
                chunk = payload[25: 25 + data_len]
                client_sock = stream_ctx.get("client_sock")
                if client_sock:
                    try:
                        client_sock.sendall(chunk)
                        stream_ctx["bytes_rx"] += len(chunk)
                    except Exception:
                        stream_ctx["closed_event"].set()
        elif cmd == CMD_CLOSE:
            stream_ctx["closed_event"].set()

    def open_tunneled_stream(
        self,
        target_host: str,
        target_port: int,
        client_sock: socket.socket,
        timeout: float = 6.0,
    ) -> Tuple[bool, str, int]:
        """
        Negotiates overlay channel with Exit Node and pipes bidirectional traffic.
        Returns (success, reason, bytes_transferred).
        """
        stream_id = os.urandom(16)
        conn_event = threading.Event()
        closed_event = threading.Event()

        ctx = {
            "stream_id": stream_id,
            "client_sock": client_sock,
            "connected_event": conn_event,
            "closed_event": closed_event,
            "status": None,
            "bytes_tx": 0,
            "bytes_rx": 0,
        }

        with self._lock:
            self.pending_streams[stream_id] = ctx

        # Send CMD_CONNECT to Exit Node
        host_bytes = target_host.encode("utf-8")
        req_frame = (
            MAGIC_EXIT_RELAY
            + bytes([CMD_CONNECT])
            + stream_id
            + struct.pack("!HH", target_port, len(host_bytes))
            + host_bytes
        )

        sent = self.node.send_message_sync(self.exit_node_did, req_frame)
        if not sent:
            with self._lock:
                self.pending_streams.pop(stream_id, None)
            return False, "Fallo al enviar trama CONNECT por el overlay PQ-QUIC", 0

        # Wait for CMD_CONNECTED
        if not conn_event.wait(timeout=timeout):
            with self._lock:
                self.pending_streams.pop(stream_id, None)
            return False, "Timeout esperando respuesta CONNECT del nodo de salida", 0

        if ctx["status"] != STATUS_OK:
            reason = "SSRF Bloqueado por Exit Node" if ctx["status"] == STATUS_SSRF_BLOCKED else "Exit Node no pudo conectar al destino"
            with self._lock:
                self.pending_streams.pop(stream_id, None)
            return False, reason, 0

        # Channel established: read from client_sock and transmit to Exit Node
        client_sock.setblocking(True)
        client_sock.settimeout(0.5)

        try:
            while not closed_event.is_set():
                try:
                    data = client_sock.recv(16384)
                    if not data:
                        break
                    ctx["bytes_tx"] += len(data)

                    # Frame in overlay chunks
                    chunk_size = 1100
                    for offset in range(0, len(data), chunk_size):
                        chunk = data[offset: offset + chunk_size]
                        frame = (
                            MAGIC_EXIT_RELAY
                            + bytes([CMD_DATA])
                            + stream_id
                            + struct.pack("!I", len(chunk))
                            + chunk
                        )
                        self.node.send_message_sync(self.exit_node_did, frame)
                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            # Send CMD_CLOSE to Exit Node
            close_frame = MAGIC_EXIT_RELAY + bytes([CMD_CLOSE]) + stream_id
            try:
                self.node.send_message_sync(self.exit_node_did, close_frame)
            except Exception:
                pass
            with self._lock:
                self.pending_streams.pop(stream_id, None)

        total_bytes = ctx["bytes_tx"] + ctx["bytes_rx"]
        return True, "Stream overlay completado exitosamente", total_bytes
