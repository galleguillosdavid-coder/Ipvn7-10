"""
IPVN 7 Dual-Stack Translation Gateway (NAT74 / NAT76)
Provides seamless backward compatibility: accepts standard legacy IPv4/IPv6
TCP client connections and maps them transparently into post-quantum encrypted
IPVN 7 PQ-QUIC streams.
"""

from __future__ import annotations
import socket
import threading
import time
from typing import Dict, Optional, Tuple

from ..node.node import IPVN7Node


class IPVN7DualStackGateway:
    """
    Translates legacy IPv4/IPv6 connections to and from IPVN 7 DID endpoints.
    Allows legacy clients (e.g. curl, browser, TCP tools) to access IPVN 7 services.
    """

    def __init__(
        self,
        local_node: IPVN7Node,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        default_target_did: Optional[str] = None,
    ):
        self.node = local_node
        self.listen_host = listen_host
        self.requested_port = listen_port
        self.default_target_did = default_target_did

        # Virtual routing table: legacy virtual IP or port -> target DID
        self.did_route_table: Dict[str, str] = {}
        if default_target_did:
            self.did_route_table["default"] = default_target_did

        self.server_sock: Optional[socket.socket] = None
        self.bound_port = 0
        self._is_running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Tracking metrics
        self.metrics = {
            "legacy_connections_accepted": 0,
            "bytes_translated_in": 0,
            "bytes_translated_out": 0,
        }

    def register_route(self, route_key: str, target_did: str) -> None:
        """Associates a route key (e.g. host header or virtual destination) with a target DID."""
        self.did_route_table[route_key] = target_did

    def start(self) -> int:
        """Binds TCP listener and launches worker thread."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.listen_host, self.requested_port))
        self.server_sock.listen(10)
        self.bound_port = self.server_sock.getsockname()[1]
        self._is_running = True

        self._worker_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._worker_thread.start()
        return self.bound_port

    def stop(self) -> None:
        """Shuts down the gateway listener."""
        self._is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
        if self._worker_thread:
            self._worker_thread.join(timeout=0.2)

    def _accept_loop(self) -> None:
        """Accepts incoming legacy TCP clients."""
        while self._is_running:
            try:
                self.server_sock.settimeout(0.2)
                client_conn, client_addr = self.server_sock.accept()
                self.metrics["legacy_connections_accepted"] += 1
                t = threading.Thread(target=self._handle_client, args=(client_conn, client_addr), daemon=True)
                t.start()
            except (socket.timeout, BlockingIOError):
                continue
            except Exception:
                break

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Reads from legacy TCP client, translates to IPVN 7 PQ-QUIC, and sends back reply."""
        try:
            client_sock.settimeout(1.0)
            data = client_sock.recv(65535)
            if not data:
                return

            self.metrics["bytes_translated_in"] += len(data)

            # Resolve target DID from table or fallback default
            target_did = self.did_route_table.get("default")
            if not target_did:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 29\r\n\r\nIPVN7: No target DID route")
                return

            # Response synchronization event
            response_container: list[bytes] = []
            response_event = threading.Event()

            def on_reply(src_did: str, reply_payload: bytes):
                response_container.append(reply_payload)
                response_event.set()

            # Temporarily register response handler
            self.node.register_message_handler(on_reply)

            # Forward payload into IPVN 7 network
            sent = self.node.send_message_sync(target_did, data)
            if sent:
                # Wait briefly for reply from IPVN 7 node
                if response_event.wait(timeout=1.0):
                    reply = response_container[0]
                    client_sock.sendall(reply)
                    self.metrics["bytes_translated_out"] += len(reply)
                else:
                    # Echo acknowledgment if single-direction
                    client_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\nIPVN7 Delivery Confirmed (1-RTT)")
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
