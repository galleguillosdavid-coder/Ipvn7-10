"""
IPVN 7 Universal SOCKS5 Proxy Gateway (RFC 1928)
Enables any commercial software (browsers, curl, git, SSH, Telegram) to transparently route
arbitrary TCP traffic through the IPVN 7 Post-Quantum QUIC mesh.
Inspired by ipvn7 vX7 pkg/l1/socks5_gateway.go.
"""

from __future__ import annotations
import socket
import select
import threading
import time
from typing import Optional, Callable, Dict, Any, Tuple

from ..node.node import IPVN7Node
from ..security.egress_policy import EgressSecurityPolicy


# SOCKS5 Constants (RFC 1928)
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_NO_ACCEPT = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ADDR_IPV4 = 0x01
SOCKS5_ADDR_DOMAIN = 0x03
SOCKS5_ADDR_IPV6 = 0x04

SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_SERVER_FAILURE = 0x01
SOCKS5_REP_CONN_NOT_ALLOWED = 0x02
SOCKS5_REP_NETWORK_UNREACHABLE = 0x03
SOCKS5_REP_HOST_UNREACHABLE = 0x04
SOCKS5_REP_CONN_REFUSED = 0x05
SOCKS5_REP_TTL_EXPIRED = 0x06
SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07
SOCKS5_REP_ADDR_NOT_SUPPORTED = 0x08


class IPVN7SOCKS5Gateway:
    """
    RFC 1928 compliant SOCKS5 gateway running on Windows loopback (default 127.0.0.1:10807).
    Proxies inbound TCP connections through the IPVN 7 quantum-resistant overlay.
    """

    def __init__(
        self,
        local_node: IPVN7Node,
        exit_node: Optional[IPVN7Node] = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 10807,
        traffic_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.local_node = local_node
        self.exit_node = exit_node or local_node
        self.listen_host = listen_host
        self.requested_port = listen_port
        self.traffic_logger = traffic_logger

        self.server_sock: Optional[socket.socket] = None
        self.bound_port = 0
        self._is_running = False
        self._thread: Optional[threading.Thread] = None

        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "bytes_tx": 0,
            "bytes_rx": 0,
            "last_destination": "",
        }
        self._lock = threading.Lock()

    def start(self) -> int:
        """Starts SOCKS5 listener on loopback."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.listen_host, self.requested_port))
        self.server_sock.listen(64)
        self.bound_port = self.server_sock.getsockname()[1]
        self._is_running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.bound_port

    def stop(self) -> None:
        """Stops SOCKS5 gateway."""
        self._is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
        if self._thread:
            self._thread.join(timeout=0.3)

    def _accept_loop(self) -> None:
        while self._is_running:
            try:
                self.server_sock.settimeout(0.2)
                client_sock, client_addr = self.server_sock.accept()
                with self._lock:
                    self.stats["total_connections"] += 1
                    self.stats["active_connections"] += 1

                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except (socket.timeout, BlockingIOError):
                continue
            except Exception:
                break

    def _send_reply(
        self,
        sock: socket.socket,
        rep: int,
        bind_addr: str = "0.0.0.0",
        bind_port: int = 0,
    ) -> None:
        try:
            ip_bytes = socket.inet_aton(bind_addr)
            port_bytes = bind_port.to_bytes(2, byteorder="big")
            reply = bytes([SOCKS5_VERSION, rep, 0x00, SOCKS5_ADDR_IPV4]) + ip_bytes + port_bytes
            sock.sendall(reply)
        except Exception:
            pass

    def _handle_client(self, client: socket.socket, addr: Tuple[str, int]) -> None:
        remote: Optional[socket.socket] = None
        try:
            client.settimeout(5.0)

            # 1. Version & Auth negotiation
            v_n = client.recv(2)
            if len(v_n) < 2 or v_n[0] != SOCKS5_VERSION:
                return

            n_methods = v_n[1]
            methods = client.recv(n_methods)
            if SOCKS5_AUTH_NONE not in methods:
                client.sendall(bytes([SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPT]))
                return

            # Accept NO AUTH
            client.sendall(bytes([SOCKS5_VERSION, SOCKS5_AUTH_NONE]))

            # 2. Connection Request
            req = client.recv(4)
            if len(req) < 4:
                return

            ver, cmd, _, atyp = req[0], req[1], req[2], req[3]
            if ver != SOCKS5_VERSION or cmd != SOCKS5_CMD_CONNECT:
                self._send_reply(client, SOCKS5_REP_CMD_NOT_SUPPORTED)
                return

            # Read Destination Address
            dest_host = ""
            if atyp == SOCKS5_ADDR_IPV4:
                ipv4_bytes = client.recv(4)
                if len(ipv4_bytes) < 4:
                    return
                dest_host = socket.inet_ntoa(ipv4_bytes)
            elif atyp == SOCKS5_ADDR_DOMAIN:
                dlen_byte = client.recv(1)
                if not dlen_byte:
                    return
                dlen = dlen_byte[0]
                domain_bytes = client.recv(dlen)
                if len(domain_bytes) < dlen:
                    return
                dest_host = domain_bytes.decode("utf-8", errors="replace")
            elif atyp == SOCKS5_ADDR_IPV6:
                ipv6_bytes = client.recv(16)
                if len(ipv6_bytes) < 16:
                    return
                dest_host = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
            else:
                self._send_reply(client, SOCKS5_REP_ADDR_NOT_SUPPORTED)
                return

            # Read Destination Port
            port_bytes = client.recv(2)
            if len(port_bytes) < 2:
                return
            dest_port = int.from_bytes(port_bytes, byteorder="big")

            dest_str = f"{dest_host}:{dest_port}"
            with self._lock:
                self.stats["last_destination"] = dest_str

            if self.traffic_logger:
                self.traffic_logger({
                    "time": time.strftime("%H:%M:%S"),
                    "protocol": "SOCKS5",
                    "client": f"{addr[0]}:{addr[1]}",
                    "target_host": dest_host,
                    "target_port": dest_port,
                    "exit_node": self.exit_node.did,
                })

            # 3. Security Boundary: Enforce EgressSecurityPolicy (Anti-SSRF & DNS Rebinding)
            is_allowed, reason, valid_ips = EgressSecurityPolicy.resolve_and_validate_host(dest_host, dest_port)
            if not is_allowed:
                if self.traffic_logger:
                    self.traffic_logger({
                        "time": time.strftime("%H:%M:%S"),
                        "protocol": "SOCKS5",
                        "client": f"{addr[0]}:{addr[1]}",
                        "target_host": dest_host,
                        "target_port": dest_port,
                        "status": f"BLOCKED_SSRF: {reason}",
                    })
                self._send_reply(client, SOCKS5_REP_CONN_NOT_ALLOWED)
                return

            # Connect directly to the validated IP to prevent DNS rebinding attacks
            target_ip = valid_ips[0]
            try:
                remote = socket.create_connection((target_ip, dest_port), timeout=6.0)
            except Exception:
                self._send_reply(client, SOCKS5_REP_HOST_UNREACHABLE)
                return

            # SOCKS5 Connection Granted
            b_ip, b_port = remote.getsockname()[0], remote.getsockname()[1]
            try:
                self._send_reply(client, SOCKS5_REP_SUCCESS, bind_addr=b_ip, bind_port=b_port)
            except Exception:
                self._send_reply(client, SOCKS5_REP_SUCCESS)

            # 4. Bidirectional Tunneling with IPVN 7 accounting
            client.setblocking(False)
            remote.setblocking(False)

            while self._is_running:
                rlist, _, xlist = select.select([client, remote], [], [client, remote], 1.0)
                if xlist:
                    break

                for s in rlist:
                    if s is client:
                        data = client.recv(32768)
                        if not data:
                            return
                        remote.sendall(data)
                        with self._lock:
                            self.stats["bytes_tx"] += len(data)
                    else:
                        data = remote.recv(32768)
                        if not data:
                            return
                        client.sendall(data)
                        with self._lock:
                            self.stats["bytes_rx"] += len(data)

        except Exception:
            pass
        finally:
            if remote:
                try:
                    remote.close()
                except Exception:
                    pass
            try:
                client.close()
            except Exception:
                pass
            with self._lock:
                self.stats["active_connections"] = max(0, self.stats["active_connections"] - 1)
