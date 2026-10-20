"""
IPVN 7 Hardware Abstraction Layer (HAL)
Abstracts physical network interfaces (Wi-Fi, 5G, Ethernet, Satellite)
and provides unified DID-compatible framing over native network hardware.
"""

from __future__ import annotations
import socket
import asyncio
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field

from ..network.packet import IPVN7Packet


class PhysicalInterfaceType(Enum):
    ETHERNET = auto()
    WIFI = auto()
    CELLULAR_5G = auto()
    SATELLITE = auto()
    LOOPBACK = auto()
    VIRTUAL_TUN = auto()


class InterfaceStatus(Enum):
    UP = auto()
    DOWN = auto()
    DEGRADED = auto()


@dataclass
class PhysicalInterface:
    """Represents a physical or virtual network interface."""
    name: str
    if_type: PhysicalInterfaceType
    ipv4_address: str = "127.0.0.1"
    ipv6_address: Optional[str] = None
    hw_address: str = "00:00:00:00:00:00"
    mtu: int = 1500
    metric: int = 10
    bandwidth_mbps: float = 1000.0
    status: InterfaceStatus = InterfaceStatus.UP

    def is_available(self) -> bool:
        return self.status == InterfaceStatus.UP


class UDPSocketDriver:
    """Low-level UDP socket driver for real packet delivery across physical interfaces."""

    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 9443):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.sock: Optional[socket.socket] = None
        self._is_running = False

    def open(self) -> int:
        """Opens and binds the UDP socket. Returns the actual bound port."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)
        self.sock.bind((self.bind_host, self.bind_port))
        self.bind_port = self.sock.getsockname()[1]
        self._is_running = True
        return self.bind_port

    def send_packet(self, packet: IPVN7Packet, target_host: str, target_port: int) -> int:
        """Serializes and transmits an IPVN 7 packet over the socket."""
        if not self.sock:
            raise RuntimeError("Socket is not open")
        raw_data = packet.serialize()
        return self.sock.sendto(raw_data, (target_host, target_port))

    def receive_packet(self, max_bytes: int = 65535) -> Optional[Tuple[IPVN7Packet, Tuple[str, int]]]:
        """Reads and deserializes a packet non-blockingly."""
        if not self.sock:
            return None
        try:
            data, addr = self.sock.recvfrom(max_bytes)
            packet = IPVN7Packet.deserialize(data)
            return packet, addr
        except (BlockingIOError, InterruptedError):
            return None
        except Exception:
            return None

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self._is_running = False


class HardwareAbstractionLayer:
    """
    Manages active hardware interfaces, multi-homing policies,
    and automatic failover when switching between Wi-Fi and 5G.
    """

    def __init__(self):
        self.interfaces: Dict[str, PhysicalInterface] = {}
        self._drivers: Dict[str, UDPSocketDriver] = {}
        self._default_driver: Optional[UDPSocketDriver] = None
        self._probe_interfaces()

    def _probe_interfaces(self) -> None:
        """Auto-discovers host system interfaces and registers baseline defaults."""
        # 1. Loopback
        self.register_interface(
            PhysicalInterface(
                name="lo0",
                if_type=PhysicalInterfaceType.LOOPBACK,
                ipv4_address="127.0.0.1",
                mtu=65535,
                metric=1,
                bandwidth_mbps=10000.0,
            )
        )

        # 2. Primary detected interface
        try:
            hostname = socket.gethostname()
            detected_ip = socket.gethostbyname(hostname)
        except Exception:
            detected_ip = "127.0.0.1"

        self.register_interface(
            PhysicalInterface(
                name="primary0",
                if_type=PhysicalInterfaceType.ETHERNET,
                ipv4_address=detected_ip,
                mtu=1500,
                metric=10,
                bandwidth_mbps=1000.0,
            )
        )

        # 3. Virtual Wi-Fi / 5G simulated interfaces for multi-homing demonstrations
        self.register_interface(
            PhysicalInterface(
                name="wlan0",
                if_type=PhysicalInterfaceType.WIFI,
                ipv4_address="192.168.1.100",
                mtu=1500,
                metric=20,
                bandwidth_mbps=300.0,
            )
        )

        self.register_interface(
            PhysicalInterface(
                name="wwan5g",
                if_type=PhysicalInterfaceType.CELLULAR_5G,
                ipv4_address="10.42.0.8",
                mtu=1420,
                metric=40,
                bandwidth_mbps=500.0,
            )
        )

    def register_interface(self, iface: PhysicalInterface) -> None:
        self.interfaces[iface.name] = iface

    def get_preferred_interface(self) -> Optional[PhysicalInterface]:
        """Returns the available interface with the best metric."""
        available = [i for i in self.interfaces.values() if i.is_available()]
        if not available:
            return None
        return min(available, key=lambda i: i.metric)

    def start_socket_driver(self, bind_host: str = "0.0.0.0", bind_port: int = 0) -> UDPSocketDriver:
        """Spawns an active UDP overlay driver."""
        driver = UDPSocketDriver(bind_host=bind_host, bind_port=bind_port)
        driver.open()
        self._default_driver = driver
        return driver

    def stop_all(self) -> None:
        if self._default_driver:
            self._default_driver.close()
            self._default_driver = None
        for d in self._drivers.values():
            d.close()
        self._drivers.clear()
