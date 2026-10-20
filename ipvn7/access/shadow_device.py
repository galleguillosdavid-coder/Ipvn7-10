"""
Shadow Device Registry & Edge Ambassador.
Rescued from 0.7/src/pkg/l1/shadow_device.go.

Enables an IPVN7 node to act as an Edge Ambassador for local LAN hardware
(printers, Smart TVs, security cameras, IoT sensors, and Edge AI workers like Ollama/BitNet)
without modifying their original firmware.
"""

from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class DeviceType(str, Enum):
    PRINTER = "printer"
    DISPLAY = "display"
    CAMERA = "camera"
    IOT = "iot"
    EDGE_AI = "edge_ai"
    GENERIC = "generic"


def derive_shadow_did(mac: str) -> str:
    """Calculates a deterministic DID based on the SHA-256 hash of the cleaned MAC address."""
    clean_mac = mac.lower().replace(":", "").replace("-", "")
    h = hashlib.sha256(f"ipvn7:shadow:{clean_mac}".encode("utf-8")).digest()
    return f"did:ipvn7:shadow:{h[:16].hex()}"


@dataclass
class ShadowDevice:
    did: str
    name: str
    device_type: DeviceType
    physical_ip: str
    mac: str
    virtual_ipv4: str
    allowed_ports: List[int]
    created_at: float = field(default_factory=time.time)
    enabled: bool = True


class ShadowDeviceRegistry:
    """
    Maintains the local catalog of bridged LAN hardware represented with
    sovereign overlay identities (10.7.100.X/24).
    """

    def __init__(self, start_ip_index: int = 10):
        self._devices_by_did: Dict[str, ShadowDevice] = {}
        self._devices_by_vip: Dict[str, ShadowDevice] = {}
        self._next_ip_index = start_ip_index

    def register_device(
        self,
        name: str,
        physical_ip: str,
        mac: str,
        device_type: DeviceType = DeviceType.GENERIC,
        allowed_ports: Optional[List[int]] = None,
    ) -> ShadowDevice:
        """Registers a physical LAN device in the sovereign mesh with a deterministic shadow DID."""
        if not physical_ip or not mac:
            raise ValueError("Physical IP and MAC address are required")

        ports = allowed_ports if allowed_ports is not None else [80, 443]
        did = derive_shadow_did(mac)

        if did in self._devices_by_did:
            existing = self._devices_by_did[did]
            existing.name = name
            existing.physical_ip = physical_ip
            existing.allowed_ports = ports
            existing.enabled = True
            return existing

        if self._next_ip_index > 254:
            raise RuntimeError("Shadow virtual IP pool exhausted in local block (10.7.100.X)")

        vip = f"10.7.100.{self._next_ip_index}"
        self._next_ip_index += 1

        dev = ShadowDevice(
            did=did,
            name=name,
            device_type=device_type,
            physical_ip=physical_ip,
            mac=mac,
            virtual_ipv4=vip,
            allowed_ports=ports,
        )

        self._devices_by_did[did] = dev
        self._devices_by_vip[vip] = dev
        return dev

    def register_edge_ai_worker(
        self,
        name: str,
        physical_ip: str,
        mac: str,
        port: int = 11434,
    ) -> ShadowDevice:
        """Registers a local compute/inference node (e.g. Ollama, BitNet, Exo)."""
        return self.register_device(
            name=name,
            physical_ip=physical_ip,
            mac=mac,
            device_type=DeviceType.EDGE_AI,
            allowed_ports=[port],
        )

    def lookup_by_did(self, did: str) -> Optional[ShadowDevice]:
        return self._devices_by_did.get(did)

    def lookup_by_vip(self, vip: str) -> Optional[ShadowDevice]:
        return self._devices_by_vip.get(vip)

    def list_devices(self) -> List[ShadowDevice]:
        return list(self._devices_by_did.values())

    def toggle_device(self, did: str, enabled: bool) -> bool:
        dev = self._devices_by_did.get(did)
        if dev:
            dev.enabled = enabled
            return True
        return False

    def is_port_allowed(self, did: str, port: int) -> bool:
        dev = self._devices_by_did.get(did)
        if not dev or not dev.enabled:
            return False
        return port in dev.allowed_ports

    def summary(self) -> dict:
        devices = list(self._devices_by_did.values())
        return {
            "total_shadow_devices": len(devices),
            "active_devices": sum(1 for d in devices if d.enabled),
            "device_types": {
                t.value: sum(1 for d in devices if d.device_type == t)
                for t in DeviceType
            },
            "devices": [
                {
                    "did": d.did,
                    "name": d.name,
                    "type": d.device_type.value,
                    "physical_ip": d.physical_ip,
                    "virtual_ipv4": d.virtual_ipv4,
                    "allowed_ports": d.allowed_ports,
                    "enabled": d.enabled,
                }
                for d in devices
            ],
        }
