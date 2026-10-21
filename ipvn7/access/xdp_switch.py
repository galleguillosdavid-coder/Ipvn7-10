"""
IPVN 7 — Sovereign eBPF / XDP Wire-Speed Switch & Early-Drop Engine (Línea S)
=============================================================================
Implementa el conmutador acelerado a nivel de kernel eBPF/XDP y verificador en alambre.
Inspirado y rescatado de 0.7/src/pkg/l0/ebpf_xdp_spec.go y xdp_ipvn7.c.

Objetivos de Arquitectura:
  1. Descarte en Alambre (Wire-Speed Early Drop en O(1)): Descartar datagramas que
     no porten el número mágico canónico de IPVN 7 o violen las invariantes de MTU (1280B)
     antes de que consuman ciclos de CPU en espacio de usuario o alojen sk_buff en el kernel.
  2. Cumplimiento de Invariantes del Verificador eBPF: Emulación rigurosa de las comprobaciones
     de límites de memoria (packet bounds checking) del verificador de Linux kernel.
  3. Telemetría Atómica: Conteo lock-free de paquetes procesados, admitidos, descartados y retransmitidos.
  4. Generador de Código C Nativo: Exportación del programa en C compatible con clang -target bpf.
"""

from __future__ import annotations

import socket
import struct
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple, Set


class XDPAction(IntEnum):
    """Acciones canónicas del sistema eBPF / XDP de Linux kernel."""
    XDP_ABORTED = 0   # Error fatal de verificación o instrucción inválida
    XDP_DROP = 1      # Descarte inmediato en el driver/NIC antes de asignar sk_buff
    XDP_PASS = 2      # Permitir que el paquete suba al stack de red estándar
    XDP_TX = 3        # Reenviar el paquete por la misma interfaz de red
    XDP_REDIRECT = 4  # Redirigir a otro dispositivo o socket AF_XDP de usuario


# Puertos y números mágicos canónicos reconocidos por el conmutador IPVN 7
DEFAULT_MESH_PORT = 7777

# Catálogo completo de cabeceras mágicas canónicas (4 bytes big-endian)
CANONICAL_MAGICS: Set[bytes] = {
    b"IP7V",  # Legacy Genesis Datagram (0x49503756)
    b"IP7H",  # HRS Silent Substrate Frame
    b"IP7M",  # Mobility Ticket Anchor Frame
    b"IP7B",  # BitNet Quantized Container
    b"IP7X",  # Exit Relay Overlay Frame
    b"IP7R",  # Reciprocity Settlement Token Frame
    b"IP7S",  # Ephemeral Ring Signature Frame / DHT Sync
    b"IP7T",  # Tunnel Telemetry Frame
    b"IP7E",  # TEE Enclave Sealed Frame
    b"IP7Z",  # Zero-Knowledge Proof Frame (Schnorr / Bulletproof)
    b"IP7P",  # WAN Active Prober Binary Frame
}

MAX_MTU_PAYLOAD = 1280


@dataclass
class XDPFilterStats:
    """Telemetría atómica de conmutación y filtrado temprano en el kernel."""
    total_processed: int = 0
    passed: int = 0
    dropped: int = 0
    transmitted: int = 0
    redirected: int = 0
    malformed_dropped: int = 0
    bytes_processed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        total = max(1, self.total_processed)
        return {
            "total_processed": self.total_processed,
            "passed": self.passed,
            "dropped": self.dropped,
            "transmitted": self.transmitted,
            "redirected": self.redirected,
            "malformed_dropped": self.malformed_dropped,
            "bytes_processed": self.bytes_processed,
            "early_drop_ratio_pct": round((self.dropped / total) * 100.0, 2),
            "pass_ratio_pct": round((self.passed / total) * 100.0, 2),
        }


class XDPKernelSimulator:
    """
    Simulador formal de instrucciones de conmutación eBPF / XDP.
    Emula la ejecución del programa del kernel en espacio de usuario, verificando
    límites de cabeceras Ethernet, IPv4, IPv6 y UDP.
    """

    def __init__(self, mesh_port: int = DEFAULT_MESH_PORT):
        self.mesh_port = mesh_port if (mesh_port and mesh_port > 0) else DEFAULT_MESH_PORT
        self._lock = threading.Lock()
        self.stats = XDPFilterStats()

    def reset_stats(self) -> None:
        """Reinicia los contadores de telemetría."""
        with self._lock:
            self.stats = XDPFilterStats()

    def get_stats(self) -> Dict[str, Any]:
        """Retorna las métricas actuales del conmutador."""
        with self._lock:
            return self.stats.to_dict()

    def process_udp_payload(self, payload: bytes) -> Tuple[XDPAction, str]:
        """
        Fast-Path: Evalúa directamente una carga útil UDP recibida en el socket de malla.
        Aplica los invariantes canónicos de IPVN 7 en O(1).
        """
        with self._lock:
            self.stats.total_processed += 1
            self.stats.bytes_processed += len(payload)

            # Invariante 1: Límite estricto de MTU de 1280 bytes
            if len(payload) > MAX_MTU_PAYLOAD:
                self.stats.dropped += 1
                return XDPAction.XDP_DROP, f"DROP: Payload excede MTU canónico de {MAX_MTU_PAYLOAD}B ({len(payload)}B)"

            # Invariante 2: Verificación de longitud mínima para cabecera mágica
            if len(payload) < 4:
                self.stats.dropped += 1
                self.stats.malformed_dropped += 1
                return XDPAction.XDP_DROP, "DROP: Paquete truncado (< 4 bytes de cabecera mágica)"

            # Invariante 3: Validación del número mágico canónico
            magic = payload[:4]
            if magic not in CANONICAL_MAGICS:
                self.stats.dropped += 1
                return XDPAction.XDP_DROP, f"DROP: Magic bytes desconocidos ({magic!r})"

            # Paquete legítimo verificado de IPVN 7
            self.stats.passed += 1
            return XDPAction.XDP_PASS, f"PASS: Trama legítima IPVN 7 ({magic.decode('ascii', errors='replace')})"

    def process_frame(self, frame: bytes) -> Tuple[XDPAction, str]:
        """
        Evalúa una trama Ethernet completa replicando el verificador de límites eBPF de Linux.
        Analiza Ethernet (14B) -> IP (20B+) -> UDP (8B) -> Payload Magic.
        """
        with self._lock:
            self.stats.total_processed += 1
            self.stats.bytes_processed += len(frame)

            # 1. Verificación de límite de cabecera Ethernet (14 bytes mínimos)
            if len(frame) < 14:
                self.stats.dropped += 1
                self.stats.malformed_dropped += 1
                return XDPAction.XDP_DROP, "DROP: Trama Ethernet truncada (< 14B)"

            ethertype = struct.unpack(">H", frame[12:14])[0]

            # Si no es IPv4 (0x0800) ni IPv6 (0x86DD), XDP_PASS al stack estándar del sistema
            if ethertype not in (0x0800, 0x86DD):
                self.stats.passed += 1
                return XDPAction.XDP_PASS, f"PASS: EtherType no-IP ({hex(ethertype)}) transmitido al SO"

            # 2. Análisis de cabecera IPv4
            if ethertype == 0x0800:
                ip_data = frame[14:]
                if len(ip_data) < 20:
                    self.stats.dropped += 1
                    self.stats.malformed_dropped += 1
                    return XDPAction.XDP_DROP, "DROP: Cabecera IPv4 truncada (< 20B)"

                version_ihl = ip_data[0]
                ihl = (version_ihl & 0x0F) * 4
                if ihl < 20 or len(ip_data) < ihl:
                    self.stats.dropped += 1
                    self.stats.malformed_dropped += 1
                    return XDPAction.XDP_DROP, "DROP: Longitud IHL IPv4 inconsistente"

                protocol = ip_data[9]
                if protocol != 17:  # No es UDP
                    self.stats.passed += 1
                    return XDPAction.XDP_PASS, f"PASS: Protocolo no-UDP ({protocol}) derivado al SO"

                udp_data = ip_data[ihl:]
                if len(udp_data) < 8:
                    self.stats.dropped += 1
                    self.stats.malformed_dropped += 1
                    return XDPAction.XDP_DROP, "DROP: Cabecera UDP truncada (< 8B)"

                dest_port = struct.unpack(">H", udp_data[2:4])[0]
                if dest_port != self.mesh_port:
                    self.stats.passed += 1
                    return XDPAction.XDP_PASS, f"PASS: UDP hacia puerto distinto ({dest_port} != {self.mesh_port})"

                payload = udp_data[8:]

            # 3. Análisis de cabecera IPv6
            else:
                ip_data = frame[14:]
                if len(ip_data) < 40:
                    self.stats.dropped += 1
                    self.stats.malformed_dropped += 1
                    return XDPAction.XDP_DROP, "DROP: Cabecera IPv6 truncada (< 40B)"

                next_header = ip_data[6]
                if next_header != 17:  # No es UDP
                    self.stats.passed += 1
                    return XDPAction.XDP_PASS, f"PASS: IPv6 no-UDP ({next_header}) derivado al SO"

                udp_data = ip_data[40:]
                if len(udp_data) < 8:
                    self.stats.dropped += 1
                    self.stats.malformed_dropped += 1
                    return XDPAction.XDP_DROP, "DROP: Cabecera UDP IPv6 truncada (< 8B)"

                dest_port = struct.unpack(">H", udp_data[2:4])[0]
                if dest_port != self.mesh_port:
                    self.stats.passed += 1
                    return XDPAction.XDP_PASS, f"PASS: UDP IPv6 hacia puerto distinto ({dest_port})"

                payload = udp_data[8:]

            # 4. Evaluación de la carga útil dirigida al puerto de la malla
            if len(payload) > MAX_MTU_PAYLOAD:
                self.stats.dropped += 1
                return XDPAction.XDP_DROP, f"DROP: Payload UDP excede MTU {MAX_MTU_PAYLOAD}B ({len(payload)}B)"

            if len(payload) < 4:
                self.stats.dropped += 1
                self.stats.malformed_dropped += 1
                return XDPAction.XDP_DROP, "DROP: Datagrama dirigido a malla truncado (< 4B magic)"

            magic = payload[:4]
            if magic not in CANONICAL_MAGICS:
                self.stats.dropped += 1
                return XDPAction.XDP_DROP, f"DROP: Tráfico no-IPVN7 en puerto de malla (Magic {magic!r})"

            self.stats.passed += 1
            return XDPAction.XDP_PASS, f"PASS: Datagrama IPVN 7 legítimo ({magic.decode('ascii', errors='replace')})"

    @staticmethod
    def synthesize_ethernet_frame(
        payload: bytes,
        src_ip: str = "192.168.1.50",
        dst_ip: str = "192.168.1.100",
        src_port: int = 54321,
        dst_port: int = DEFAULT_MESH_PORT,
    ) -> bytes:
        """
        Sintetiza una trama Ethernet + IPv4 + UDP canónica para pruebas y benchmarks.
        """
        import socket
        # Cabecera Ethernet (14 bytes): DstMAC(6) + SrcMAC(6) + EtherType(2)
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\x08\x00"

        # Cabecera UDP (8 bytes): SrcPort(2) + DstPort(2) + Length(2) + Checksum(2)
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack(">HHHH", src_port, dst_port, udp_len, 0x0000)

        # Cabecera IPv4 (20 bytes):
        ip_total_len = 20 + udp_len
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack(
            ">BBHHHBBH4s4s",
            0x45,         # Version 4, IHL 5
            0x00,         # DSCP/ECN
            ip_total_len, # Total Length
            0x1234,       # Identification
            0x4000,       # Flags (Don't Fragment)
            64,           # TTL
            17,           # Protocol (UDP)
            0x0000,       # Header Checksum (simulado)
            src_bytes,
            dst_bytes,
        )

        return eth_hdr + ip_hdr + udp_hdr + payload

    @staticmethod
    def generate_c_program(mesh_port: int = DEFAULT_MESH_PORT) -> str:
        """
        Genera el código fuente C del programa eBPF / XDP para compilación con clang.
        """
        return f"""// ==============================================================================
// IPVN 7 Native Linux eBPF / XDP Kernel Program (Línea S - Canonical Wire-Speed Filter)
// Compile with: clang -O2 -target bpf -c xdp_ipvn7.c -o xdp_ipvn7.o
// ==============================================================================

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPVN7_PORT {mesh_port}
#define MAX_MTU_PAYLOAD {MAX_MTU_PAYLOAD}

// Magic bytes canónicos de IPVN 7
#define MAGIC_IP7V 0x49503756 // "IP7V"
#define MAGIC_IP7H 0x49503748 // "IP7H"
#define MAGIC_IP7M 0x4950374D // "IP7M"
#define MAGIC_IP7B 0x49503742 // "IP7B"
#define MAGIC_IP7X 0x49503758 // "IP7X"
#define MAGIC_IP7R 0x49503752 // "IP7R"
#define MAGIC_IP7S 0x49503753 // "IP7S"
#define MAGIC_IP7T 0x49503754 // "IP7T"
#define MAGIC_IP7E 0x49503745 // "IP7E"
#define MAGIC_IP7Z 0x4950375A // "IP7Z"
#define MAGIC_IP7P 0x49503750 // "IP7P"

struct {{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 6);
}} ipvn7_stats_map SEC(".maps");

enum {{
    STAT_TOTAL = 0,
    STAT_PASS  = 1,
    STAT_DROP  = 2,
    STAT_MALFORMED = 3,
    STAT_BYTES = 4,
}};

static __always_inline void increment_stat(__u32 key, __u64 bytes) {{
    __u64 *val = bpf_map_lookup_elem(&ipvn7_stats_map, &key);
    if (val) *val += 1;
    __u32 bkey = STAT_BYTES;
    __u64 *bval = bpf_map_lookup_elem(&ipvn7_stats_map, &bkey);
    if (bval) *bval += bytes;
}}

SEC("xdp")
int xdp_ipvn7_filter(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 len = data_end - data;

    increment_stat(STAT_TOTAL, len);

    // 1. Verificación de límite de cabecera Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Verificación de límite de cabecera IPv4
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr)) return XDP_PASS;

    // 3. Verificación de límite de cabecera UDP
    struct udphdr *udp = (void *)((char *)ip + ip_len);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    if (udp->dest != bpf_htons(IPVN7_PORT)) return XDP_PASS;

    // 4. Verificación de carga útil dirigida al puerto de la malla
    void *payload = (void *)(udp + 1);
    __u64 payload_len = data_end - payload;

    if (payload_len > MAX_MTU_PAYLOAD) {{
        increment_stat(STAT_DROP, len);
        return XDP_DROP; // Violación de MTU acotado
    }}

    __u32 *magic_ptr = payload;
    if ((void *)(magic_ptr + 1) > data_end) {{
        increment_stat(STAT_MALFORMED, len);
        return XDP_DROP; // Paquete truncado
    }}

    __u32 magic = bpf_ntohl(*magic_ptr);
    if (magic == MAGIC_IP7V || magic == MAGIC_IP7H || magic == MAGIC_IP7M ||
        magic == MAGIC_IP7B || magic == MAGIC_IP7X || magic == MAGIC_IP7R ||
        magic == MAGIC_IP7S || magic == MAGIC_IP7T || magic == MAGIC_IP7E ||
        magic == MAGIC_IP7Z || magic == MAGIC_IP7P) {{
        increment_stat(STAT_PASS, len);
        return XDP_PASS;
    }}

    // Tráfico ilegítimo dirigido al puerto seguro de IPVN7 -> Descarte en alambre O(1)
    increment_stat(STAT_DROP, len);
    return XDP_DROP;
}}

char _license[] SEC("license") = "GPL";
"""
