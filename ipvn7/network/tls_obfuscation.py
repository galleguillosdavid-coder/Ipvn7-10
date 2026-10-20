"""
IPVN 7 TLS 1.3 Obfuscation & DPI Bypass Engine (RFC 8446)
Permite que el tráfico cuántico de IPVN 7 se transporte indistinguible
de navegación HTTPS legítima en el puerto 443, burlando firewalls
de inspección profunda de paquetes (DPI/Layer-7).
Inspirado en ipvn7 vX7 pkg/l1/tls_obfuscation.go.
"""

from __future__ import annotations
import os
import struct
from enum import IntEnum
from typing import Tuple, Optional


class TLSRecordType(IntEnum):
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17


class TLSHandshakeType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02


TLS_VERSION_LEGACY = 0x0303  # TLS 1.2 legacy wire version for middlebox compat
TLS_VERSION_13 = 0x0304      # TLS 1.3 negotiated version
TLS_RECORD_HEADER_SIZE = 5   # Type(1B) + Version(2B) + Length(2B)
TLS_MAX_PLAINTEXT = 16384    # 16 KB max RFC 8446 plaintext record length


class TLSOptionEngine:
    """
    Motor de camuflaje y enmascaramiento TLS 1.3.
    Empaqueta datagramas IPVN 7 como registros TLS ApplicationData legítimos
    y sintetiza handshakes ClientHello RFC 8446 con SNI y extensiones reales.
    """

    def __init__(self, default_sni: str = "gateway.cloudflare.com"):
        self.default_sni = default_sni
        self.stats = {
            "records_wrapped": 0,
            "records_unwrapped": 0,
            "client_hellos_generated": 0,
            "bytes_camouflaged": 0,
        }

    def build_client_hello(self, sni: Optional[str] = None) -> bytes:
        """
        Genera un mensaje TLS 1.3 ClientHello (RFC 8446) sintético pero
        sintácticamente indistinguible con SNI y extensiones modernas.
        """
        server_name = (sni or self.default_sni).encode("utf-8")

        # 1. Random (32 bytes)
        random_bytes = os.urandom(32)

        # 2. Legacy Session ID (32 bytes para compatibilidad middlebox)
        session_id = os.urandom(32)
        session_id_part = bytes([len(session_id)]) + session_id

        # 3. Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        cipher_suites = bytes([0x13, 0x01, 0x13, 0x03])
        cipher_part = struct.pack(">H", len(cipher_suites)) + cipher_suites

        # 4. Compression Methods: 1 byte null (0x00)
        compression_part = bytes([0x01, 0x00])

        # 5. Extensiones TLS
        exts_buf = bytearray()

        # Extensión SNI (0x0000)
        sni_payload = bytearray()
        sni_payload.extend(struct.pack(">H", len(server_name) + 3))  # list length
        sni_payload.append(0x00)                                     # NameType: host_name
        sni_payload.extend(struct.pack(">H", len(server_name)))
        sni_payload.extend(server_name)
        exts_buf.extend(struct.pack(">HH", 0x0000, len(sni_payload)))
        exts_buf.extend(sni_payload)

        # Extensión Supported Versions: TLS 1.3 (0x002b)
        sup_vers = bytes([0x02, 0x03, 0x04])  # length=2, version 0x0304
        exts_buf.extend(struct.pack(">HH", 0x002B, len(sup_vers)))
        exts_buf.extend(sup_vers)

        # Extensión Supported Groups: X25519 (0x001d)
        sup_groups = struct.pack(">HH", 0x0002, 0x001D)
        exts_buf.extend(struct.pack(">HH", 0x000A, len(sup_groups)))
        exts_buf.extend(sup_groups)

        # Extensión Key Share sintética (0x0033) con clave pública X25519 (32 bytes)
        ks_payload = bytearray()
        client_shares_len = 2 + 2 + 32  # group(2) + key_len(2) + key(32)
        ks_payload.extend(struct.pack(">HHH", client_shares_len, 0x001D, 32))
        ks_payload.extend(os.urandom(32))
        exts_buf.extend(struct.pack(">HH", 0x0033, len(ks_payload)))
        exts_buf.extend(ks_payload)

        # Construir cuerpo del ClientHello
        ch_body = bytearray()
        ch_body.extend(struct.pack(">H", TLS_VERSION_LEGACY))
        ch_body.extend(random_bytes)
        ch_body.extend(session_id_part)
        ch_body.extend(cipher_part)
        ch_body.extend(compression_part)
        ch_body.extend(struct.pack(">H", len(exts_buf)))
        ch_body.extend(exts_buf)

        # Envolver en Handshake (Type=1 ClientHello, Length 3 bytes)
        handshake_msg = bytearray()
        handshake_msg.append(TLSHandshakeType.CLIENT_HELLO)
        handshake_msg.extend(len(ch_body).to_bytes(3, "big"))
        handshake_msg.extend(ch_body)

        self.stats["client_hellos_generated"] += 1
        return self.wrap_record(bytes(handshake_msg), TLSRecordType.HANDSHAKE)

    def wrap_record(self, payload: bytes, record_type: int = TLSRecordType.APPLICATION_DATA) -> bytes:
        """
        Envuelve un payload binario en un registro TLS 1.3 legítimo.
        Cabecera: [Type (1B)][Legacy Version (2B)][Length (2B BigEndian)]
        """
        if len(payload) > TLS_MAX_PLAINTEXT:
            raise ValueError(f"Payload excede longitud máxima TLS ({len(payload)} > {TLS_MAX_PLAINTEXT})")

        header = struct.pack(">BHH", int(record_type), TLS_VERSION_LEGACY, len(payload))
        self.stats["records_wrapped"] += 1
        self.stats["bytes_camouflaged"] += len(payload)
        return header + payload

    def unwrap_record(self, raw_record: bytes) -> Tuple[int, bytes]:
        """
        Valida y desencapsula un registro TLS 1.3, retornando (record_type, payload).
        """
        if len(raw_record) < TLS_RECORD_HEADER_SIZE:
            raise ValueError(f"Registro TLS truncado ({len(raw_record)} < {TLS_RECORD_HEADER_SIZE} bytes)")

        rtype, ver, length = struct.unpack(">BHH", raw_record[:TLS_RECORD_HEADER_SIZE])
        if ver != TLS_VERSION_LEGACY:
            raise ValueError(f"Versión de registro TLS inválida: 0x{ver:04x}")

        if len(raw_record) < TLS_RECORD_HEADER_SIZE + length:
            raise ValueError(f"Cuerpo de registro TLS incompleto ({len(raw_record)} < {TLS_RECORD_HEADER_SIZE + length})")

        payload = raw_record[TLS_RECORD_HEADER_SIZE:TLS_RECORD_HEADER_SIZE + length]
        self.stats["records_unwrapped"] += 1
        return rtype, payload

    def is_tls_record(self, data: bytes) -> bool:
        """Verifica de forma rápida O(1) si los bytes corresponden a una cabecera TLS válida."""
        if len(data) < TLS_RECORD_HEADER_SIZE:
            return False
        rtype, ver, length = struct.unpack(">BHH", data[:TLS_RECORD_HEADER_SIZE])
        return rtype in (TLSRecordType.APPLICATION_DATA, TLSRecordType.HANDSHAKE, TLSRecordType.ALERT) and ver == TLS_VERSION_LEGACY
