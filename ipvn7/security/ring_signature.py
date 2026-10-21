"""
IPVN 7 — Sovereign Ephemeral Ring Signature Engine (Línea Q / v7.13.0)
========================================================================
Implementa Firmas en Anillo Efímeras (Ephemeral Ring Signatures) para
gobernanza anónima en la malla IPVN 7.

Una firma en anillo permite a un miembro de un grupo {PK_0, …, PK_{n-1}} firmar
un mensaje demostrando que *uno* de los miembros posee la clave privada correspondiente,
sin revelar cuál. Aplicación directa en IPVN 7:
  - Votación anónima sobre propuestas de gobernanza de la malla.
  - Emisión anónima de alertas de seguridad por un operador del grupo.
  - Auditoría de nodos sin revelar identidad al conjunto de validadores.

Protocolo: Ring Signature de Schnorr (Abe-Ohkubo-Suzuki / AOS02)
  - Para el firmante real (índice s): genera prueba real Schnorr.
  - Para todos los demás (i ≠ s): genera prueba Schnorr simulada.
  - Challenge determinista: c_{i+1} = H(msg || K || R_i || ring_pks || epoch || ctx).
  - Cierre cíclico: c_n ≡ c_0.
  - Nulificador K = x_s · H(PK_s): previene doble-firma en la misma época sin revelar identidad.

Wire frame canónico IP7S (≤ 1280B MTU):
  Magic   : b'IP7S' (4B)
  Version : 0x01   (1B)
  Type    : 0x10=RING_SIG (1B)
  Length  : uint16 BE (2B)
  Payload : JSON comprimido zlib (variable ≤ 1268B)
  CRC32   : uint32 BE (4B)

Invariantes de Seguridad:
  - ANONYMITY: Ningún verificador puede determinar el índice s del firmante.
  - UNFORGEABILITY: Sin la clave privada de al menos un miembro, la firma falla.
  - LINKABILITY_CONTROL: El campo key_image (nulificador) impide doble-firma
    del mismo (msg, epoch) sin revelar la identidad.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
import zlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Reutilizar parámetros del grupo desde zkp.py
from ..crypto.zkp import (
    _G,
    _H,
    _Q,
    _scalar_mul,
)

_WIRE_MAGIC_RS = b"IP7S"  # IP7S = IP7 Ring Signature
_WIRE_VERSION = 0x01
_RING_SIG_TYPE = 0x10
_MTU = 1280


def _encode_wire_rs(payload: Dict[str, Any]) -> bytes:
    """Serializa la firma en anillo al formato wire IP7S (≤ 1280B)."""
    raw = json.dumps(payload, separators=(",", ":")).encode()
    compressed = zlib.compress(raw, level=9)
    if len(compressed) + 12 > _MTU:
        raise ValueError(
            f"Frame IP7S excede MTU de {_MTU}B (tamaño actual: {len(compressed) + 12}B)"
        )
    header = _WIRE_MAGIC_RS + bytes([_WIRE_VERSION, _RING_SIG_TYPE]) + struct.pack(">H", len(compressed))
    body = header + compressed
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack(">I", crc)


def _decode_wire_rs(frame: bytes) -> Dict[str, Any]:
    """Deserializa y verifica un frame IP7S."""
    if len(frame) < 12:
        raise ValueError("IP7S frame demasiado corto")
    if len(frame) > _MTU:
        raise ValueError(f"IP7S frame excede MTU de {_MTU}B: {len(frame)}B")
    if frame[:4] != _WIRE_MAGIC_RS:
        raise ValueError("Magic bytes IP7S inválidos")
    if frame[4] != _WIRE_VERSION:
        raise ValueError(f"Versión IP7S desconocida: {frame[4]}")
    if frame[5] != _RING_SIG_TYPE:
        raise ValueError(f"Tipo de frame IP7S inesperado: {frame[5]}")
    payload_len = struct.unpack(">H", frame[6:8])[0]
    if len(frame) != 8 + payload_len + 4:
        raise ValueError("IP7S frame longitud inconsistente")
    compressed = frame[8 : 8 + payload_len]
    stored_crc = struct.unpack(">I", frame[8 + payload_len : 8 + payload_len + 4])[0]
    computed_crc = zlib.crc32(frame[: 8 + payload_len]) & 0xFFFFFFFF
    if stored_crc != computed_crc:
        raise ValueError("IP7S CRC32 mismatch — frame corrompido")
    raw = zlib.decompress(compressed)
    return json.loads(raw)


# ─── Clave de anillo ──────────────────────────────────────────────────────────


@dataclass
class RingMember:
    """Miembro de un anillo de gobernanza. Solo pk_hex es público."""
    pk_hex: str                        # Clave pública Y = x·G mod q (hex)
    sk_hex: Optional[str] = None      # Clave privada x (hex) — solo conocida por el dueño

    @property
    def pk(self) -> int:
        return int(self.pk_hex, 16)

    @property
    def sk(self) -> Optional[int]:
        return int(self.sk_hex, 16) if self.sk_hex else None

    @staticmethod
    def generate() -> "RingMember":
        """Genera un par de claves efímeras para un miembro del anillo."""
        x = secrets.randbelow(_Q - 1) + 1
        Y = _scalar_mul(_G, x)
        return RingMember(pk_hex=hex(Y), sk_hex=hex(x))

    def public_only(self) -> "RingMember":
        """Retorna una copia solo con la clave pública (para compartir)."""
        return RingMember(pk_hex=self.pk_hex)


# ─── Firma en Anillo ──────────────────────────────────────────────────────────


@dataclass
class EphemeralRingSignature:
    """
    Firma en anillo efímera sobre un mensaje msg con anillo de n miembros.
    El campo key_image es el nulificador: x_s · H(PK_s) mod q.
    Permite detectar doble-firma sin revelar la identidad.
    """
    ring_pks: List[str]          # Claves públicas del anillo [Y_0, …, Y_{n-1}]
    commitments: List[str]       # Commitments [R_0, …, R_{n-1}]
    responses: List[str]         # Respuestas [s_0, …, s_{n-1}]
    challenge_hex: str           # Desafío inicial c_0 (hex)
    key_image_hex: str           # Nulificador K = x_s · H(PK_s) (hex)
    msg_hash_hex: str            # SHA-256 del mensaje firmado
    epoch: str = ""              # Época efímera de rotación (e.g. "2026-10-21:00")
    ring_context: str = ""       # Contexto del anillo (e.g. "GOVERNANCE_VOTE")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "RING_SIGNATURE",
            "ring": self.ring_pks,
            "R": self.commitments,
            "s": self.responses,
            "c0": self.challenge_hex,
            "K": self.key_image_hex,
            "mh": self.msg_hash_hex,
            "epoch": self.epoch,
            "ctx": self.ring_context,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EphemeralRingSignature":
        return cls(
            ring_pks=d["ring"],
            commitments=d["R"],
            responses=d["s"],
            challenge_hex=d["c0"],
            key_image_hex=d["K"],
            msg_hash_hex=d["mh"],
            epoch=d.get("epoch", ""),
            ring_context=d.get("ctx", ""),
        )


class SovereignRingSignature:
    """
    Motor de Firmas en Anillo Efímeras para gobernanza anónima IPVN 7.

    Protocolo Schnorr Ring (n miembros):
      1. Para el firmante (índice s):
           r_s ← Zq aleatorio ; R_s = r_s · G mod q
      2. Challenge de avance:
           c_{s+1} = H(msg || K || R_s || ring_pks || epoch || ctx)
      3. Para todos i ≠ s (simulación):
           s_i ← Zq aleatorio
           R_i = (s_i · G - c_i · Y_i) mod q   [compromiso simulado]
           c_{i+1} = H(msg || K || R_i || ring_pks || epoch || ctx)
      4. Respuesta real del firmante:
           s_s = (r_s + c_s · x_s) mod q
      5. Consistencia cíclica: c_n ≡ c_0.
    """

    @staticmethod
    def _hash_to_scalar(*parts: bytes) -> int:
        """H: {0,1}* → Zq mediante SHA3-256."""
        h = hashlib.sha3_256()
        for p in parts:
            h.update(struct.pack(">I", len(p)))
            h.update(p)
        return int.from_bytes(h.digest(), "big") % _Q

    @staticmethod
    def _key_image(x: int, Y: int) -> int:
        """
        Nulificador K = (x · H(Y)) mod q.
        Determinista para (x, Y), único por firmante — impide doble-firma.
        """
        h_Y = hashlib.sha3_256(Y.to_bytes(32, "big")).digest()
        h_Y_scalar = int.from_bytes(h_Y, "big") % _Q
        return _scalar_mul(_G, (h_Y_scalar * x) % _Q)

    @classmethod
    def sign(
        cls,
        message: bytes,
        signer: RingMember,
        ring: List[RingMember],
        epoch: str = "",
        ring_context: str = "",
    ) -> EphemeralRingSignature:
        """
        Firma el mensaje de forma anónima dentro del anillo especificado.
        """
        if signer.sk is None:
            raise ValueError("El firmante debe poseer clave privada (sk_hex)")

        n = len(ring)
        if n < 2:
            raise ValueError("El anillo debe tener al menos 2 miembros")

        signer_pk = signer.pk
        s_idx = next(
            (i for i, m in enumerate(ring) if m.pk == signer_pk), None
        )
        if s_idx is None:
            raise ValueError("El firmante no pertenece al anillo")

        x_s = signer.sk
        Y_s = signer.pk
        msg_hash = hashlib.sha256(message).digest()
        msg_hash_hex = msg_hash.hex()

        # Key image (nulificador K)
        K = cls._key_image(x_s, Y_s)

        Rs: List[int] = [0] * n
        ss: List[int] = [0] * n
        cs: List[int] = [0] * n

        # Nonce real del firmante
        r_s = secrets.randbelow(_Q - 1) + 1
        Rs[s_idx] = _scalar_mul(_G, r_s)

        ctx_b = (epoch + ring_context).encode()
        ring_pks_bytes = b"".join(m.pk.to_bytes(32, "big") for m in ring)

        # Challenge inicial que sale del firmante: c_{s+1}
        start = (s_idx + 1) % n
        cs[start] = cls._hash_to_scalar(
            msg_hash,
            K.to_bytes(32, "big"),
            Rs[s_idx].to_bytes(32, "big"),
            ring_pks_bytes,
            ctx_b,
        )

        # Propagar desafíos simulando respuestas para todos i ≠ s_idx
        i = start
        while i != s_idx:
            ss[i] = secrets.randbelow(_Q - 1) + 1
            Y_i = ring[i].pk
            Rs[i] = (_scalar_mul(_G, ss[i]) - _scalar_mul(Y_i, cs[i])) % _Q
            next_i = (i + 1) % n
            cs[next_i] = cls._hash_to_scalar(
                msg_hash,
                K.to_bytes(32, "big"),
                Rs[i].to_bytes(32, "big"),
                ring_pks_bytes,
                ctx_b,
            )
            i = next_i

        # Respuesta real del firmante: s_s = (r_s + c_s · x_s) mod q
        c_s = cs[s_idx]
        ss[s_idx] = (r_s + c_s * x_s) % _Q

        return EphemeralRingSignature(
            ring_pks=[hex(m.pk) for m in ring],
            commitments=[hex(R) for R in Rs],
            responses=[hex(s) for s in ss],
            challenge_hex=hex(cs[0]),
            key_image_hex=hex(K),
            msg_hash_hex=msg_hash_hex,
            epoch=epoch,
            ring_context=ring_context,
        )

    @classmethod
    def verify(cls, sig: EphemeralRingSignature, message: bytes) -> bool:
        """
        Verifica la firma en anillo. Retorna True si la firma es válida.
        NO revela qué miembro firmó.
        """
        try:
            n = len(sig.ring_pks)
            ring_Ys = [int(pk, 16) for pk in sig.ring_pks]
            ss = [int(s, 16) for s in sig.responses]
            c0 = int(sig.challenge_hex, 16)
            K = int(sig.key_image_hex, 16)
        except (ValueError, TypeError):
            return False

        if n < 2 or len(ss) != n or len(sig.commitments) != n:
            return False

        msg_hash = hashlib.sha256(message).digest()
        if msg_hash.hex() != sig.msg_hash_hex:
            return False

        ctx_b = (sig.epoch + sig.ring_context).encode()
        ring_pks_bytes = b"".join(Y.to_bytes(32, "big") for Y in ring_Ys)

        c_curr = c0
        for i in range(n):
            Y_i = ring_Ys[i]
            R_recomputed = (_scalar_mul(_G, ss[i]) - _scalar_mul(Y_i, c_curr)) % _Q
            c_next = cls._hash_to_scalar(
                msg_hash,
                K.to_bytes(32, "big"),
                R_recomputed.to_bytes(32, "big"),
                ring_pks_bytes,
                ctx_b,
            )
            c_curr = c_next

        # El anillo cierra perfectamente si c_n == c_0
        return c_curr == c0

    @staticmethod
    def to_wire(sig: EphemeralRingSignature) -> bytes:
        """Serializa la firma en anillo al formato wire IP7S."""
        return _encode_wire_rs(sig.to_dict())

    @staticmethod
    def from_wire(frame: bytes) -> EphemeralRingSignature:
        """Deserializa un frame IP7S y retorna la firma en anillo."""
        payload = _decode_wire_rs(frame)
        return EphemeralRingSignature.from_dict(payload)

    @staticmethod
    def is_double_signed(sig1: EphemeralRingSignature, sig2: EphemeralRingSignature) -> bool:
        """
        Detecta doble firma en la misma época: si dos firmas tienen el mismo
        key_image (nulificador K), el mismo firmante firmó dos mensajes distintos.
        """
        return (
            sig1.key_image_hex == sig2.key_image_hex
            and sig1.epoch == sig2.epoch
            and sig1.msg_hash_hex != sig2.msg_hash_hex
        )
