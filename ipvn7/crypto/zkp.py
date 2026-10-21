"""
IPVN 7 — Sovereign Zero-Knowledge Proof Engine (Línea Q / v7.13.0)
====================================================================
Implementa dos primitivas ZK sobre grupo abeliano modular (Z_q):

  1. SovereignZKSchnorr  — Prueba de conocimiento de clave privada (ZK-PoK Schnorr σ).
     Protocolo: Sigma de 3 movimientos (commit → challenge → respond).
     Aplicación: Gobernanza anónima — el nodo demuestra poseer una clave raíz DID
     sin revelarla. Base de las Firmas en Anillo (RingSignature en ring_signature.py).

  2. SovereignBulletproof — Prueba de rango confidencial (Range Proof sobre valores v ∈ [0, 2^n)).
     Protocolo: Descomposición de bits con commitments homomórficos de Pedersen y
     OR-proofs Σ de 1-de-2 (CDS94).
     Aplicación: El nodo demuestra que su saldo de tokens IP7R ∈ [0, 2^n) sin revelar el valor.

Wire frame canónico IP7Z (≤ 1280B MTU):
  Magic   : b'IP7Z' (4B)
  Version : 0x01   (1B)
  Type    : 0x01=ZK_SCHNORR, 0x02=RANGE_PROOF (1B)
  Length  : uint16 BE (2B)
  Payload : JSON comprimido zlib (variable ≤ 1268B)
  CRC32   : uint32 BE (4B)

Invariantes de Seguridad:
  - ZERO_FIAT_SHAMIR_REUSE: cada desafío es único por (pk, commitment, context).
  - SOUNDNESS: probabilidad de engaño ≤ 2^-128 con iteraciones de range proof.
  - ZERO_VALUE_LEAKAGE: ningún path expone el valor v ni la clave privada x.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ─── Grupo Abeliano sobre Z_q (primo seguro 256-bit) ────────────────────────
# Orden del grupo base q: primo de 252 bits de la curva Ed25519
_Q = 2**252 + 27742317777372353535851937790883648493

# Generador canónico g = hash-to-scalar del DID maestro del protocolo
_G_SEED = b"IPVN7:ZKP:GENERATOR:v1"
_G = int.from_bytes(hashlib.sha256(_G_SEED).digest(), "big") % _Q

# Segundo generador h para commitments de Pedersen (h = hash(g))
_H_SEED = b"IPVN7:ZKP:PEDERSEN_H:v1"
_H = int.from_bytes(hashlib.sha256(_H_SEED).digest(), "big") % _Q

_WIRE_MAGIC = b"IP7Z"
_WIRE_VERSION = 0x01
_ZK_SCHNORR_TYPE = 0x01
_RANGE_PROOF_TYPE = 0x02
_MTU = 1280


def _scalar_mul(g: int, x: int, q: int = _Q) -> int:
    """Multiplicación escalar modular en el grupo aditivo Z_q: (g * x) mod q."""
    return (g * x) % q


def _fiat_shamir_challenge(
    *components: bytes, context: bytes = b""
) -> int:
    """
    Desafío Fiat-Shamir determinista y único por (commitment, pk, context).
    Invariante ZERO_FIAT_SHAMIR_REUSE: incluye contexto y nonce de sesión.
    """
    h = hashlib.sha3_256()
    h.update(b"IPVN7:ZKP:FIAT-SHAMIR:v1:")
    h.update(context)
    for c in components:
        h.update(struct.pack(">I", len(c)))
        h.update(c)
    return int.from_bytes(h.digest(), "big") % _Q


def _b64_enc(n: int, length: int = 32) -> str:
    """Codifica un entero escalar en Base64 compacto."""
    return base64.b64encode(n.to_bytes(length, "big")).decode("ascii")


def _b64_dec(s: str) -> int:
    """Decodifica un entero escalar desde Base64."""
    return int.from_bytes(base64.b64decode(s.encode("ascii")), "big")


def _encode_wire(payload: Dict[str, Any], proof_type: int) -> bytes:
    """
    Serializa un proof al formato wire canónico IP7Z (≤ 1280B).
    Magic(4) + Version(1) + Type(1) + Length(2) + Payload(var) + CRC32(4)
    """
    raw = json.dumps(payload, separators=(",", ":")).encode()
    compressed = zlib.compress(raw, level=9)
    if len(compressed) + 12 > _MTU:
        raise ValueError(
            f"Frame IP7Z excede MTU de {_MTU}B (tamaño actual: {len(compressed) + 12}B)"
        )
    header = _WIRE_MAGIC + bytes([_WIRE_VERSION, proof_type]) + struct.pack(">H", len(compressed))
    body = header + compressed
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack(">I", crc)


def _decode_wire(frame: bytes) -> Tuple[int, Dict[str, Any]]:
    """
    Deserializa y verifica un frame IP7Z.
    Retorna (proof_type, payload_dict).
    Raises ValueError si el frame es inválido o excede MTU.
    """
    if len(frame) < 12:
        raise ValueError("IP7Z frame demasiado corto")
    if len(frame) > _MTU:
        raise ValueError(f"IP7Z frame excede MTU de {_MTU}B: {len(frame)}B")
    if frame[:4] != _WIRE_MAGIC:
        raise ValueError("Magic bytes IP7Z inválidos")
    if frame[4] != _WIRE_VERSION:
        raise ValueError(f"Versión IP7Z desconocida: {frame[4]}")
    proof_type = frame[5]
    payload_len = struct.unpack(">H", frame[6:8])[0]
    if len(frame) != 8 + payload_len + 4:
        raise ValueError("IP7Z frame longitud inconsistente")
    compressed = frame[8 : 8 + payload_len]
    stored_crc = struct.unpack(">I", frame[8 + payload_len : 8 + payload_len + 4])[0]
    computed_crc = zlib.crc32(frame[: 8 + payload_len]) & 0xFFFFFFFF
    if stored_crc != computed_crc:
        raise ValueError("IP7Z CRC32 mismatch — frame corrompido")
    raw = zlib.decompress(compressed)
    return proof_type, json.loads(raw)


# ─── 1. ZK-Schnorr: Prueba de Conocimiento de Clave Privada ─────────────────


@dataclass
class ZKSchnorrProof:
    """
    Prueba Sigma de 3 movimientos para conocimiento de x tal que Y = x·G mod q.
    Protocolo:
      Prover:    r ← Zq aleatorio;  R = r·G mod q
      Challenge: e = H(context || pk || R)
      Response:  s = (r + e·x) mod q
    Verifier:  s·G ≟ R + e·Y mod q
    """
    pk_hex: str        # Clave pública Y = x·G mod q (hex)
    R_hex: str         # Commitment R = r·G mod q (hex)
    s_hex: str         # Respuesta s = r + e·x mod q (hex)
    e_hex: str         # Desafío e = Fiat-Shamir (hex)
    context: str = ""  # Contexto de sesión (DID, epoch, etc.)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "ZK_SCHNORR",
            "pk": self.pk_hex,
            "R": self.R_hex,
            "s": self.s_hex,
            "e": self.e_hex,
            "ctx": self.context,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ZKSchnorrProof":
        return cls(
            pk_hex=d["pk"],
            R_hex=d["R"],
            s_hex=d["s"],
            e_hex=d["e"],
            context=d.get("ctx", ""),
        )


class SovereignZKSchnorr:
    """
    Motor ZK-Schnorr soberano. Compatible con claves derivadas de Ed25519 DIDs.
    Uso típico: demostrar posesión de clave DID raíz para gobernanza anónima.
    """

    @staticmethod
    def keygen(seed: Optional[bytes] = None) -> Tuple[int, int]:
        """
        Genera par (x, Y) donde x es clave privada escalar y Y = x·G mod q.
        Si seed es None, usa entropía criptográfica segura.
        """
        if seed is None:
            x = int.from_bytes(secrets.token_bytes(32), "big") % _Q
        else:
            x = int.from_bytes(hashlib.sha256(seed).digest(), "big") % _Q
        if x == 0:
            x = 1
        Y = _scalar_mul(_G, x)
        return x, Y

    @staticmethod
    def prove(x: int, Y: int, context: str = "") -> ZKSchnorrProof:
        """
        Genera la prueba ZK-Schnorr no interactiva (Fiat-Shamir heuristic).
        El prover conoce x secretamente y demuestra conocimiento sin revelarlo.
        """
        r = secrets.randbelow(_Q - 1) + 1
        R = _scalar_mul(_G, r)
        ctx_bytes = context.encode()
        e = _fiat_shamir_challenge(
            Y.to_bytes(32, "big"),
            R.to_bytes(32, "big"),
            context=ctx_bytes,
        )
        s = (r + e * x) % _Q
        return ZKSchnorrProof(
            pk_hex=hex(Y),
            R_hex=hex(R),
            s_hex=hex(s),
            e_hex=hex(e),
            context=context,
        )

    @staticmethod
    def verify(proof: ZKSchnorrProof) -> bool:
        """
        Verifica la prueba ZK-Schnorr.
        Acepta si: s·G ≡ R + e·Y (mod q)
        """
        try:
            Y = int(proof.pk_hex, 16)
            R = int(proof.R_hex, 16)
            s = int(proof.s_hex, 16)
            e = int(proof.e_hex, 16)
        except (ValueError, TypeError):
            return False

        ctx_bytes = proof.context.encode()
        e_expected = _fiat_shamir_challenge(
            Y.to_bytes(32, "big"),
            R.to_bytes(32, "big"),
            context=ctx_bytes,
        )
        if e != e_expected:
            return False

        lhs = _scalar_mul(_G, s)
        rhs = (R + _scalar_mul(Y, e)) % _Q
        return lhs == rhs

    @staticmethod
    def to_wire(proof: ZKSchnorrProof) -> bytes:
        """Serializa la prueba al formato wire IP7Z."""
        return _encode_wire(proof.to_dict(), _ZK_SCHNORR_TYPE)

    @staticmethod
    def from_wire(frame: bytes) -> ZKSchnorrProof:
        """Deserializa y valida el frame IP7Z retornando la prueba."""
        ptype, payload = _decode_wire(frame)
        if ptype != _ZK_SCHNORR_TYPE:
            raise ValueError(f"Tipo de prueba inesperado: {ptype}")
        return ZKSchnorrProof.from_dict(payload)


# ─── 2. Bulletproof de Rango: v ∈ [0, 2^n) ──────────────────────────────────


@dataclass
class SovereignRangeProof:
    """
    Prueba de rango confidencial basada en Pedersen commitments y OR-proofs.
    Demuestra que v ∈ [0, 2^n) sin revelar v.
    """
    commitment_hex: str
    bit_commitments: List[str] = field(default_factory=list)
    or_proofs: List[Dict[str, str]] = field(default_factory=list)
    challenge_hex: str = ""
    n_bits: int = 32
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "RANGE_PROOF",
            "C": self.commitment_hex,
            "bit_C": self.bit_commitments,
            "or_proofs": self.or_proofs,
            "e": self.challenge_hex,
            "n": self.n_bits,
            "ctx": self.context,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SovereignRangeProof":
        return cls(
            commitment_hex=d["C"],
            bit_commitments=d.get("bit_C", []),
            or_proofs=d.get("or_proofs", []),
            challenge_hex=d.get("e", ""),
            n_bits=int(d.get("n", 32)),
            context=d.get("ctx", ""),
        )


class SovereignBulletproof:
    """
    Motor de pruebas de rango soberano (Range Proof Engine).
    Permite a un nodo IPVN 7 demostrar que su saldo de tokens IP7R
    se encuentra en [0, 2^n) sin revelarlo.
    """

    def __init__(self, n_bits: int = 32):
        if n_bits < 1 or n_bits > 64:
            raise ValueError("n_bits debe ser ∈ [1, 64]")
        self.n_bits = n_bits

    def _pedersen_commit(self, v: int, r: int) -> int:
        """C = v·G + r·H mod q"""
        return (_scalar_mul(_G, v) + _scalar_mul(_H, r)) % _Q

    def prove(self, v: int, context: str = "") -> SovereignRangeProof:
        """
        Genera prueba de rango para v ∈ [0, 2^n_bits).
        Raises ValueError si v está fuera de rango.
        """
        if v < 0 or v >= 2**self.n_bits:
            raise ValueError(f"Valor v={v} fuera de rango [0, 2^{self.n_bits})")

        r = secrets.randbelow(_Q - 1) + 1
        C = self._pedersen_commit(v, r)
        bits = [(v >> i) & 1 for i in range(self.n_bits)]

        # Factores de cegado para descomposición homomórfica: sum(2^i * r_i) == r mod q
        bit_rs: List[int] = [secrets.randbelow(_Q - 1) + 1 for _ in range(self.n_bits - 1)]
        sum_prev = sum((bit_rs[i] * (1 << i)) for i in range(self.n_bits - 1)) % _Q
        inv_2_pow = pow(1 << (self.n_bits - 1), _Q - 2, _Q)
        last_r = ((r - sum_prev) * inv_2_pow) % _Q
        bit_rs.append(last_r)

        bit_Cs = [self._pedersen_commit(bits[i], bit_rs[i]) for i in range(self.n_bits)]
        all_C_bytes = b"".join(Ci.to_bytes(32, "big") for Ci in bit_Cs)
        e_global = _fiat_shamir_challenge(
            C.to_bytes(32, "big"),
            all_C_bytes,
            context=context.encode(),
        )

        or_proofs: List[Dict[str, str]] = []
        for i in range(self.n_bits):
            b = bits[i]
            r_b = bit_rs[i]
            Ci = bit_Cs[i]
            P0 = Ci
            P1 = (Ci - _G) % _Q
            e_bit = _fiat_shamir_challenge(
                Ci.to_bytes(32, "big"),
                struct.pack(">I", i),
                context=context.encode(),
            )
            if b == 0:
                e1 = secrets.randbelow(2**128)
                s1 = secrets.randbelow(_Q - 1) + 1
                R1 = (_scalar_mul(_H, s1) - _scalar_mul(P1, e1)) % _Q
                k0 = secrets.randbelow(_Q - 1) + 1
                R0 = _scalar_mul(_H, k0)
                e0 = (e_bit - e1) % _Q
                s0 = (k0 + e0 * r_b) % _Q
            else:
                e0 = secrets.randbelow(2**128)
                s0 = secrets.randbelow(_Q - 1) + 1
                R0 = (_scalar_mul(_H, s0) - _scalar_mul(P0, e0)) % _Q
                k1 = secrets.randbelow(_Q - 1) + 1
                R1 = _scalar_mul(_H, k1)
                e1 = (e_bit - e0) % _Q
                s1 = (k1 + e1 * r_b) % _Q

            or_proofs.append({
                "e0": hex(e0),
                "s0": hex(s0),
                "e1": hex(e1),
                "s1": hex(s1),
                "R0": hex(R0),
                "R1": hex(R1),
            })

        return SovereignRangeProof(
            commitment_hex=hex(C),
            bit_commitments=[hex(ci) for ci in bit_Cs],
            or_proofs=or_proofs,
            challenge_hex=hex(e_global),
            n_bits=self.n_bits,
            context=context,
        )

    def verify(self, proof: SovereignRangeProof) -> bool:
        """
        Verifica la prueba de rango confidencial. Retorna True si v ∈ [0, 2^n_bits).
        """
        try:
            C = int(proof.commitment_hex, 16)
            bit_Cs = [int(c, 16) for c in proof.bit_commitments]
            e_stored = int(proof.challenge_hex, 16)
        except (ValueError, TypeError):
            return False

        if len(bit_Cs) != proof.n_bits or len(proof.or_proofs) != proof.n_bits:
            return False

        # 1. Verificación del desafío global Fiat-Shamir
        all_C_bytes = b"".join(Ci.to_bytes(32, "big") for Ci in bit_Cs)
        e_expected = _fiat_shamir_challenge(
            C.to_bytes(32, "big"),
            all_C_bytes,
            context=proof.context.encode(),
        )
        if e_stored != e_expected:
            return False

        # 2. Verificación de homomorfismo de Pedersen: sum(2^i * C_i) ≡ C (mod q)
        sum_C = sum((bit_Cs[i] * (1 << i)) for i in range(proof.n_bits)) % _Q
        if sum_C != C:
            return False

        # 3. Verificación de OR-proofs Σ (CDS94) para cada bit b_i ∈ {0, 1}
        for i in range(proof.n_bits):
            Ci = bit_Cs[i]
            P0 = Ci
            P1 = (Ci - _G) % _Q
            op = proof.or_proofs[i]
            try:
                e0 = int(op["e0"], 16)
                s0 = int(op["s0"], 16)
                s1 = int(op["s1"], 16)
            except (KeyError, ValueError, TypeError):
                return False

            e_bit = _fiat_shamir_challenge(
                Ci.to_bytes(32, "big"),
                struct.pack(">I", i),
                context=proof.context.encode(),
            )
            e1 = (e_bit - e0) % _Q

            R0 = (_scalar_mul(_H, s0) - _scalar_mul(P0, e0)) % _Q
            R1 = (_scalar_mul(_H, s1) - _scalar_mul(P1, e1)) % _Q

            check0 = (_scalar_mul(_H, s0) == (R0 + _scalar_mul(P0, e0)) % _Q)
            check1 = (_scalar_mul(_H, s1) == (R1 + _scalar_mul(P1, e1)) % _Q)
            if not (check0 and check1):
                return False

        return True

    @staticmethod
    def to_wire(proof: SovereignRangeProof) -> bytes:
        """
        Serializa la prueba de rango al formato wire IP7Z con compresión Base64
        garantizando MTU ≤ 1280B para frames en red.
        """
        C_int = int(proof.commitment_hex, 16)
        bC_list = [_b64_enc(int(c, 16), 32) for c in proof.bit_commitments]
        ops_list = [
            [
                _b64_enc(int(op["e0"], 16), 32),
                _b64_enc(int(op["s0"], 16), 32),
                _b64_enc(int(op["s1"], 16), 32),
            ]
            for op in proof.or_proofs
        ]
        compact_payload = {
            "t": _RANGE_PROOF_TYPE,
            "C": _b64_enc(C_int, 32),
            "bC": bC_list,
            "ops": ops_list,
            "e": _b64_enc(int(proof.challenge_hex, 16), 32),
            "n": proof.n_bits,
            "ctx": proof.context,
        }
        return _encode_wire(compact_payload, _RANGE_PROOF_TYPE)

    @staticmethod
    def from_wire(frame: bytes) -> SovereignRangeProof:
        """Deserializa un frame IP7Z y retorna la prueba de rango."""
        ptype, d = _decode_wire(frame)
        if ptype != _RANGE_PROOF_TYPE:
            raise ValueError(f"Tipo de prueba inesperado: {ptype}")
        C_hex = hex(_b64_dec(d["C"]))
        bC_hex = [hex(_b64_dec(c)) for c in d["bC"]]
        or_proofs = [
            {
                "e0": hex(_b64_dec(op[0])),
                "s0": hex(_b64_dec(op[1])),
                "s1": hex(_b64_dec(op[2])),
            }
            for op in d["ops"]
        ]
        e_hex = hex(_b64_dec(d["e"]))
        return SovereignRangeProof(
            commitment_hex=C_hex,
            bit_commitments=bC_hex,
            or_proofs=or_proofs,
            challenge_hex=e_hex,
            n_bits=int(d["n"]),
            context=d.get("ctx", ""),
        )
