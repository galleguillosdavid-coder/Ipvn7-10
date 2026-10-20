"""
IPVN 7 Out-of-Band (OOB) Secure Pairing & Human SAS Verification
Implements Short Authentication Strings (6 digits + 4 visual emojis)
and Uniform Resource (UR) animated QR multipart chunking for air-gapped node bootstrapping.
Inspired by ipvn7 vX7 pkg/l4/oob_pairing.go.
"""

from __future__ import annotations
import base64
import hashlib
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass

# 32 distinct visual emojis for human zero-knowledge verification
SAS_EMOJI_CATALOG = [
    "🚀", "🛡️", "🔑", "⚡", "🌟", "🔥", "💎", "🪐",
    "🎯", "🧭", "⚓", "🛸", "🌈", "🌊", "🔮", "🍀",
    "🦁", "🦅", "🐬", "🦊", "👑", "🏆", "🎁", "🎨",
    "🌲", "🍄", "🍎", "🍉", "☕", "🎷", "🎸", "🚲",
]


@dataclass
class SASCode:
    digits: str        # 6-digit verification number (e.g. "482915")
    emojis: List[str]  # 4-emoji visual sequence
    auth_string: str   # Combined display string

    def to_dict(self) -> Dict[str, Any]:
        return {
            "digits": self.digits,
            "emojis": self.emojis,
            "auth_string": self.auth_string,
        }


def derive_sas(pub_a: bytes, pub_b: bytes) -> SASCode:
    """
    Derives Short Authentication String (SAS) from two public keys.
    Sorts keys canonically so both endpoints independently derive the identical SAS.
    """
    # Canonical lexicographical ordering
    if pub_a < pub_b:
        combined = pub_a + pub_b
    else:
        combined = pub_b + pub_a

    h = hashlib.sha256(combined).digest()

    # 1. 6-digit numeric code from first 4 bytes
    num = int.from_bytes(h[:4], "big") % 1_000_000
    digits = f"{num:06d}"

    # 2. 4 visual emojis from next 4 bytes
    emojis = [SAS_EMOJI_CATALOG[h[4 + i] % len(SAS_EMOJI_CATALOG)] for i in range(4)]
    auth_string = f"{digits} {' '.join(emojis)}"

    return SASCode(digits=digits, emojis=emojis, auth_string=auth_string)


def generate_ur_chunks(payload: bytes, max_chunk_size: int = 64) -> List[str]:
    """
    Splits arbitrary configuration payload into Uniform Resource (UR) frames
    suitable for animated QR code streaming or clipboard transfer.
    Format: ur:ipvn7-profile/<index>-<total>/<base64url>
    """
    if max_chunk_size <= 0:
        max_chunk_size = 64

    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    total_len = len(encoded)
    total_chunks = (total_len + max_chunk_size - 1) // max_chunk_size or 1

    chunks = []
    for i in range(total_chunks):
        start = i * max_chunk_size
        end = min(start + max_chunk_size, total_len)
        part = encoded[start:end]
        chunks.append(f"ur:ipvn7-profile/{i + 1}-{total_chunks}/{part}")

    return chunks


def reconstruct_ur_chunks(frames: List[str]) -> bytes:
    """Reconstructs original payload from collected UR frames."""
    if not frames:
        raise ValueError("No UR frames provided")

    parts: Dict[int, str] = {}
    expected_total = -1

    for f in frames:
        clean = f.strip()
        if not clean.startswith("ur:ipvn7-profile/"):
            continue
        rest = clean[len("ur:ipvn7-profile/"):]
        idx_part, sep, data_part = rest.partition("/")
        if not sep:
            continue
        idx_str, sep2, total_str = idx_part.partition("-")
        if not sep2:
            continue

        try:
            idx = int(idx_str)
            total = int(total_str)
        except ValueError:
            continue

        if expected_total == -1:
            expected_total = total
        elif expected_total != total:
            raise ValueError(f"Inconsistent total frames count: {expected_total} vs {total}")

        parts[idx] = data_part

    if expected_total == -1 or len(parts) < expected_total:
        raise ValueError(f"Incomplete frames: received {len(parts)} of {expected_total} required")

    # Assemble in order
    full_encoded = "".join(parts[i] for i in range(1, expected_total + 1))
    # Pad base64 if needed
    rem = len(full_encoded) % 4
    if rem:
        full_encoded += "=" * (4 - rem)

    return base64.urlsafe_b64decode(full_encoded.encode("ascii"))
