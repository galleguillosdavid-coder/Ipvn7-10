"""
IPVN 7 BitNet b1.58 Ternary Quantization Engine
Implements 1.58-bit ternary quantization (-1, 0, +1) and 8-bit activation scaling
for ultra-low-power Edge AI and IoT devices on the sovereign mesh.
Zero third-party dependencies; uses integer matrix arithmetic and packed byte buffers.
"""

from __future__ import annotations
import math
import struct
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass


MAGIC_BITNET = b"IP7B"  # IPVN 7 BitNet Container Magic (4 bytes)


@dataclass
class PackedTernaryWeights:
    """Stores packed ternary weights (4 weights per byte) and scale factor."""
    rows: int
    cols: int
    scale: float
    packed_data: bytes

    @property
    def total_weights(self) -> int:
        return self.rows * self.cols

    @property
    def compression_ratio(self) -> float:
        """Ratio of 32-bit float memory to packed 2-bit ternary memory."""
        original_bytes = self.total_weights * 4
        packed_bytes = len(self.packed_data) + 8  # +8 for scale float
        return round(original_bytes / max(1, packed_bytes), 2)


class BitNetQuantizer:
    """
    Quantizes dense floating-point weight tensors into BitNet b1.58 ternary format
    and performs integer-only matrix-vector multiplication.
    """

    @staticmethod
    def quantize_weights(weights: List[List[float]]) -> PackedTernaryWeights:
        """
        Quantizes a 2D float weight matrix W into ternary values {-1, 0, 1}:
        scale = mean(abs(W))
        W_ternary = clip(round(W / scale), -1, 1)
        """
        rows = len(weights)
        if rows == 0:
            return PackedTernaryWeights(0, 0, 1.0, b"")
        cols = len(weights[0])
        if cols == 0:
            return PackedTernaryWeights(rows, 0, 1.0, b"")

        # 1. Compute mean absolute scale gamma
        total_abs = sum(abs(v) for row in weights for v in row)
        scale = total_abs / (rows * cols) if (rows * cols) > 0 else 1.0
        if scale == 0.0:
            scale = 1e-6

        # 2. Quantize each element to -1, 0, or 1
        # Bit encoding per weight (2 bits):
        # 0 -> 00 (0)
        # +1 -> 01 (1)
        # -1 -> 11 (3)
        flat_ternary: List[int] = []
        for row in weights:
            for val in row:
                scaled = round(val / scale)
                t_val = max(-1, min(1, scaled))
                flat_ternary.append(t_val)

        # 3. Pack 4 ternary weights per byte
        packed_bytes = bytearray()
        for i in range(0, len(flat_ternary), 4):
            byte_val = 0
            for shift_idx, j in enumerate(range(i, min(i + 4, len(flat_ternary)))):
                w = flat_ternary[j]
                # Encode: 0->0, 1->1, -1->3
                code = 0 if w == 0 else (1 if w == 1 else 3)
                byte_val |= (code << (shift_idx * 2))
            packed_bytes.append(byte_val)

        return PackedTernaryWeights(
            rows=rows,
            cols=cols,
            scale=scale,
            packed_data=bytes(packed_bytes),
        )

    @staticmethod
    def unpack_weights(packed: PackedTernaryWeights) -> List[List[int]]:
        """Unpacks packed 2-bit representation back to ternary integer matrix."""
        matrix: List[List[int]] = []
        total = packed.rows * packed.cols
        flat: List[int] = []

        for b in packed.packed_data:
            for shift_idx in range(4):
                if len(flat) >= total:
                    break
                code = (b >> (shift_idx * 2)) & 0x03
                w = 0 if code == 0 else (1 if code == 1 else -1)
                flat.append(w)

        idx = 0
        for _ in range(packed.rows):
            matrix.append(flat[idx:idx + packed.cols])
            idx += packed.cols

        return matrix

    @staticmethod
    def quantize_activations(x: List[float]) -> Tuple[List[int], float]:
        """Quantizes activation vector x to 8-bit integers: x_int = round(x * 127 / max(abs(x)))."""
        if not x:
            return [], 1.0
        max_abs = max(abs(v) for v in x) or 1e-6
        scale = 127.0 / max_abs
        quantized = [max(-128, min(127, round(v * scale))) for v in x]
        return quantized, max_abs / 127.0

    @staticmethod
    def forward(
        x: List[float],
        packed_weights: PackedTernaryWeights,
        bias: Optional[List[float]] = None,
    ) -> List[float]:
        """
        Executes BitNet b1.58 linear layer:
        y = (W_ternary * x_quantized) * (scale_w * scale_x) + bias
        All inner products are integer additions and subtractions (zero multiply units).
        """
        if packed_weights.cols != len(x):
            raise ValueError(f"Shape mismatch: weights col {packed_weights.cols} != input len {len(x)}")

        # Quantize activations to int8
        x_int, scale_x = BitNetQuantizer.quantize_activations(x)
        w_ternary = BitNetQuantizer.unpack_weights(packed_weights)

        effective_scale = packed_weights.scale * scale_x
        y: List[float] = []

        for r_idx in range(packed_weights.rows):
            w_row = w_ternary[r_idx]
            # Accumulate integer product: w in {-1, 0, 1}
            acc = 0
            for w, x_val in zip(w_row, x_int):
                if w == 1:
                    acc += x_val
                elif w == -1:
                    acc -= x_val
                # w == 0 is skipped (sparse branch / zero op)

            val = acc * effective_scale
            if bias and r_idx < len(bias):
                val += bias[r_idx]
            y.append(round(val, 4))

        return y

    @staticmethod
    def serialize_model(packed: PackedTernaryWeights, model_name: str = "bitnet-tiny") -> bytes:
        """Serializes packed ternary model to canonical binary layout."""
        name_bytes = model_name.encode("utf-8")
        header = struct.pack(
            "!4sHHdf",
            MAGIC_BITNET,
            len(name_bytes),
            packed.rows,
            packed.cols,
            packed.scale,
        )
        return header + name_bytes + packed.packed_data

    @staticmethod
    def deserialize_model(data: bytes) -> Tuple[str, PackedTernaryWeights]:
        """Deserializes canonical binary buffer to model name and PackedTernaryWeights."""
        if len(data) < 20 or not data.startswith(MAGIC_BITNET):
            raise ValueError("Invalid BitNet container magic or truncated buffer")

        magic, name_len, rows, cols_float, scale = struct.unpack("!4sHHdf", data[:20])
        offset = 20
        name = data[offset:offset + name_len].decode("utf-8")
        offset += name_len
        packed_data = data[offset:]

        return name, PackedTernaryWeights(rows=rows, cols=int(cols_float), scale=scale, packed_data=packed_data)
