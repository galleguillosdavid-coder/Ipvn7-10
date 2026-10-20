"""
IPVN 7 1024-Bit Sliding Window Anti-Replay Filter (RFC 4303 Compatible)
Protege las sesiones de red en O(1) contra ataques de retransmisión y replay
mediante una ventana deslizante de 1024 bits estructurada en un arreglo de 16 enteros uint64.
Inspirado en ipvn7 vX7 pkg/l0/anti_replay.go.
"""

from __future__ import annotations
import threading
from typing import Tuple, Dict, Any

REPLAY_WINDOW_SIZE_1024 = 1024
UINT64_MASK = 0xFFFFFFFFFFFFFFFF


class AntiReplayFilter:
    """
    Filtro de ventana deslizante de 1024 bits en O(1).
    Rastrea el último número de secuencia recibido y mantiene un mapa de bits
    de 16 enteros de 64 bits para detección ultra-rápida de paquetes duplicados.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.last_seq: int = 0
        self.bitmap: list[int] = [0] * 16  # 16 * 64 = 1024 bits
        self.accepted: int = 0
        self.rejected: int = 0

    def _shift_left(self, diff: int) -> None:
        """Desplaza el mapa de bits de 1024 bits hacia la izquierda por diff posiciones."""
        words = diff // 64
        bits = diff % 64

        if words >= 16:
            self.bitmap = [0] * 16
            return

        if words > 0:
            for i in range(15, words - 1, -1):
                self.bitmap[i] = self.bitmap[i - words]
            for i in range(words):
                self.bitmap[i] = 0

        if bits > 0:
            carry_shift = 64 - bits
            for i in range(15, 0, -1):
                self.bitmap[i] = ((self.bitmap[i] << bits) | (self.bitmap[i - 1] >> carry_shift)) & UINT64_MASK
            self.bitmap[0] = (self.bitmap[0] << bits) & UINT64_MASK

    def validate_and_update(self, seq: int) -> bool:
        """
        Verifica si un número de secuencia seq es válido y no repetido dentro de la ventana de 1024 bits.
        Retorna True si el paquete es legítimo y se actualiza la ventana, o False si es un replay/duplicado.
        """
        with self._lock:
            if seq > self.last_seq:
                diff = seq - self.last_seq
                if diff >= REPLAY_WINDOW_SIZE_1024:
                    self.bitmap = [0] * 16
                    self.bitmap[0] = 1
                else:
                    self._shift_left(diff)
                    self.bitmap[0] |= 1
                self.last_seq = seq
                self.accepted += 1
                return True

            diff = self.last_seq - seq
            if diff >= REPLAY_WINDOW_SIZE_1024:
                self.rejected += 1
                return False  # Paquete demasiado antiguo (fuera de la ventana)

            word_idx = diff // 64
            bit_idx = diff % 64
            mask = 1 << bit_idx

            if (self.bitmap[word_idx] & mask) != 0:
                self.rejected += 1
                return False  # Replay / duplicado detectado

            self.bitmap[word_idx] |= mask
            self.accepted += 1
            return True

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "last_seq": self.last_seq,
                "accepted_packets": self.accepted,
                "rejected_replays": self.rejected,
                "window_size_bits": REPLAY_WINDOW_SIZE_1024,
            }
