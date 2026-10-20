"""
IPVN 7 Spectral Fourier Analysis Engine (DFT / Jitter Resonance Detection)
Descompone las fluctuaciones de latencia y jitter de paquetes en armónicos ortogonales
mediante la Transformada Discreta de Fourier (DFT), calculando Densidad Espectral de Potencia (PSD),
Entropía Espectral de Shannon y detección matemática de micro-ráfagas periódicas o bufferbloat resonante.
Inspirado en ipvn7 vX7 pkg/l2/fourier_spectral.go.
"""

from __future__ import annotations
import math
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class SpectralAnalysis:
    frequencies: List[float]             # Frecuencias evaluadas (Hz)
    power_spectral_density: List[float]  # Densidad espectral de potencia |X_k|^2
    dominant_frequency: float            # Frecuencia armónica de mayor energía
    spectral_entropy: float              # Entropía espectral normalizada [0.0, 1.0]
    is_periodic_anomaly: bool            # True si hay resonancia de jitter / micro-ráfagas
    peak_to_average_ratio: float         # Ratio pico/media espectral (PAPR)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frequencies": [round(f, 3) for f in self.frequencies],
            "power_spectral_density": [round(p, 4) for p in self.power_spectral_density],
            "dominant_frequency_hz": round(self.dominant_frequency, 3),
            "spectral_entropy": round(self.spectral_entropy, 4),
            "is_periodic_anomaly": self.is_periodic_anomaly,
            "peak_to_average_ratio": round(self.peak_to_average_ratio, 2),
        }


def compute_fourier_spectrum(signal: List[float], sampling_rate_hz: float = 100.0) -> SpectralAnalysis:
    """
    Aplica la Transformada Discreta de Fourier (DFT) sobre una serie temporal de latencias/jitter:
        X_k = sum_{t=0}^{N-1} (x_t - mean) * e^{-i * 2*pi*k*t / N}
    """
    n = len(signal)
    if n == 0:
        return SpectralAnalysis([], [], 0.0, 0.0, False, 0.0)

    if sampling_rate_hz <= 0:
        sampling_rate_hz = 1.0

    # 1. Centrado de señal (eliminar componente DC para aislar fluctuaciones AC / jitter)
    mean = sum(signal) / n

    # Teorema de Nyquist-Shannon: N/2 bins espectrales
    half = max(1, n // 2)

    freqs: List[float] = [0.0] * half
    psd: List[float] = [0.0] * half

    total_power = 0.0
    max_power = 0.0
    dominant_idx = 0

    for k in range(half):
        real_part = 0.0
        imag_part = 0.0
        two_pi_k = 2.0 * math.pi * float(k) / float(n)

        for t in range(n):
            centered = signal[t] - mean
            angle = two_pi_k * float(t)
            real_part += centered * math.cos(angle)
            imag_part -= centered * math.sin(angle)

        power = (real_part * real_part + imag_part * imag_part) / float(n)
        psd[k] = power
        freqs[k] = float(k) * sampling_rate_hz / float(n)

        total_power += power
        if k > 0 and power > max_power:
            max_power = power
            dominant_idx = k

    # 2. Entropía espectral de Shannon normalizada: H = -sum(p_k * log2(p_k)) / log2(half)
    entropy = 0.0
    if total_power > 1e-12:
        for p in psd:
            if p > 1e-12:
                prob = p / total_power
                entropy -= prob * math.log2(prob)
        if half > 1:
            entropy /= math.log2(float(half))

    # 3. Ratio Pico a Promedio (PAPR) sobre armónicos AC
    papr = 0.0
    ac_bins = max(1, half - 1)
    avg_power = (total_power - psd[0]) / ac_bins
    if avg_power > 1e-12:
        papr = max_power / avg_power

    # Criterio robusto de detección de resonancia periódica / micro-ráfaga:
    # Pico armónico concentrado (PAPR > 4.5), baja entropía espectral (< 0.85) y k > 0
    is_periodic = (papr > 4.5) and (entropy < 0.85) and (dominant_idx > 0)

    return SpectralAnalysis(
        frequencies=freqs,
        power_spectral_density=psd,
        dominant_frequency=freqs[dominant_idx],
        spectral_entropy=entropy,
        is_periodic_anomaly=is_periodic,
        peak_to_average_ratio=papr,
    )
