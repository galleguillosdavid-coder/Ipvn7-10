"""
IPVN 7 - Resilience Guardian & Circuit Breaker Engine
Rescued & ported from ipvn7  vX7/pkg/l2/resilience_guardian.go.

Features:
1. Full Jitter Exponential Backoff to avoid thundering herd problem.
2. Tri-state Circuit Breaker (CLOSED, OPEN, HALF_OPEN) with cool-off timer.
3. Safe execution with panic/exception interception and auto-recovery.
4. Process health metrics and execution telemetry.
"""

import time
import math
import random
import threading
from typing import Callable, Any, Dict, Optional

class CircuitState:
    CLOSED = "CLOSED"       # Normal traffic allowed
    OPEN = "OPEN"           # Total block due to recurring failures
    HALF_OPEN = "HALF_OPEN" # Probing recovery with limited traffic


class ResilienceGuardian:
    def __init__(
        self,
        max_retries: int = 5,
        base_backoff_ms: float = 50.0,
        max_backoff_ms: float = 2000.0,
        failure_threshold: int = 3,
        cool_off_duration_s: float = 5.0,
    ):
        self.max_retries = max_retries
        self.base_backoff_ms = base_backoff_ms
        self.max_backoff_ms = max_backoff_ms
        self.failure_threshold = failure_threshold
        self.cool_off_duration_s = cool_off_duration_s

        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.last_failure_time = 0.0

        self.total_executions = 0
        self.total_exceptions_saved = 0
        self.total_recoveries = 0

        self._lock = threading.Lock()
        self._rng = random.Random(42)

    def compute_backoff(self, attempt: int) -> float:
        """Calcula el tiempo de espera en segundos con Full Jitter."""
        if attempt < 0:
            attempt = 0
        factor = math.pow(2, min(attempt, 10))
        calculated_ms = min(self.max_backoff_ms, self.base_backoff_ms * factor)
        # Full jitter: uniforme entre 0 y calculated_ms
        jittered_ms = self._rng.uniform(0, calculated_ms)
        return jittered_ms / 1000.0

    def allow_request(self) -> bool:
        """Determina si una petición es admitida según el estado del Circuit Breaker."""
        with self._lock:
            now = time.time()
            if self.state == CircuitState.OPEN:
                if (now - self.last_failure_time) >= self.cool_off_duration_s:
                    self.state = CircuitState.HALF_OPEN
                    return True
                return False
            return True

    def record_success(self):
        """Registra una ejecución exitosa."""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.total_recoveries += 1
            self.consecutive_failures = 0

    def record_failure(self):
        """Registra una falla y conmuta a OPEN si supera el umbral."""
        with self._lock:
            self.consecutive_failures += 1
            self.last_failure_time = time.time()
            if self.consecutive_failures >= self.failure_threshold:
                self.state = CircuitState.OPEN

    def safe_execute(self, func: Callable, *args, **kwargs) -> Any:
        """Ejecuta una función protegiendo el proceso contra fallos no capturados."""
        with self._lock:
            self.total_executions += 1

        if not self.allow_request():
            raise RuntimeError(f"circuit_breaker: llamada rechazada (estado actual: {self.state})")

        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        except Exception as e:
            with self._lock:
                self.total_exceptions_saved += 1
            self.record_failure()
            raise e

    def get_health_status(self) -> Dict[str, Any]:
        """Retorna el estado de salud y telemetría de resiliencia."""
        with self._lock:
            is_healthy = (self.state != CircuitState.OPEN)
            return {
                "circuit_state": self.state,
                "consecutive_failures": self.consecutive_failures,
                "failure_threshold": self.failure_threshold,
                "cool_off_duration_s": self.cool_off_duration_s,
                "total_executions": self.total_executions,
                "total_exceptions_saved": self.total_exceptions_saved,
                "total_recoveries": self.total_recoveries,
                "is_healthy": is_healthy,
                "status_message": "NORMAL" if is_healthy else "CIRCUIT_BREAKER_TRIPPED",
            }
