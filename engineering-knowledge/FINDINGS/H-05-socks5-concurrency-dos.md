# H-05-AUDIT-3 — Riesgo de Denegación de Servicio por Hilos No Acotados en SOCKS5

- **Identificador Estable:** `H-05-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P2 / Media`
- **Archivo(s) y Líneas Afectadas:** `ipvn7/gateway/socks5.py:L110-L135`
- **Componente Afectado:** L4 Proxy SOCKS5 Gateway

---

## 1. Descripción del Comportamiento Observado
En el bucle principal de aceptación de conexiones de `IPVN7SOCKS5Gateway`, cada conexión entrante disparaba un nuevo hilo con `threading.Thread(target=self._handle_client, args=(client_sock,)).start()` sin un límite superior o semáforo de admisión. Una ráfaga masiva de conexiones TCP en el puerto 10807 podía agotar los descriptores de archivos del sistema operativo o la memoria para pilas de hilos (thread stack starvation DoS).

## 2. Evidencia Original
```python
while self.running:
    client_sock, addr = server_sock.accept()
    t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
    t.start()
```

## 3. Causa Raíz
- **Causa Raíz:** R1 (Diseño sin invariantes verificables de recursos) y R7 (Cierre prematuro de componentes de red).
- **Mecanismo:** Omisión de un mecanismo de contrapresión (backpressure) o semáforo de admisión acotado.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Se incorporó un `threading.BoundedSemaphore(64)` en el gateway SOCKS5. Si se alcanza el límite de 64 conexiones concurrentes, nuevas conexiones se bloquean o son rechazadas limpiamente hasta que se libere un hilo activo, garantizando la estabilidad operativa del nodo.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-008` (Límites estrictos de concurrencia en listeners).
- **Invariante:** `INV-7` (Tolerancia DoS y Delimitación Estricta de Recursos).

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_socks5_bounded_concurrency_and_dos_mitigation`.

## 7. Riesgo Residual
Controlado. 64 streams concurrentes por gateway es un límite apropiado para uso soberano local; parametrizable mediante configuración si se requiere mayor densidad.
