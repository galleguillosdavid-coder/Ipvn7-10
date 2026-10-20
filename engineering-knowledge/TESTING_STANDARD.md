# ESTÁNDAR DE PRUEBAS Y VALIDACIÓN ADVERSARIAL — LAIA

**Versión:** 1.0  
**Ámbito:** Suite de Pruebas de IPVN 7  

Este estándar define los criterios que deben cumplir las pruebas de software para ser consideradas válidas en el sistema LAIA.

---

## 1. Clasificación Obligatoria de Pruebas

Toda funcionalidad crítica debe contar con dos clases de pruebas en `tests/test_ipvn7.py`:

### 1.1. Pruebas Positivas (Funcionalidad Esperada)
- Verifican que la operación funcione según la especificación bajo condiciones nominales.
- Ejemplo: `test_pqc_hybrid_key_exchange` comprueba que dos nodos honestos deriven el mismo secreto compartido de 32 bytes.

### 1.2. Pruebas Negativas Adversariales (Resistencia al Ataque)
- Intentan deliberadamente romper las garantías de seguridad utilizando entradas hostiles, parámetros falsificados o secuencias anómalas.
- Ejemplos obligatorios:
  - **Suplantación de Identidad:** Verificar que firmas manipuladas provoquen `ValueError` inmediato (`test_audit_3_h09_pqc_authenticated_handshake_and_mitm_rejection`).
  - **Fuzzing de Entradas Binarias:** Probar buffers truncados, cotas gigantescas y números mágicos corruptos (`test_audit_3_h06_bitnet_deserialize_bounds_and_fuzz_resilience`).
  - **Destinos Prohibidos:** Intentar conectar a `127.0.0.1:22` o `169.254.169.254` y comprobar rechazo `0x02` (`test_audit_h02_socks5_blocks_internal_and_loopback_destinations`).
  - **Sobrecarga de Concurrencia:** Iniciar conexiones que superen el semáforo y verificar rechazo rápido sin degradación (`test_audit_3_h02_h05_socks5_concurrency_and_mode_accounting`).

---

## 2. Puertas de Calidad para Cierre de Tareas

1. **Compilación y Sintaxis:** Cero errores de sintaxis o `NameError` en tiempo de importación.
2. **Suite Unitaria Completa:** `pytest -q` debe arrojar 100% de pruebas aprobadas (108 de 108 en v7.10.0).
3. **Cero Silenciamiento:** No se permiten `skip` o `xfail` injustificados en pruebas de seguridad.
4. **Pruebas de Regresión Vinculadas:** Cada defecto corregido debe tener al menos una prueba unitaria específica que falle si el defecto se reintroduce.
