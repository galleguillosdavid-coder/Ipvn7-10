# H-06-AUDIT-3 — Deserialización de Contenedores Ternarios BitNet sin Validación de Cotas

- **Identificador Estable:** `H-06-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P2 / Media`
- **Archivo(s) y Líneas Afectadas:** `ipvn7/crypto/bitnet.py:L140-L195`
- **Componente Afectado:** L1 Edge AI BitNet b1.58 Container Format (`IP7B`)

---

## 1. Descripción del Comportamiento Observado
En `BitNetQuantizer.deserialize_model()`, el parser binario leía los enteros de dimensiones de capa (rows, cols) directamente de la cabecera del contenedor `IP7B` y calculaba el tamaño esperado del buffer de pesos empaquetados. Tramas malformadas enviadas por pares maliciosos (fuzzing) con dimensiones desproporcionadas (e.g. $10^9 \times 10^9$) o con longitudes inconsistentes respecto al buffer restante causaban excepciones no controladas (`struct.error`, `IndexError` o intentos de reserva de memoria desmedidos).

## 2. Evidencia Original
```python
rows, cols = struct.unpack("!II", data[offset:offset+8])
expected_packed_bytes = (rows * cols + 3) // 4
layer_weights = data[offset+8:offset+8+expected_packed_bytes] # Sin validación de cota superior ni longitud de buffer
```

## 3. Causa Raíz
- **Causa Raíz:** R4 (Validación de entrada sin garantía de uso seguro) y R6 (Pruebas unitarias que verificaban únicamente el caso feliz sin casos límite).
- **Mecanismo:** Deserialización directa sin validar límites de cordura dimensional ni consistencia de tamaño de trama binaria.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Se agregaron cotas estrictas de validación:
  1. Número máximo de capas permitido: $\le 64$.
  2. Dimensiones máximas por capa: $1 \le \text{rows}, \text{cols} \le 16384$.
  3. Verificación exacta de que el buffer restante contiene exactamente la cantidad de bytes requerida antes de extraerlos.
  4. Lanzamiento de `ValueError` determinista con mensaje explícito ante cualquier malformación.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-005` (Blindaje de parsers binarios y serializadores).
- **Invariante:** `INV-4` (Integridad de Protocolos Wire).

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_bitnet_deserialize_bounds_validation_and_fuzz_defense`.

## 7. Riesgo Residual
Nulo. El parser rechaza de forma segura y controlada cualquier entrada corrupta o maliciosa.
