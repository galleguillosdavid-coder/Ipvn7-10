# PLANTILLA DE REGISTRO DE HALLAZGOS (FINDING TEMPLATE) — LAIA

```markdown
# [ID_HALLAZGO] — [Título Descriptivo del Hallazgo]

- **Identificador Estable:** [ej. H-01-AUDIT-3]
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** [ej. v7.9.0]
- **Commit:** [Hash SHA-1]
- **Fecha:** [YYYY-MM-DD]
- **Estado de Evidencia:** [DEMOSTRADO | PROBABLE | HIPÓTESIS | DESCARTADO | NO VERIFICADO]
- **Severidad:** [P0 / Crítica | P1 / Alta | P2 / Media | P3 / Baja | INFO]
- **Archivo(s) y Líneas Afectadas:** [`path/to/file.py:L10-L25`]
- **Componente Afectado:** [Control Plane | Data Plane | Crypto | Gateway | MCP]

---

## 1. Descripción del Comportamiento Observado
[Explicación clara y técnica del comportamiento detectado.]

## 2. Evidencia Original
[Código relevante, traza de red, comando ejecutado o salida que demuestra el problema.]

## 3. Causa Raíz (Taxonomía LAIA)
- **Causa Raíz:** [R1 a R10]
- **Mecanismo:** [Cómo se produjo el fallo y por qué no fue detectado antes.]

## 4. Estado Actual y Corrección Aplicada
- **Estado:** [CORREGIDO | MITIGADO | PENDIENTE | DESCARTADO]
- **Cambio Realizado:** [Descripción sucinta del código modificado.]
- **Commit de Corrección:** [Hash SHA-1]

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** [ER-SEC-XXX]
- **Otros Proyectos Afectados:** [Rutas o versiones revisadas.]

## 6. Prueba de Regresión
- **Nombre de la Prueba:** [`test_xxx`]
- **Ubicación:** [`tests/test_ipvn7.py`]
- **Comportamiento Probado:** [Prueba negativa que falla si el error se reintroduce.]

## 7. Riesgo Residual
[Riesgo remanente o consideraciones operativas.]
```
