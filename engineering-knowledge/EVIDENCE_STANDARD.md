# ESTÁNDAR DE EVIDENCIA Y CLASIFICACIÓN — LAIA

**Versión:** 1.0  
**Ámbito:** Auditoría y Verificación en Antigravity  

Todo hallazgo, afirmación técnica o informe debe adherirse estrictamente a esta taxonomía de dos dimensiones: Estado de Evidencia y Severidad de Impacto.

---

## 1. Escala de Estado de Evidencia

1. **DEMOSTRADO:** Existe evidencia empírica y reproducible del comportamiento mediante prueba automatizada, captura de tráfico o ejecución de comando con salida verificable.
2. **PROBABLE:** El código fuente y el contexto técnico sustentan fuertemente la hipótesis de riesgo, pero falta una prueba automatizada decisiva o un entorno de laboratorio para reproducirlo al 100%.
3. **HIPÓTESIS:** Posibilidad lógica identificada durante el análisis estático o arquitectónico que requiere investigación adicional.
4. **DESCARTADO:** Se comprobó mediante pruebas empíricas que la hipótesis no aplica a la versión examinada, adjuntando la prueba que lo refuta.
5. **NO VERIFICADO:** No se pudo determinar el estado debido a limitaciones del entorno (falta de dependencias, permisos o dispositivos físicos).

---

## 2. Escala de Severidad de Impacto

- **P0 / Crítica:** Compromiso grave e inmediato de la confidencialidad, integridad o control del sistema sin prerrequisitos elevados.
- **P1 / Alta:** Riesgo de impacto significativo que afecta a componentes nucleares de autenticación, transporte o control.
- **P2 / Media:** Riesgo relevante pero con impacto delimitado o que requiere condiciones específicas para su explotación.
- **P3 / Baja:** Riesgo menor, debilidad teórica o desviación de mejores prácticas con bajo impacto operativo.
- **INFO:** Observación técnica, deuda técnica identificada, recomendación de mantenimiento o refactorización cosmética.

---

## 3. Principio de Cero Falsos Positivos
Ningún informe debe:
- Afirmar que una prueba fue ejecutada sin haberla corrido en el intérprete.
- Usar un `README` o documentación como prueba suficiente del comportamiento.
- Declarar una funcionalidad "100% segura" o "certificada".
- Eliminar un hallazgo histórico del registro sin preservar su trazabilidad.
