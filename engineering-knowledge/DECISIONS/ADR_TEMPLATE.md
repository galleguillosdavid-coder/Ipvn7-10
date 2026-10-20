# PLANTILLA DE DECISIÓN ARQUITECTÓNICA (ADR TEMPLATE) — LAIA

```markdown
# ADR-[NUM]: [Título de la Decisión Arquitectónica]

**Estado:** [Propuesto | Aprobado | Superado | Rechazado]  
**Fecha:** [YYYY-MM-DD]  
**Versión del Protocolo:** [ej. IPVN 7 v7.10.0]  
**Contexto Técnico:** [Problema técnico o auditoría que motiva la decisión]  
**Impacto:** [Crítico | Alto | Medio | Bajo]  

---

## 1. Contexto y Planteamiento del Problema
[Descripción del escenario arquitectónico, las restricciones del sistema y las opciones evaluadas.]

## 2. Invariantes de Seguridad Relevantes
- [Invariante N de SECURITY_INVARIANTS.md]

## 3. Decisión Adoptada
[Descripción clara y precisa de la solución elegida, indicando las modificaciones a realizar.]

## 4. Razones Técnicas y Justificación
[Por qué esta solución resuelve la causa raíz de fondo y no es un parche cosmético.]

## 5. Consecuencias
### Positivas
- [Mejoras de seguridad, rendimiento o simplicidad]

### Negativas / Compromisos
- [Trade-offs aceptados, posibles incompatibilidades o límites conocidos]

## 6. Verificación Empírica y Pruebas
- **Pruebas Automatizadas:** [`test_name`]
- **Evidencia Obtenida:** [Resultado de pytest o benchmark]
```
