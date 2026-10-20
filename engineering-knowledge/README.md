# LAIA — Sistema de Memoria de Ingeniería y Prevención de Errores

Este directorio constituye la memoria técnica permanente, persistente y versionada del sistema LAIA para el protocolo IPVN 7 y proyectos derivados en el ecosistema Antigravity.

## Principios Fundacionales Inviolables

1. **REALIDAD > ACTIVIDAD:** La actividad de escribir código no equivale a resolver un problema.
2. **EVIDENCIA > AFIRMACIÓN:** Toda afirmación técnica debe estar vinculada a una prueba o telemetría reproducible.
3. **DEMOSTRACIÓN > INTENCIÓN:** La existencia de una biblioteca o algoritmo no demuestra la seguridad del sistema completo.
4. **SIMPLICIDAD > COMPLEJIDAD:** Favorecer soluciones directas, robustas y verificables.
5. **RECUPERABILIDAD > VELOCIDAD:** Cada ciclo produce un estado seguro y recuperable.
6. **TRAZABILIDAD > MEMORIA CONVERSACIONAL:** Lo que no está persistido en archivos versionados no existe.
7. **CAUSA RAÍZ > CORRECCIÓN SUPERFICIAL:** Un parche aislado sin prevención transversal es una falla diferida.
8. **PREVENCIÓN REUTILIZABLE > PARCHE AISLADO:** Si un error ocurrió en un componente, debe prevenirse en todos los componentes y proyectos.
9. **SEGURIDAD POR DEFECTO > CONFIGURACIÓN CONFIADA:** Cero credenciales estáticas públicas y denegación por defecto.
10. **COMPORTAMIENTO REAL > DIAGRAMA O DOCUMENTACIÓN:** El camino de ejecución real en bits y bytes manda sobre cualquier especificación.
11. **INCERTIDUMBRE EXPLÍCITA > CERTEZA INVENTADA:** Si algo no ha sido probado empíricamente, se declara como NO VERIFICADO o HIPÓTESIS.

## Estructura del Conocimiento de Ingeniería

- `CONSTITUTION.md`: Reglas constitucionales de obligado cumplimiento.
- `ENGINEERING_RULES.md`: Catálogo operativo de reglas ER-SEC-001 a ER-SEC-012.
- `SECURITY_INVARIANTS.md`: Invariantes matemáticos, criptográficos y de red.
- `ROOT_CAUSES.md`: Análisis formal de causas raíz (R1 a R10).
- `LESSONS_LEARNED.md`: Registro de incidentes históricos y lecciones aprendidas (LL-001+).
- `FAILURE_PATTERNS.md`: Catálogo de antipatrones y modos de falla de IA.
- `TOOLING_CATALOG.md`: Catálogo y evaluación empírica de herramientas.
- `PROTOCOLS_AND_LIBRARIES.md`: Especificación técnica de estándares criptográficos y de red.
- `PROJECT_INVENTORY.md`: Inventario de versiones y proyectos en unidades C: y D:.
- `TESTING_STANDARD.md`: Estándar para pruebas dinámicas y análisis adversarial.
- `EVIDENCE_STANDARD.md`: Criterios de clasificación y niveles de evidencia.
- `POLICIES/`: Políticas operativas detalladas por dominio técnico.
- `DECISIONS/`: Plantillas y registros de decisiones arquitectónicas.
- `FINDINGS/`: Catálogo histórico de hallazgos auditados con trazabilidad permanente.
- `REGRESSIONS/`: Casos de prueba de regresión y verificación negativa.
