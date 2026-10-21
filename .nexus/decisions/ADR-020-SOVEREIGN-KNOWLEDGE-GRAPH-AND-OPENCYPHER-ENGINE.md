# ADR-020: Sovereign In-Memory Knowledge Graph Engine & openCypher Pattern Matcher (Línea W)

## Estado
Aceptado e Implementado (v7.18.0)

## Fecha
2026-10-21

## Contexto y Motivación
Desde las versiones embrionarias de IPVN 7 (`0.7/src/pkg/interfaces/graph.go`, `ipvn7  vX7/pkg/l3/kuzu_graph.go` y la directiva `MAGNA SKILL 7.0: Ecosistema AFE-Kùzu`), se estableció la necesidad de contar con una estructura ontológica unificada para modelar el sistema completo en tiempo de ejecución:
1. **Gobernanza Axiomática Formal**: Los Principios Axiomáticos inmutables (L0: Zero-PII, Core Freeze, Fast Path, Small World, Post-Quantum Sovereignty) deben gobernar a todos los Subcistemas y Módulos de Código sin excepción.
2. **Evaluación de Consultas openCypher**: Los ingenieros, agentes de IA autónomos y operadores deben poder interrogar la topología mediante sentencias estándar de consulta de grafos (`MATCH ... WHERE ... RETURN ... LIMIT`).
3. **Auditoría de Invariantes y Huérfanos**: El sistema debe certificar formalmente que ningún componente se encuentra desconectado (Zero Orphans) y que ninguna Observación Empírica de telemetría contradice los axiomas base.
4. **Trazabilidad de Decisiones (ADRs)**: Cada subcistema debe estar enlazado a su correspondiente Registro de Decisión Arquitectónica (`DECIDED_BY`).

Hasta la versión v7.17.0, el motor `PFOEngine` (`ipvn7/diagnostics/pfo.py`) mantenía listas y diccionarios jerárquicos planos sin capacidades de consulta relacional, sin soporte para patrones openCypher, sin búsqueda de caminos más cortos (BFS), ni cálculo de sub-grafos locales.

Para consolidar la unificación ontológica del sistema, se formaliza la **Línea W (v7.18.0)**: **Sovereign In-Memory Knowledge Graph Engine & openCypher Pattern Matcher**.

## Decisión de Diseño

Se implementa el subsistema `ipvn7/diagnostics/graph.py`, integrado en `IPVN7Node`:

1. **Entidades del Grafo (`GraphNode` & `GraphEdge`)**:
   - Vértices tipados (`GraphNode`): `id`, `label` (`AxiomPrinciple`, `Subsystem`, `OperationalFunction`, `EmpiricalObservation`, `Decision`, `Peer`), `name`, `layer` (`L0` a `L4`, `Core`, `App`), `properties: dict`, `created_at`.
   - Aristas dirigidas tipadas (`GraphEdge`): `id`, `source_id`, `target_id`, `rel_type` (`GOVERNED_BY`, `DECIDED_BY`, `IMPLEMENTS`, `DERIVED_FROM`, `VALIDATED_BY`, `PEER_LINK`, `TRANSFERS_DATA_TO`, `SECURED_BY`), `properties: dict`.

2. **Evaluador de Consultas openCypher (`CypherEvaluator`, `CypherExecutionResult`)**:
   - Soporte para patrones dirigidos e inversos:
     * `MATCH (n:Label)`
     * `MATCH (n:Label)-[r:TYPE]->(m:Label)`
     * `MATCH (n:Label)<-[r:TYPE]-(m:Label)`
     * `MATCH (n)-[r]->(m)`
   - Evaluación de cláusulas `WHERE`:
     * Comparaciones directas: `=`, `!=`, `<`, `>`, `<=`, `>=`.
     * Navegación por campos de entidad y propiedades arbitrarias (ej: `a.layer = 'L0'`, `r.weight > 2.0`, `f.status = 'VERIFIED'`).
     * Filtros booleanos encadenados con `AND`.
   - Proyecciones de retorno (`RETURN`):
     * Selección de campos (`RETURN a.id, a.layer, r.rel_type, m.id`).
     * Alias de columnas mediante `AS` (`RETURN f.id AS function_identifier`).
     * Cláusula `LIMIT <N>` para paginación eficiente de resultados.
   - Medición de alta precisión del tiempo de ejecución en milisegundos (`exec_ms`).

3. **Análisis Topológico y Auditoría Axiomática**:
   - `validate_zero_orphans()`: Cálculo de grados de entrada y salida, detección de vértices aislados y cálculo del porcentaje de cobertura conectada.
   - `audit_axiomatic_coherence()`: Verifica que toda función derive de un axioma (`DERIVED_FROM`), que todo subcistema esté gobernado por un axioma (`GOVERNED_BY`) o implemente una función (`IMPLEMENTS`), y que toda observación empírica vinculada cumpla con la conformidad (`compliant == True`).
   - `find_shortest_path(source_id, target_id, rel_type)`: Algoritmo Breadth-First Search (BFS) para calcular la ruta semántica óptima entre dos entidades cualesquiera.
   - `extract_subgraph(seed_id, max_depth)`: Extracción de red egocéntrica local para inspección visual y análisis contextual de agentes.

4. **Sembrado Canónico Automático (`seed_canonical_architecture`)**:
   - Auto-ingesta de los 7 Axiomas Inmutables fundamentales.
   - Auto-ingesta de los 19 Registros de Decisión Arquitectónica (`ADR-001` a `ADR-019`).
   - Auto-ingesta de los Subcistemas de la arquitectura (DNS Server, XDP Switch, Mode Controller, OTA Hot-Swap, TEE Enclave, Formal Verifier, ZKP Schnorr, Ring Signatures, Reciprocity Settlement, DWRR Pacer, Kleinberg Mesh, PQC Keys, etc.).
   - Sincronización dinámica de peers remotos en `bootstrap_peer` (creación de nodos `Peer` y aristas `PEER_LINK`).

5. **Herramienta MCP 77 (`ipvn7_knowledge_graph`)**:
   - El catálogo de herramientas MCP de IPVN 7 alcanza exactamente 77 herramientas nativas.
   - Acciones soportadas: `query_cypher`, `get_topology`, `audit_coherence`, `find_orphans`, `find_path`, `extract_subgraph`, `register_node`, `register_edge`.

6. **Integración REST y Dashboard Web**:
   - Endpoints:
     * `POST /api/graph/query`: Ejecuta una consulta openCypher enviada en el cuerpo JSON.
     * `GET /api/graph/topology`: Retorna la topología completa con métricas de distribución de capas y etiquetas.
     * `GET /api/graph/audit`: Retorna el informe de auditoría de coherencia axiomática y huérfanos.
     * `GET /api/graph/path?source=X&target=Y`: Retorna la ruta más corta calculada por BFS.
     * `POST /api/graph/node`: Inserta o actualiza un vértice dinámico.
     * `POST /api/graph/edge`: Inserta o actualiza una relación semántica.
   - UI: Pestaña `tab-knowledge-graph` en el Control Center con insignias de métricas en tiempo real, consola interactiva de consulta openCypher, botones preset y visualizador de resultados estructurados.

## Consecuencias y Garantías
- **Axiomatic Consistency**: Todo cambio o módulo futuro puede ser auditado algorítmicamente contra los axiomas canónicos en $O(V + E)$ en memoria.
- **Transparencia para Agentes MCP**: Los asistentes de IA y agentes autónomos pueden explorar la arquitectura del sistema en lenguaje declarativo Cypher en tiempo de ejecución.
- **Zero Regressions Invariant**: 157 pruebas automatizadas pasan al 100% en `tests/test_ipvn7.py` en 7.87 segundos.
