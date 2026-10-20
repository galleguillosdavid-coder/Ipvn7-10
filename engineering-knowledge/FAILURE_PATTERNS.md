# CATÁLOGO DE PATRONES DE FALLA (FAILURE PATTERNS) — LAIA

**Versión:** 1.0  
**Ámbito:** IPVN 7 y Desarrollo Asistido por IA en Antigravity  

Este catálogo describe los patrones de error sistemáticos que surgen durante el desarrollo y auditoría por parte de modelos de lenguaje (LLMs) y agentes autónomos.

---

### FP-01: El Bypass Silencioso (*Silent Exception Swallowing*)
- **Mecanismo:** La IA escribe bloques defensivos que capturan excepciones genéricas y retornan estructuras vacías o valores por defecto para evitar que el script se detenga con un traceback.
- **Ejemplo Mínimo Reproducible:**
  ```python
  # ANTIPATRÓN PROHIBIDO
  def verify_peer_identity(did: str) -> bool:
      try:
          return identity_engine.check(did)
      except Exception:
          return False  # O peor: return True para "no romper el flujo"
  ```
- **Riesgo:** Los errores reales de configuración, red o corrupción de datos quedan enmascarados; el sistema sigue operando en estado zombi o desprotegido.
- **Mitigación:** Exigir logging estructurado con nivel `ERROR` y relanzar la excepción (*Fail-Fast*) a menos que exista una política de recuperación explícita y documentada.

---

### FP-02: La Trampa del Éxito Fantasma (*Phantom Success Trap*)
- **Mecanismo:** El agente invoca una herramienta externa (ej. comando de terminal, script de compilación o linter). El comando arroja un código de salida distinto de cero (`exit code 1`), pero el modelo en su razonamiento ignora el error y prosigue como si hubiese triunfado.
- **Mitigación:** Inspección obligatoria de la salida estándar y de error (`stdout`/`stderr`) y del código de retorno. Toda tarea debe detenerse si el código de retorno es $\neq 0$.

---

### FP-03: Alucinación de Scope y Variables Inexistentes
- **Mecanismo:** El modelo asume que una variable calculada en una función auxiliar o en una rama condicional está disponible en el scope local actual.
- **Ejemplo Mínimo Reproducible:**
  ```python
  # ANTIPATRÓN PROHIBIDO
  def finalize_session(client_keys, server_keys):
      # Omitir el cálculo de transcript_hash
      return derive_key(secret, salt=transcript_hash) # NameError en runtime
  ```
- **Mitigación:** Ejecutar pruebas unitarias automatizadas (`pytest`) antes de dar por finalizada la edición de cualquier archivo.

---

### FP-04: Confusión entre Notificación de Control y Flujo de Datos
- **Mecanismo:** El modelo implementa una pasarela o proxy; despacha un paquete UDP o mensaje JSON anunciando una transferencia a un nodo remoto, y luego ejecuta un socket TCP directo en la máquina local, etiquetando el evento como "tráfico tunelizado por el overlay".
- **Mitigación:** Invariante 4 (`SECURITY_INVARIANTS.md`): ningún evento se marca como verificado sin que los bytes de datos hayan cursado efectivamente por el túnel cifrado.

---

### FP-05: Bucles de Agotamiento (*Exhaustion Loops*)
- **Mecanismo:** Al fallar una prueba, el modelo aplica repetidamente variantes cosméticas del mismo cambio fallido sin reflexionar sobre la causa raíz.
- **Mitigación:** Si una corrección falla dos veces consecutivas, detenerse obligatoriamente, formular hipótesis, consultar la documentación oficial o versiones de referencia mediante `search_web`, y rediseñar el enfoque.

---

### FP-06: Deriva de Contexto y Pérdida de Restricciones (*Context Drift*)
- **Mecanismo:** A medida que la conversación o la sesión de trabajo se alarga, el modelo pierde visibilidad de las restricciones iniciales del sistema (ej. no usar credenciales fijas, no mutar estado en GET) y comienza a reintroducir deuda técnica copiada del código legado.
- **Mitigación:** Lectura obligatoria de `CONSTITUTION.md` y `ENGINEERING_RULES.md` al inicio de cada ciclo de desarrollo.
