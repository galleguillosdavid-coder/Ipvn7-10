# CATÁLOGO DE HERRAMIENTAS Y EVALUACIÓN (TOOLING CATALOG) — LAIA

**Versión:** 1.0  
**Fecha:** 20 de Octubre de 2026  
**Ámbito:** Entorno de Desarrollo y CI de Antigravity  

Este catálogo registra las herramientas de análisis estático, dinámico, linters y suites de prueba evaluadas empíricamente.

---

| Herramienta | Función | Lenguajes | Comando Reproducible | Decisión | Justificación y Limitaciones |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **pytest** | Pruebas dinámicas unitarias y adversariales | Python | `pytest -q` | **ADOPTADA** | Motor de verificación primaria. Ejecuta 108 pruebas en 6.5s sin dependencias externas complejas. |
| **Bandit** | Análisis estático de vulnerabilidades de seguridad | Python | `bandit -r ipvn7/ -ll` | **PROBAR DESPUÉS** | Excelente para detectar `try-except-pass` y debilidades criptográficas. Requiere instalación en venv sin contaminar dependencias de producción. |
| **Ruff** | Linter y analizador estático ultrarrápido | Python | `ruff check ipvn7/ app/` | **PROBAR DESPUÉS** | Detección inmediata de variables no utilizadas o alucinadas (`NameError`). |
| **Gitleaks** | Detección de secretos expuestos en Git | Agnóstico | `gitleaks detect -v` | **PROBAR DESPUÉS** | Valioso como pre-commit hook para asegurar la regla `ER-SEC-001`. |
| **pip-audit** | Escaneo de vulnerabilidades en dependencias (CVEs) | Python | `pip-audit` | **ADOPTAR EN CI** | Verifica dependencias del proyecto (`cryptography`) contra bases de datos OSV/PyPI. |
| **Semgrep** | Reglas semánticas personalizadas de seguridad | Multi-lenguaje | `semgrep --config p/security-audit` | **PROBAR DESPUÉS** | Útil para definir reglas customizadas basadas en `SECURITY_INVARIANTS.md`. |
| **CodeQL** | Análisis de taint-tracking y flujo de datos | Multi-lenguaje | `codeql database analyze` | **INTEGRAR EN GITHUB CI** | Integrado de forma nativa en workflows de GitHub Actions para el repositorio público. |
| **Hypothesis** | Pruebas basadas en propiedades (Property-Based Testing) | Python | `pytest --hypothesis-show-statistics` | **PROBAR DESPUÉS** | Generación sistemática de casos límite para parsers binarios (`BitNet`). |
| **Atheris** | Fuzzing guiado por cobertura | Python / C | `python fuzzer.py` | **DESCARTADA TEMPORALMENTE** | Requiere Clang/LLVM en Windows; alta complejidad de setup en el entorno actual. |
| **Schemathesis** | Pruebas automatizadas de contratos de API | OpenAPI / Python | `st run http://127.0.0.1:7070/openapi.json` | **PROBAR DESPUÉS** | Requiere generación previa del esquema OpenAPI formal del servidor. |

---

## Directiva de Integración
Ninguna herramienta se declara "adoptada" sin haber sido probada en el entorno local o en GitHub Actions. La ausencia de alertas en una herramienta no constituye demostración de seguridad.
