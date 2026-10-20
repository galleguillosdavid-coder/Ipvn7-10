# PLANTILLA DE CASO DE REGRESIÓN (REGRESSION TEMPLATE) — LAIA

```markdown
# REG-[NUM]: [Nombre del Caso de Prueba de Regresión]

- **ID de Hallazgo Asociado:** [ej. H-09-AUDIT-3]
- **Regla Inmutable:** [ej. ER-SEC-009]
- **Archivo de Prueba:** `tests/test_ipvn7.py`
- **Función:** `test_xxx`

---

## 1. Vector de Ataque o Falla Simulado
[Descripción del escenario adverso o payload malicioso.]

## 2. Comportamiento Esperado del Sistema (Invariante)
[El sistema debe rechazar la conexión, arrojar excepción específica o denegar el acceso sin fugas de datos.]

## 3. Código de la Prueba Negativa
```python
def test_regression_xxx():
    # Arrange: preparar estado hostil
    # Act: ejecutar operación
    # Assert: verificar rechazo seguro
```

## 4. Estado de Verificación
- **Última Ejecución:** [Fecha y hora]
- **Resultado:** [PASSED / FAILED]
```
