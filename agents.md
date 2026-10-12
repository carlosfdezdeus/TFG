# Agents overview for TFG repository 🚀

## 📌 Objetivo
Este documento define una colección de *agents* (agentes) basados en la estructura de carpetas del proyecto para que puedas pedirme (a GitHub Copilot) tareas más complejas de forma clara y reproducible.

---

## 🧭 Índice
- Data Ingestion Agent
- Database Agent
- Conflict Detection Agent
- Graph Traversal Agent
- Optimization Agent
- Reporting Agent
- Test & Dev Agent
- Utilities Agent
- Cómo pedirme acciones (ejemplos)

---

## 1) Data Ingestion Agent 💾
**Propósito:** Cargar y validar archivos JSON de reglas de firewall desde `Input data/`.

**Responsabilidades:**
- Validar formato JSON y esquemas esperados
- Normalizar campos (ej. convertir a JSON string donde se espera)
- Guardar/exportar reglas para consumo por otros agentes

**Entrypoints / archivos relevantes:**
- `Input data/*.json` (p. ej. `firewall_cliente_WiFi_rules.json`)
- `Functions/file_management_functions.py`
- Scripts de carga: `Functions/database_management_functions.py.old` (funciones `read_firewall_rules()` y utilidades relacionadas)

**Entradas / Salidas:**
- Entrada: JSON de reglas
- Salida: JSON normalizado o DataFrame / Inserción en DB

**Comandos de ejemplo:**
- Python snippet: `from Functions import file_management_functions as fm; fm.load_rules('Input data/file.json')`

---

## 2) Database Agent 🗄️
**Propósito:** Crear y mantener la base de datos SQLite con reglas y conflictos.

**Responsabilidades:**
- Crear tablas (`firewall_rules`, `firewall_conflicts`)
- Insertar/consultar reglas
- Exportar a DataFrame/JSON

**Entrypoints / archivos relevantes:**
- `Functions/database_management_functions.py.old` (funcs: `create_firewall_rules_database()`, `insert_firewall_rule()`, `get_firewall_rules()`, `create_conflict_database()`)

**Ejemplo de uso:**
- `from Functions.database_management_functions import create_firewall_rules_database, insert_firewall_rule`

---

## 3) Conflict Detection Agent ⚠️
**Propósito:** Detectar conflictos entre reglas (shadowing, redundant, etc.) y generar reportes intermedios.

**Responsabilidades:**
- Aplicar reglas de detección
- Generar estructuras de conflicto (p. ej. grafos, listas)
- Marcar tipo de conflicto y severidad

**Entrypoints / archivos relevantes:**
- `conflictRuleDetector.py`
- `conflictGraphGenerator.py`
- `graph_detected_conflicts.py`
- `pruebaConflictRuleDetector.py`
- `Functions/conflict_detection_functions.py`

**Salida:** JSON con conflictos, tablas en DB (`firewall_conflicts`), y reportes de texto

**Comando de ejemplo:**
- `python conflictRuleDetector.py --input Input data/firewall.json --out Output data/conflicts.json`

---

## 4) Graph Traversal Agent 🔍
**Propósito:** Construir y recorrer grafos de conflictos para análisis estructural.

**Responsabilidades:**
- Crear grafos (nodal) a partir de detecciones
- Detectar componentes conectadas, ciclos y caminos críticos
- Proveer APIs para optimización basada en grafos

**Entrypoints / archivos relevantes:**
- `Functions/graphFunctions.py` / `graphFunctions.py.new`
- `conflictGraphGenerator.py`

**Salida:** JSON con estructura de grafo, imágenes DOT o datos para visualización

---

## 5) Optimization Agent 🔧
**Propósito:** Proponer optimizaciones (p. ej. eliminar reglas redundantes, reordenar) y generar un conjunto optimizado de reglas.

**Responsabilidades:**
- Analizar conflictos y proponer cambios conservadores
- Generar `optimized_firewall_rules.json`
- Medir impacto (número de reglas, métricas de cobertura)

**Entrypoints / archivos relevantes:**
- `optimizator.py`
- `conflictOptimizations.py`
- `Functions/optimization_functions.py`

**Salida:** `Output data/optimized_firewall_rules.json`, reportes comparativos

---

## 6) Reporting Agent 📊
**Propósito:** Generar reportes legibles (txt, json, tablas) y métricas de calidad.

**Responsabilidades:**
- Crear reportes de conflictos y optimizaciones
- Mantener historiales y métricas

**Archivos relevantes:**
- `Output data/` (destino de salidas)
- `old/` (ejemplos de reportes en `Shadow Rules Searcher v1.0/`)

---

## 7) Test & Dev Agent ✅
**Propósito:** Ejecutar pruebas, scripts de ejemplo y validación rápida.

**Responsabilidades:**
- Ejecutar `pruebaConflictRuleDetector.py` y scripts de sanity
- Probar integraciones: ingestion → detection → optimization

**Recomendación:** Añadir `pytest` y tests unitarios en `Functions/tests/`

---

## 8) Utilities Agent 🧰
**Propósito:** Funciones auxiliares (configuración, I/O, DB helpers).

**Archivos relevantes:**
- `Functions/config.py` (constantes como `JSON_FILE_PATH`, `DB_FW_RULES`)
- `Functions/file_management_functions.py`
- `Functions/database_management_functions.py.old`

---

## Entorno recomendado ⚙️
- Python 3.10+ (venv/virtualenv)
- Pip packages sugeridos: `pandas`, `networkx` (si no existe), `sqlite3` (stdlib)
- Variables de configuración en `Functions/config.py`

Instalación rápida:
```bash
python -m venv .venv
source .venv/bin/activate
pip install pandas networkx
```

---

## Cómo pedirme acciones (ejemplos) 💬
- "Ejecuta al Agente de Detección de Conflictos sobre `Input data/firewall_cliente_WiFi_rules.json` y genera `Output data/conflicts.json`." ✅
- "Haz que el Agente de Optimización genere `optimized_firewall_rules.json` y adjunta un resumen de métricas." ✅
- "Añade un test unitario para `insert_firewall_rule()` y ejecútalo." ✅

> Consejo: cuando me pidas algo, indica: 1) agente objetivo, 2) archivo de entrada o DB, 3) salida esperada y 4) nivel de conservadurismo (p.ej. 'no eliminar reglas que aprueben tráfico').

---

## Notas finales ✨
- Si quieres, puedo convertir cada agente en comandos CLI claros o en una pequeña API (FastAPI) para integrarlos en un pipeline automatizado.

---

*Generado para el branch `feature/graphTraveser`. Si quieres ajustes (más agentes, más detalle por archivo o flujos de datos), dime qué parte quieres priorizar.*
