# 🛡️ Firewall Rule Optimizator

Herramienta en Python que analiza las reglas de un firewall, detecta conflictos y anomalías de seguridad, las representa como un grafo de conflictos y propone un conjunto de reglas optimizado, acompañado de un informe PDF.

> Trabajo Fin de Grado (Ingeniería de Telecomunicación) desarrollado en colaboración con **PLANCIBER** y utilizado como producto de PLANCIBER.
> Autor: **Carlos Fernando Fernández Deus**.

---

## 📑 Índice

- [Descripción](#-descripción)
- [Características principales](#-características-principales)
- [Tecnologías utilizadas](#-tecnologías-utilizadas)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Requisitos previos](#-requisitos-previos)
- [Instalación](#-instalación)
- [Configuración](#-configuración)
- [Modo de uso](#-modo-de-uso)
- [Formato de entrada](#-formato-de-entrada)
- [Resultados generados](#-resultados-generados)
- [Autoría](#-autoría)

---

## 📝 Descripción

Firewall Rule Optimizator carga un conjunto de reglas de firewall exportadas en JSON y las compara entre sí para identificar conflictos. Cada conflicto se guarda en una base de datos SQLite con su tipo y su criticidad. A partir de esos datos se construye un **grafo de conflictos** que se recorre con técnicas de teoría de grafos (BFS/DFS) para priorizar y resolver los problemas.

El resultado es un conjunto de reglas optimizado, un grafo comparativo antes/después y un informe PDF con todas las recomendaciones.

---

## ✨ Características principales

### Detección de conflictos

| Conflicto | Tipo | Criticidad |
|---|---|---|
| Regla no utilizada (`Not in use`) | Individual | Baja |
| Regla deshabilitada (`Disabled`) | Individual | Baja |
| Regla redundante (`Redundant`) | Entre reglas | Baja |
| Regla parcialmente ensombrecida (`Partially Shadowed`) | Entre reglas | Media |
| Regla bidireccional (`Bidirectional`) | Individual | Media |
| `ANY` en servicio u origen | Individual | Media |
| Regla totalmente ensombrecida (`Fully Shadowed`) | Entre reglas | Alta |
| `ANY` en destino | Individual | Alta |
| Protocolos inseguros (FTP, Telnet, HTTP, SMBv1…) | Individual | Alta |
| `ANY` en 2 o 3 campos | Individual | Crítica |
| Tráfico restante no denegado | Política | Crítica |

La criticidad y la lista de protocolos inseguros se definen en [`Functions/config.py`](Functions/config.py).

### Análisis y optimización

- **Grafo de conflictos** (NetworkX + Matplotlib) con colores y estilos de línea según el tipo y la gravedad de cada conflicto.
- **Optimización 0 – Priorización de subgrafos:** obtiene las componentes conexas del grafo (BFS) y propone su posición en el firewall según el número de *hits* de cada subgrafo.
- **Optimización 1 – Anomalías individuales:** elimina reglas deshabilitadas, inseguras o no utilizadas, y señala las reglas con `ANY`.
- **Optimización 2 – Redundancias:** elimina las reglas redundantes y conserva la más específica.
- **Optimización 3 – Ensombrecimiento total:** propone reordenar las reglas totalmente ensombrecidas.
- **Reanálisis:** vuelve a ejecutar la detección sobre las reglas optimizadas para comparar el antes y el después.

### Informes

- Informe PDF (ReportLab) con portada, reglas conflictivas, grafos antes/después y las secciones de cada optimización.
- Exportación del conjunto de reglas optimizado en JSON.
- Métricas de tiempo de ejecución por fase (detección, grafo, optimización y exportación).

---

## 🧰 Tecnologías utilizadas

| Tecnología | Versión | Uso |
|---|---|---|
| Python | 3.14 (versión probada) | Lenguaje principal |
| pandas | 3.0.6 | Tratamiento de datos tabulares |
| NumPy | 2.5.4 | Cálculo numérico auxiliar |
| NetworkX | 3.7 | Construcción y recorrido del grafo de conflictos |
| Matplotlib | 3.11.2 | Visualización del grafo (backend `TkAgg`) |
| ReportLab | 5.0.1 | Generación del informe PDF |
| SQLite (`sqlite3`) | Librería estándar | Almacenamiento de conflictos |
| `ipaddress` | Librería estándar | Comparación de subredes y direcciones IP |

Las versiones exactas están fijadas en [`requirements.txt`](requirements.txt).

---

## 📂 Estructura del proyecto

```text
.
├── Input data/                  # Reglas de firewall en JSON e imágenes del informe
├── Functions/
│   ├── config.py                        # Rutas, criticidades y protocolos inseguros
│   ├── conflict_detection_functions.py  # Lógica de detección de conflictos
│   ├── file_management_functions.py     # E/S de ficheros, SQLite, PDF y JSON
│   ├── graphFunctions.py                # Construcción, dibujo y recorrido del grafo
│   └── optimization_functions.py        # Optimizaciones 1, 2 y 3
├── Databases/                   # Bases de datos SQLite de conflictos (original y optimizada)
├── Output data/                 # Grafos, informe PDF y reglas optimizadas
├── graph_detected_conflicts.py  # Detección de conflictos y generación del grafo
├── optimizator.py               # Punto de entrada: pipeline completo
└── requirements.txt
```

---

## ✅ Requisitos previos

- **Python 3** con `pip` y `venv`. Versión probada: 3.14.
- **Tkinter.** Es obligatorio porque `graphFunctions.py` fuerza el backend `TkAgg` de Matplotlib.
  - macOS (Homebrew):

    ```bash
    brew install python-tk@3.14
    ```

  - Debian/Ubuntu:

    ```bash
    sudo apt install python3-tk
    ```

  - Para comprobar que está disponible:

    ```bash
    python3 -m tkinter
    ```

- **Git**, para clonar el repositorio.

---

## ⚙️ Instalación

1. Clona el repositorio:

   ```bash
   git clone <URL_DEL_REPOSITORIO>
   cd <CARPETA_DEL_REPOSITORIO>
   ```

2. Crea y activa un entorno virtual:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

   En Windows:

   ```powershell
   .venv\Scripts\activate
   ```

3. Instala las dependencias:

   ```bash
   pip install -r requirements.txt
   ```

4. Comprueba que existen las carpetas de trabajo (`Input data/`, `Databases/` y `Output data/`):

   ```bash
   mkdir -p "Input data" "Databases" "Output data"
   ```

---

## 🔧 Configuración

Toda la configuración está en [`Functions/config.py`](Functions/config.py). El fichero de reglas que se analiza se elige en `JSON_FILE_PATH`:

```python
JSON_FILE_PATH = os.path.join(INPUT_DATA_DIR, "reglas_ejemplo_memoria.json")
```

También se pueden ajustar:

- `STRICT_POLICY_INSECURE_PROTOCOLS`: protocolos y puertos que se consideran inseguros.
- `CRITICALITY`: nivel de criticidad de cada tipo de conflicto.
- `CONFLICT_LINE_STYLES` / `UNARY_CONFLICT_COLORS`: estilo visual del grafo.
- Rutas de salida: `REPORT`, `CONFLICT_GRAPH_PATH`, `OPTIMIZED_CONFLICT_GRAPH_PATH` y `OPTIMIZED_JSON_FILE_PATH`.

---

## 🚀 Modo de uso

### Pipeline completo

Ejecuta el análisis y la optimización de principio a fin desde la raíz del proyecto:

```bash
python optimizator.py
```

El proceso:

1. Carga las reglas desde `JSON_FILE_PATH`.
2. Detecta los conflictos y los guarda en `Databases/firewall_conflict_rules.db`.
3. Genera el grafo de conflictos original.
4. Aplica las optimizaciones 0, 1, 2 y 3.
5. Vuelve a analizar las reglas optimizadas y genera el grafo optimizado.
6. Exporta el informe PDF y el JSON de reglas optimizadas.
7. Muestra por consola los tiempos de ejecución de cada fase.

### Capturas

**Ejecución por consola**

![Salida por consola de optimizator.py](docs/images/consola.png)

**Grafo de conflictos original**

![Grafo de conflictos original](docs/images/conflict_graph.png)

**Grafo de conflictos optimizado**

![Grafo de conflictos optimizado](docs/images/optimized_conflict_graph.png)

**Informe PDF**

![Portada del informe PDF](docs/images/informe_pdf.png)

> 📌 Sustituye estas rutas por capturas reales. Usa solo datos de ejemplo: nunca reglas reales de un cliente.

---

## 📥 Formato de entrada

El fichero de entrada es un array JSON de reglas. Estos son los campos que lee el programa:

```json
[
  {
    "ID": "100",
    "Policy": "SRV-SSL_ADMIN (14)",
    "Source": ["ANY"],
    "Destination": ["10.0.0.0/24"],
    "Schedule": ["always"],
    "Service": ["80"],
    "Action": "ALLOW",
    "Log": "All",
    "Application Control": ["default"],
    "Comments": "",
    "Hit Count": 117,
    "Status": "enabled"
  }
]
```

- `ID` debe ser numérico (en formato texto), porque se usa para ordenar las comparaciones.
- `Service` admite tanto una lista como un texto separado por comas.
- Los campos que falten toman valores por defecto (`Status: "enabled"`, `Hit Count: 0`…).

En [`Input data/reglas_ejemplo_memoria.json`](Input%20data/reglas_ejemplo_memoria.json) tienes un ejemplo completo.

---

## 📤 Resultados generados

| Fichero | Contenido |
|---|---|
| `Databases/firewall_conflict_rules.db` | Conflictos detectados en las reglas originales |
| `Databases/optimized_firewall_conflict_rules.db` | Conflictos que quedan tras optimizar |
| `Output data/conflict_graph.png` | Grafo de conflictos original |
| `Output data/optimized_conflict_graph.png` | Grafo de conflictos optimizado |
| `Output data/firewall_optimization_report.pdf` | Informe completo de optimización |
| `Output data/optimized_firewall_rules.json` | Conjunto de reglas optimizado |

---

## 👤 Autoría

- **Autor:** Carlos Fernando Fernández Deus
- **Contexto:** Trabajo Fin de Grado, Ingeniería de Telecomunicación
- **Colaboración:** PLANCIBER. La herramienta se utiliza como producto de PLANCIBER.
