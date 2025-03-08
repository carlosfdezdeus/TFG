# FIREWALL SECURITY POLICY COMPLIANCE SCRIPT
This document details the functionality of the firewall security policy compliance script. It explains everything from reading rules from a JSON to saving conflictive rules in a DB.

## Conflictive rules:
- Redundant Rules
- Shadowed Rules
- Rules with ANY
- Insecure Rules
- Bidirecctional Rules
- Unused Rules
- Disabled Rules
- Deny remaining traffic Rule

## Project estructure
The project is organised as follows:

```
VULNERABILITY_AUTOMATIZATION/
│
├── Input data/
│   └── "firewall_rules.json"   # Firewall rules exported as JSON
│
├── Functions/
│   └── config.py                           # Script configuration
│   └── conflict_detection_functions.py     # Python file which contains the functions dedicated to the detect conflict rules
│   └── file_management_functions.py        # Python file with which contains the functions dedicated to the management of files like getting rules from JSON or creating a DB.
└── main.py                    # Main script file to start the revision of the firewall security policy.
```

## Intoduction
The script allows to manage firewall rules efficiently. 
First, they are loaded from a JSON file. Then, the intersections between the rules are checked, detecting possible conflicts and storing them in a DB with specific information about each conflict. Based on the information stored in the DB, a graph of conflicts with the rules is made to later solve them by means of Graph Theory.a


## Main Functions: *concflict_detection_functiones.py*

### 1. `is_redundant()`
Guarda las reglas de un archivo JSON en una base de datos SQLite.

#### **Detailed Description**:
- Carga un archivo JSON que contiene una lista de reglas de firewall, cada una con detalles como el origen, destino, protocolo, rango de puertos, acción y descripción.
- Crea una tabla en la base de datos SQLite (si no existe) para almacenar las reglas.
- Inserta las reglas en la tabla de manera segura, asegurándose de no duplicar registros existentes.
- Es útil para centralizar la gestión de reglas y prepararlas para su análisis posterior.

#### **Parameters**:
- `json_file` (str): Ruta al archivo JSON que contiene las reglas del firewall.
- `db_name` (str): Nombre del archivo de base de datos SQLite. Por defecto, `"firewall_rules.db"`.

#### **Examples**:
```python
functions.saveFWRules("reglasFW.json")
```

#### **Flow Diagrams**:
<img src="Flow diagrams/Flow Diagram - is_redundant().png" alt="FUNCIÓN: is_redundant()" width="200">

