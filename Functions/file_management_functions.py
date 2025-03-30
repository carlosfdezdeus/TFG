from Functions.config import DB_FW_CONFLICTS, DATABASES_DIR, JSON_FILE_PATH, CRITICALITY, CONFLICT_GRAPH_PATH
import json, sqlite3, os, logging
import matplotlib.pyplot as plt
from typing import List, Dict


def load_rules_from_file(filename=JSON_FILE_PATH) -> List[Dict]:
    """Carga todas las reglas desde un archivo JSON en una lista de diccionarios, formateadas correctamente."""
    with open(filename, 'r') as file:
        json_data = json.load(file)
    
    rules = []
    for entry in json_data:
        rule = {
            "ID": entry["ID"],  
            "Policy": entry["Policy"],
            "Source": entry["Source"] if isinstance(entry["Source"], list) else [entry["Source"]],
            "Destination": entry["Destination"] if isinstance(entry["Destination"], list) else [entry["Destination"]],
            "Schedule": entry["Schedule"],
            "Service": (
                [s.strip() for s in entry["Service"].split(",")]  # Convertir a lista si es un string separado por comas
                if isinstance(entry["Service"], str) else entry["Service"]
            ),
            "Action": entry["Action"],
            "Log": entry["Log"],
            "Application Control": entry["Application Control"] if isinstance(entry["Application Control"], list) else [entry["Application Control"]],
            "Comments": entry["Comments"],
            "Hit Count": entry["Hit Count"],
            "Status": entry["Status"]
        }
        rules.append(rule)

    return rules

def create_conflict_database():
    logging.info("FUNCTION: create_conflict_database()")

    # Crear la carpeta de la base de datos si no existe
    if not os.path.exists(DATABASES_DIR):
        os.makedirs(DATABASES_DIR, exist_ok=True)
                    
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firewall_conflict_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            id_rule_1 INTEGER,
            id_rule_2 INTEGER,
            source_rule_1 TEXT,
            source_rule_2 TEXT,
            destination_rule_1 TEXT,
            destination_rule_2 TEXT,
            service_rule_1 TEXT,
            service_rule_2 TEXT,
            action_rule_1 TEXT,
            action_rule_2 TEXT,
            hit_count_rule_1 INTEGER,
            hit_count_rule_2 INTEGER,
            status_rule_1 TEXT,
            status_rule_2 TEXT,
            conflict_type TEXT,
            criticality TEXT,
            UNIQUE (id_rule_1, id_rule_2, 
                    source_rule_1, source_rule_2, 
                    destination_rule_1, destination_rule_2,
                    service_rule_1, service_rule_2,
                    action_rule_1, action_rule_2, 
                    hit_count_rule_1, hit_count_rule_2,
                    status_rule_1, status_rule_2,
                    conflict_type, criticality) 
        )
    ''')
    conn.commit()
    conn.close()


def insert_conflict_rule(rule1, rule2, conflict_type):
    """Inserta un conflicto en la base de datos si no existe previamente."""
    logging.info("FUNCTION: insert_conflict_rule()")

    criticality = CRITICALITY.get(conflict_type, "Unknown")

    def safe_get(rule, key):
        return json.dumps(rule[key]) if rule and key in rule else None

    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO firewall_conflict_rules (
                id_rule_1, id_rule_2,
                source_rule_1, source_rule_2,
                destination_rule_1, destination_rule_2,
                service_rule_1, service_rule_2,
                action_rule_1, action_rule_2,
                hit_count_rule_1, hit_count_rule_2,
                status_rule_1, status_rule_2,
                conflict_type, criticality
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING
        ''', (
            rule1["ID"], 
            rule2["ID"] if rule2 else 'NULL',

            safe_get(rule1, "Source"), 
            safe_get(rule2, "Source") if rule2 else 'NULL',

            safe_get(rule1, "Destination"), 
            safe_get(rule2, "Destination") if rule2 else 'NULL',

            safe_get(rule1, "Service"), 
            safe_get(rule2, "Service") if rule2 else 'NULL',

            rule1["Action"], 
            rule2["Action"] if rule2 else 'NULL',

            int(rule1.get("Hit Count", 0)), 
            int(rule2.get("Hit Count", 0)) if rule2 else 'NULL',

            safe_get(rule1, "Status"), 
            safe_get(rule2, "Status") if rule2 else 'NULL',

            conflict_type, criticality
        ))

        conn.commit()

    except sqlite3.Error as e:
        logging.error(f"Error inserting conflict: {e}")

    finally:
        conn.close()


def get_conflictive_rules_from_db():
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    rules_dataframe = pd.read_sql_query("SELECT * FROM firewall_conflict_rules", conn)
    conn.close()

    return rules_dataframe


def diplay_conflictive_rules():
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM firewall_conflict_rules")
    rules = cursor.fetchall()
    conn.close()
    
    for rule in rules:
        print(rule)  


def save_conflict_graph(fig, path):
    fig.tight_layout()
    fig.savefig(path, format=path.split('.')[-1])
    print(f"[INFO] Grafo guardado en: {path}")