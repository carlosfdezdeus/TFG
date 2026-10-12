from Functions.config import DB_FW_CONFLICTS, DB_FW_RULES, DB_FW_OPTIMIZED, DATABASES_DIR, JSON_FILE_PATH, OPTIMIZED_JSON_FILE_PATH, CRITICALITY, PLANCIBER_LOGO, PLANCIBER_PORTADA_IMG
import json, sqlite3, os, logging, shutil
import matplotlib.pyplot as plt
import pandas as pd
from typing import List, Dict

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from textwrap import wrap
from datetime import datetime

from reportlab.platypus import Paragraph, Frame, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY


from copy import deepcopy

def load_rules_from_file(filename=JSON_FILE_PATH) -> List[Dict]:
    """Carga todas las reglas desde un archivo JSON en una lista de diccionarios, formateadas correctamente."""
    import json

    with open(filename, 'r') as file:
        json_data = json.load(file)

    rules = []
    for entry in json_data:
        rule = {
            "ID": entry.get("ID", ""),  
            "Policy": entry.get("Policy", ""),
            "Source": entry.get("Source", []) if isinstance(entry.get("Source", []), list) else [entry.get("Source", [])],
            "Destination": entry.get("Destination", []) if isinstance(entry.get("Destination", []), list) else [entry.get("Destination", [])],
            "Schedule": entry.get("Schedule", "always"),
            "Service": (
                [s.strip() for s in entry.get("Service", "").split(",")]
                if isinstance(entry.get("Service", ""), str) else entry.get("Service", [])
            ),
            "Action": entry.get("Action", ""),
            "Log": entry.get("Log", ""),
            "Application Control": entry.get("Application Control", []) if isinstance(entry.get("Application Control", []), list) else [entry.get("Application Control", [])],
            "Comments": entry.get("Comments", ""),
            "Hit Count": entry.get("Hit Count", 0),
            "Status": entry.get("Status", "enabled")
        }
        rules.append(rule)

    return rules


# def load_rules_from_file(filename=JSON_FILE_PATH) -> List[Dict]:
#     """Carga todas las reglas desde un archivo JSON en una lista de diccionarios, formateadas correctamente."""
#     with open(filename, 'r') as file:
#         json_data = json.load(file)
    
#     rules = []
#     for entry in json_data:
#         rule = {
#             "ID": entry["ID"],  
#             "Policy": entry["Policy"],
#             "Source": entry["Source"] if isinstance(entry["Source"], list) else [entry["Source"]],
#             "Destination": entry["Destination"] if isinstance(entry["Destination"], list) else [entry["Destination"]],
#             "Schedule": entry["Schedule"],
#             "Service": (
#                 [s.strip() for s in entry["Service"].split(",")]  # Convertir a lista si es un string separado por comas
#                 if isinstance(entry["Service"], str) else entry["Service"]
#             ),
#             "Action": entry["Action"],
#             "Log": entry["Log"],
#             "Application Control": entry["Application Control"] if isinstance(entry["Application Control"], list) else [entry["Application Control"]],
#             "Comments": entry["Comments"],
#             "Hit Count": entry["Hit Count"],
#             "Status": entry["Status"]
#         }
#         rules.append(rule)

#     return rules

# def create_firewall_rules_database():
#     # Conectar a la base de datos (se crea si no existe)
#     conn = sqlite3.connect(DB_FW_RULES)
#     cursor = conn.cursor()

#     # Crear tabla (puedes ajustarla si necesitas más campos)
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS firewall_rules (
#             id INTEGER PRIMARY KEY,
#             policy TEXT,
#             source TEXT,
#             destination TEXT,
#             schedule TEXT,
#             service TEXT,
#             action TEXT,
#             log TEXT,
#             application_control TEXT,
#             status TEXT,
#             hit_count INTEGER,
#             comments TEXT
#         )
#     """)

#     # Limpiar tabla antes de insertar (opcional)
#     cursor.execute("DELETE FROM firewall_rules")

#     conn.commit()
#     conn.close()


def insert_firewall_rules(firewall_rules):
    conn = sqlite3.connect(DB_FW_RULES)
    cursor = conn.cursor()

    for rules in firewall_rules:
        cursor.execute("""
            INSERT INTO firewall_rules (
                id, policy, name, source, destination, service, action, status, hit_count, comments
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            int(rules.get("ID", -1)),
            rules.get("Policy", ""),
            rules.get("Name", ""),
            ",".join(rules.get("Source", rules.get("Source Address", []))),
            ",".join(rules.get("Destination", rules.get("Destination Address", []))),
            ",".join(rules.get("Service", [])),
            rules.get("Action", ""),
            rules.get("Status", ""),
            int(rules.get("Hit Count", 0)),
            rules.get("Comments", "")
        ))
    conn.commit()
    conn.close()
    # print("Reglas insertadas correctamente en la base de datos.")


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


def insert_conflict_rule(rule1, rule2, conflict_type, database):
    """Inserta un conflicto en la base de datos si no existe previamente."""
    logging.info("FUNCTION: insert_conflict_rule()")

    criticality = CRITICALITY.get(conflict_type, "Unknown")

    def safe_get(rule, key):
        return json.dumps(rule[key]) if rule and key in rule else None

    conn = sqlite3.connect(database)
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

def getConflicts(database=DB_FW_CONFLICTS):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    query = "SELECT id_rule_1, id_rule_2, conflict_type FROM firewall_conflict_rules"
    #query = "SELECT id_rule_1, id_rule_2, conflict_type FROM prueba"

    cursor.execute(query)
    conflicts = cursor.fetchall()

    conn.close()

    # print(conflicts)
    
    return conflicts

def display_conflictive_rules():
    conflictive_rules_text = []
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM firewall_conflict_rules")
    rules = cursor.fetchall()
    conn.close()
    
    for i, rule in enumerate(rules, 1):
        # print(rule)
        rule_str = ", ".join(str(r) for r in rule)
        conflictive_rules_text.append(f"{rule_str}")
    return conflictive_rules_text


# FALTAN DE AQUÍ PARA ABAJO:


def save_conflict_graph(fig, path):
    fig.tight_layout()
    fig.savefig(path, format=path.split('.')[-1])
    # print(f"[INFO] Grafo guardado en: {path}")

def get_hits():
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()

    query = """
    SELECT id_rule_1, hit_count_rule_1, id_rule_2, hit_count_rule_2
    FROM firewall_conflict_rules
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    hits_per_rule = {}

    for id1, hits1, id2, hits2 in rows:
        # Regla 1
        if id1 is not None:
            id1 = int(id1)
            hits1 = hits1 if hits1 else 0
            hits_per_rule[id1] = max(hits1, hits_per_rule.get(id1, 0))
        
        # Regla 2
        if id2 not in ("NULL", None):
            id2 = int(id2)
            hits2 = hits2 if hits2 else 0
            hits_per_rule[id2] = max(hits2, hits_per_rule.get(id2, 0))

    return hits_per_rule

def get_redundant_rules():
    conn = sqlite3.connect(DB_FW_OPTIMIZED)
    cursor = conn.cursor()

    query = """
        SELECT id_rule_1, id_rule_2,
                   source_rule_1, source_rule_2,
                   destination_rule_1, destination_rule_2,
                   service_rule_1, service_rule_2,
                   hit_count_rule_1, hit_count_rule_2
            FROM firewall_conflict_rules
            WHERE conflict_type = 'Redundant'
    """
    
    cursor.execute(query)    
    redundant_rules = cursor.fetchall()
    conn.close()

    return redundant_rules
  
def get_fully_shadowed_rules():
    conn = sqlite3.connect(DB_FW_OPTIMIZED)
    cursor = conn.cursor()

    query = """
        SELECT id_rule_1, id_rule_2,
                   source_rule_1, source_rule_2,
                   destination_rule_1, destination_rule_2,
                   service_rule_1, service_rule_2,
                   action_rule_1, action_rule_2,
                   hit_count_rule_1, hit_count_rule_2

            FROM firewall_conflict_rules
            WHERE conflict_type = 'Fully Shadowed'
    """
    cursor.execute(query)
    fully_shadowed_rules = cursor.fetchall()
    conn.close()

    return fully_shadowed_rules

def get_insecure_rules_id():
    conn = sqlite3.connect(DB_FW_OPTIMIZED)
    cursor = conn.cursor()

    query = """
        SELECT id_rule_1 FROM firewall_conflict_rules
        WHERE conflict_type == 'Insecure'
    """
    cursor.execute(query)
    insecure_rules = cursor.fetchall()
    conn.close()

    return insecure_rules

def get_disabled_rules_id():
    conn = sqlite3.connect(DB_FW_OPTIMIZED)
    cursor = conn.cursor()

    query = """
        SELECT id_rule_1 FROM firewall_conflict_rules
        WHERE conflict_type == 'Disabled'
    """
    cursor.execute(query)
    fully_shadowed_rules = cursor.fetchall()
    conn.close()

    return fully_shadowed_rules

def get_not_in_use_rules_without_shadowing():
    try:
        conn = sqlite3.connect(DB_FW_OPTIMIZED)
        cursor = conn.cursor()

        # Paso 1: Obtener reglas con conflicto 'Not in use'
        cursor.execute("""
            SELECT DISTINCT id_rule_1 
            FROM firewall_conflict_rules 
            WHERE conflict_type = 'Not in use'
        """)
        not_in_use_ids = set(int(row[0]) for row in cursor.fetchall() if row[0] is not None)

        # Paso 2: Obtener reglas involucradas en conflictos shadowed
        cursor.execute("""
            SELECT DISTINCT id_rule_1 FROM firewall_conflict_rules 
            WHERE conflict_type IN ('Fully Shadowed', 'Partially Shadowed')
            UNION
            SELECT DISTINCT id_rule_2 FROM firewall_conflict_rules 
            WHERE conflict_type IN ('Fully Shadowed', 'Partially Shadowed')
        """)
        shadowed_ids = set(int(row[0]) for row in cursor.fetchall() if row[0] is not None)

        # print(f"Not in use: {not_in_use_ids}")
        # print(f"Shadowed: {shadowed_ids}")

        # Paso 3: Filtrar los id_rule_1 que solo están en 'Not in use'
        not_in_use_to_remove = not_in_use_ids - shadowed_ids
        
        if not_in_use_to_remove:
            # print(f"Eliminando conflictos 'Not in use' para {len(not_in_use_to_remove)} reglas...")

            cursor.executemany("""
                DELETE FROM firewall_conflict_rules 
                WHERE conflict_type = 'Not in use' AND id_rule_1 = ?
            """, [(rule_id,) for rule_id in not_in_use_to_remove])

            conn.commit()

            # print(f"Se eliminaron {cursor.rowcount} filas.")
        # else:
        #     print("No hay reglas 'Not in use' seguras para eliminar.")
            
        return not_in_use_to_remove
    except Exception as e:
        print(f"Error durante la eliminación: {e}")
    finally:
        conn.close()

    
def get_rules_with_any_id():
    conflict_types = ("Any: Origin", "Any: Destination", "Any: Service", "Any: 2 fields", "Any: 3 fields")

    try:
        conn = sqlite3.connect(DB_FW_OPTIMIZED)
        cursor = conn.cursor()

        cursor.execute(f"""
            SELECT DISTINCT id_rule_1
            FROM firewall_conflict_rules
            WHERE conflict_type IN ({','.join(['?'] * len(conflict_types))})
        """, conflict_types)

        rules_id_with_any = [str(row[0]) for row in cursor.fetchall() if row[0] is not None]
        return rules_id_with_any

    except Exception as e:
        print(f"Error al obtener reglas con conflictos 'Any': {e}")
        return []
    finally:
        conn.close()

import sqlite3

def remove_insecure_and_disabled_rules_db(ids_to_remove):
    if not ids_to_remove:
        # print("No hay reglas para eliminar de la base de datos.")
        return

    try:
        conn = sqlite3.connect(DB_FW_OPTIMIZED)
        cursor = conn.cursor()

        # print("📋 Estado inicial de la tabla firewall_conflict_rules:")
        # cursor.execute("SELECT * FROM firewall_conflict_rules")
        # for row in cursor.fetchall():
        #     print(row)

        # Genera placeholders dinámicos (?, ?, ?, ...)
        placeholders = ','.join(['?'] * len(ids_to_remove))
        query_1 = f"DELETE FROM firewall_conflict_rules WHERE id_rule_1 IN ({placeholders})"
        cursor.execute(query_1, list(ids_to_remove))
        conn.commit()

        num_reglas_eliminadas = cursor.rowcount

        query_2 = f"DELETE FROM firewall_conflict_rules WHERE id_rule_2 IN ({placeholders})"
        cursor.execute(query_2, list(ids_to_remove))
        conn.commit()
        num_reglas_eliminadas += cursor.rowcount

        # print(f"\n✅ Se eliminaron conflictos correspondientes a {num_reglas_eliminadas} reglas distintas.")

        # print("\n📋 Estado final de la tabla firewall_conflict_rules:")
        # cursor.execute("SELECT * FROM firewall_conflict_rules")
        # for row in cursor.fetchall():
        #     print(row)

    except Exception as e:
        print(f"Error al eliminar reglas inseguras o deshabilitadas: {e}")
    finally:
        conn.close()

import sqlite3

def remove_not_in_use_rules_db(ids_to_remove):
    if not ids_to_remove:
        # print("No hay reglas 'Not in use' para eliminar de la base de datos.")
        return

    try:
        conn = sqlite3.connect(DB_FW_OPTIMIZED)
        cursor = conn.cursor()

        # print("📋 Estado inicial de la tabla firewall_conflict_rules:")
        # cursor.execute("SELECT * FROM firewall_conflict_rules")
        # for row in cursor.fetchall():
        #     print(row)

        # Genera placeholders dinámicos (?, ?, ...)
        placeholders = ','.join(['?'] * len(ids_to_remove))

        # Elimina conflictos donde estas reglas sean id_rule_1
        query_1 = f"DELETE FROM firewall_conflict_rules WHERE id_rule_1 IN ({placeholders})"
        cursor.execute(query_1, list(ids_to_remove))
        conn.commit()

        num_reglas_eliminadas = cursor.rowcount

        # Elimina conflictos donde estas reglas sean id_rule_2
        query_2 = f"DELETE FROM firewall_conflict_rules WHERE id_rule_2 IN ({placeholders})"
        cursor.execute(query_2, list(ids_to_remove))
        conn.commit()

        num_reglas_eliminadas += cursor.rowcount

        # print(f"\n✅ Se eliminaron conflictos correspondientes a {num_reglas_eliminadas} reglas 'Not in use'.")

        # print("\n📋 Estado final de la tabla firewall_conflict_rules:")
        # cursor.execute("SELECT * FROM firewall_conflict_rules")
        # for row in cursor.fetchall():
        #     print(row)

    except Exception as e:
        print(f"Error al eliminar reglas 'Not in use': {e}")
    finally:
        conn.close()

def is_remaining_traffic_denied_conflict():
    try:
        conn = sqlite3.connect(DB_FW_CONFLICTS)
        cursor = conn.cursor()

        # Selecciona la última regla habilitada por orden de ID descendente
        cursor.execute(""" SELECT id_rule_1 FROM firewall_conflict_rules 
                           WHERE conflict_type = 'Remaining traffic not denied';
        """)
        result = cursor.fetchone()

        if result:
            rule_id = result[0]  
            return int(rule_id), True

        return None, False

    except Exception as e:
        print(f"Error al consultar la base de datos: {e}")
        return None, False

    finally:
        conn.close()    

def remove_redundant_from_db(redundant_rules_to_remove):
    if not redundant_rules_to_remove:
        # print("No hay reglas redundantes para eliminar.")
        return

    try:
        conn = sqlite3.connect(DB_FW_OPTIMIZED)
        cursor = conn.cursor()

        # print("📋 Estado inicial de la tabla firewall_conflict_rules:")
        # cursor.execute("SELECT * FROM firewall_conflict_rules")
        # for row in cursor.fetchall():
        #     print(row)

        placeholders = ','.join(['?'] * len(redundant_rules_to_remove))

        # Elimina conflictos donde estas reglas sean id_rule_1
        query_1 = f"""
            DELETE FROM firewall_conflict_rules 
            WHERE id_rule_1 IN ({placeholders})
        """
        cursor.execute(query_1, list(redundant_rules_to_remove))
        conn.commit()
        num_reglas_eliminadas = cursor.rowcount

        # Elimina conflictos donde estas reglas sean id_rule_2
        query_2 = f"""
            DELETE FROM firewall_conflict_rules 
            WHERE id_rule_2 IN ({placeholders})
        """
        cursor.execute(query_2, list(redundant_rules_to_remove))
        conn.commit()
        num_reglas_eliminadas += cursor.rowcount

        # print(f"\n✅ Se eliminaron conflictos correspondientes a {num_reglas_eliminadas} reglas redundantes.")

        # print("\n📋 Estado final de la tabla firewall_conflict_rules:")
        # cursor.execute("SELECT * FROM firewall_conflict_rules")
        # for row in cursor.fetchall():
        #     print(row)

    except Exception as e:
        print(f"Error durante la eliminación de reglas redundantes: {e}")
    finally:
        conn.close()

def swap_fully_shadowed_rules(proposed_swaps):
    return 0

def copiar_db_sqlite_backup():
    try:
        if not os.path.exists(DB_FW_CONFLICTS):
            print(f"El archivo original no existe: {DB_FW_CONFLICTS}")
            return False
        con_origen = sqlite3.connect(DB_FW_CONFLICTS)
        con_destino = sqlite3.connect(DB_FW_OPTIMIZED)
        con_origen.backup(con_destino)
        con_origen.close()
        con_destino.close()
        # print(f"Copia creada correctamente en: {DB_FW_OPTIMIZED}")
        return True
    except Exception as e:
        print(f"Error al crear copia de seguridad con backup(): {e}")
        return False
    
def erase_optimized_db():
    try:
        conn = sqlite3.connect(DB_FW_OPTIMIZED)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM firewall_conflict_rules;")
        conn.commit()

        # cursor.execute("SELECT * FROM firewall_conflict_rules;")
        # rows = cursor.fetchall()

        # if not rows:
        #     print("⚠️ No hay conflictos en la tabla 'firewall_conflict_rules'.")
        # else:
        #     print(f"📋 Conflictos encontrados en '{DB_FW_OPTIMIZED}':")
        #     for row in rows:
        #         print(row)

        # print(f"✅ Tabla 'firewall_conflict_rules' limpiada en: {DB_FW_OPTIMIZED}")
    except Exception as e:
        print(f"Error al limpiar la tabla: {e}")
    finally:
        conn.close()


# ----------- PDF EXPORT FUNCTION -----------

# def generate_conflictive_paragraphs(conflictive_rules_text):
#     styles = getSampleStyleSheet()
#     justified_style = ParagraphStyle(
#         name="JustifiedStyle",
#         parent=styles["Normal"],
#         fontName="Helvetica",
#         fontSize=10,
#         leading=15,
#         alignment=TA_JUSTIFY,
#     )
#     return [Paragraph(f"- <b>Conflict {i+1}. </b> {line}", justified_style) for i, line in enumerate(conflictive_rules_text)]

def generate_conflictive_paragraphs(conflictive_rules_text):
    styles = getSampleStyleSheet()
    justified_style = ParagraphStyle(
        name="JustifiedStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=15,
        alignment=TA_JUSTIFY,
    )

    header = (
        "<b>Campos:</b> ID, ID Regla Superior (R1), ID Regla Inferior (R2), Origen R1, Origen R2, "
        "Destino R1, Destino R2, Servicio R1, Servicio R2, Acción R1, Acción R2, "
        "Hits R1, Hits R2, Estado R1, Estado R2, Tipo de conflicto, Criticidad"
    )

    paragraphs = [Paragraph(header, justified_style)]
    paragraphs += [
        Paragraph(f"- <b>Conflict {i+1}.</b> {line}", justified_style)
        for i, line in enumerate(conflictive_rules_text)
    ]
    return paragraphs

def export_pdf(filename, optimization_sections, graph_before_path, graph_after_path, author="", date_str=None):
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4
    margin = 50

    # --- COVER PAGE with custom layout ---
    try:
        logo = ImageReader(PLANCIBER_LOGO)
        image_width = 150
        image_height = 90
        # image_x = (width - image_width) / 2
        image_x = 30
        image_y = height - 80
        c.drawImage(logo, image_x, image_y, width=image_width, height=image_height, preserveAspectRatio=True, mask='auto')

    except Exception as e:
        print(f"Warning: Logo load failed: {e}")

    try:
        portada_img = ImageReader(PLANCIBER_PORTADA_IMG)
        image_width = 650
        image_height = 420
        image_x = (width - image_width) / 2
        image_y = height - 600
        c.drawImage(portada_img, image_x, image_y, width=image_width, height=image_height, preserveAspectRatio=True, mask='auto')
    except Exception as e:
        print(f"Warning: Cover image load failed: {e}")

    # Author name top right (italic + light gray)
    if author:
        c.setFont("Helvetica-Oblique", 8)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawRightString(width - margin, height - 30, f"Author: {author}")
        c.setFillColorRGB(0, 0, 0)

    # Text block aligned to left, bottom
    y = 140
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "Firewall Rule Optimization Report")
    y -= 20
    c.setFont("Helvetica", 12)
    c.setFillColorRGB(0.2, 0.6, 0.2)
    c.drawString(margin, y, "Cybersecurity Department")
    y -= 20
    c.setFillColorRGB(0, 0, 0)
    c.drawString(margin, y, f"{date_str or datetime.today().strftime('%B %Y')}")

    # Confidential label in red
    c.setFont("Helvetica-Bold", 10)
    c.setFillColorRGB(1, 0, 0)
    c.drawRightString(width - margin, 80, "CONFIDENTIAL")

    c.setFillColorRGB(0, 0, 0)

    # Graph BEFORE optimization
    if graph_before_path:
        c.showPage()
        c.setFont("Helvetica-Bold", 14)
        c.drawString(margin, height - margin, "Conflict Graph (Before Optimization)")
        img = ImageReader(graph_before_path)
        
        c.drawImage(img, margin, 100, width=width - 2 * margin, preserveAspectRatio=True, mask='auto')

        # Agregar las reglas conflictivas justo debajo
        y = 400
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Detected Conflictive Rules")
        y -= 15
        c.setFont("Helvetica", 9)
        conflictive_rules = display_conflictive_rules()

        # header = "ID, ID Regla Superior (R1), ID Regla Inferior (R2), Origen R1, Origen R2, Destino R1, Destino R2, Servicio R1, Servicio R2, Acción R1, Acción R2, Hits R1, Hits R2, Estado R1, Estado R2, Tipo de conflicto, Criticidad"
        # c.setFont("Helvetica", 9)
        # c.drawString(margin, y, "Campos: " + header)
        # y -= 15

        paragraphs = generate_conflictive_paragraphs(conflictive_rules)

        # Crear un frame que ocupa el resto de la página desde y hasta el margen inferior
        frame = Frame(margin, 80, width - 2 * margin, y - 70, showBoundary=0)

        for paragraph in paragraphs:
            if frame.add(paragraph, c) == 0:
                c.showPage()
                frame = Frame(margin, 80, width - 2 * margin, height - 2 * margin, showBoundary=0)
                frame.add(paragraph, c)

    # --- OPTIMIZATION SECTIONS ---
    styles = getSampleStyleSheet()

    justified_style = ParagraphStyle(
        name="Justified",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        alignment=TA_JUSTIFY,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        name="Bullet",
        parent=justified_style,
        leftIndent=12,
        bulletIndent=0,
        bulletFontName="Helvetica",
        bulletFontSize=10,
    )

    optimization_title_style = ParagraphStyle(
        name="OptimizationTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        spaceAfter=12,
        spaceBefore=12
    )

    for section_title, lines in optimization_sections.items():
        c.showPage()
        frame = Frame(margin, margin, width - 2 * margin, height - 2 * margin, showBoundary=0)
        content = []

        content.append(Paragraph(section_title, optimization_title_style))
        content.append(Spacer(1, 10))

        for line in lines:
            if not line.strip():
                content.append(Spacer(1, 10))
                continue

            # Solo "OPTIMIZATION:" en negrita
            if line.strip().startswith("OPTIMIZATION:"):
                bolded_line = line.replace("OPTIMIZATION:", "<b>OPTIMIZATION:</b>", 1)
                content.append(Paragraph(bolded_line.strip(), justified_style))
            elif "Component" in line:
                content.append(Paragraph(f"→ {line.strip()}", bullet_style))
            else:
                content.append(Paragraph(line.strip(), justified_style))

            content.append(Spacer(1, 4))

        # frame.addFromList(content, c)
        for paragraph in content:
            if frame.add(paragraph, c) == 0:
                c.showPage()
                frame = Frame(margin, margin, width - 2 * margin, height - 2 * margin, showBoundary=0)
                frame.add(paragraph, c)

    # Graph AFTER optimization
    if graph_after_path:
        c.showPage()
        c.setFont("Helvetica-Bold", 14)
        c.drawString(margin, height - margin, "Conflict Graph (After Optimization)")
        img = ImageReader(graph_after_path)
        c.drawImage(img, margin, 100, width=width - 2 * margin, preserveAspectRatio=True, mask='auto')

    c.save()

def export_json(optimized_rules):
    """
    Exporta las reglas optimizadas a JSON usando una plantilla base para completar los campos faltantes.
    """
    # Cargar plantilla base desde el archivo JSON
    with open(JSON_FILE_PATH, "r", encoding="utf-8") as f:
        default_template = json.load(f)
        if isinstance(default_template, list):
            default_template = default_template[0]  # Extrae el primer elemento si es lista

    final_rules = []

    for rule in optimized_rules:
        # Copiar la plantilla como base
        full_rule = deepcopy(default_template)

        # Sobrescribir campos con los datos de la regla optimizada
        for key, value in rule.items():
            full_rule[key] = value

        # Asegurar campos consistentes en nomenclatura
        if "Source" in rule:
            full_rule["Source Address"] = rule["Source"]
        if "Destination" in rule:
            full_rule["Destination Address"] = rule["Destination"]

        # Añadir al resultado
        final_rules.append(full_rule)

    # Exportar al archivo JSON
    with open(OPTIMIZED_JSON_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(final_rules, f, indent=4)

    print(f"✅ Reglas exportadas correctamente a {OPTIMIZED_JSON_FILE_PATH}")