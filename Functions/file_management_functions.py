from config import DB_FW_CONFLICTS, DB_FW_RULES
import json, sqlite3
from typing import List, Dict


def load_rules_from_file(filename: str) -> List[Dict]:
    """Carga todas las reglas desde un archivo JSON en una lista de diccionarios."""
    with open(filename, 'r') as file:
        json_data = json.load(file)
    
    rules = []
    for index, entry in enumerate(json_data, start=1):
        rule = {
            "ID": entry["ID"],  
            "Policy": entry["Policy"],
            "Source": entry["Source"],
            "Destination": entry["Destination"],
            "Schedule": entry["Schedule"],
            "Service": entry["Service"],
            "Action": entry["Action"],
            "Log": entry["Log"],
            "Application Control": entry["Application Control"],
            "Comments": entry["Comments"],
            "Hit Count": entry["Hit Count"]
        }
        rules.append(rule)
    
    return rules

def create_conflict_database():
    conn = sqlite3.connect(DB_FW_RULES)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS firewall_conflicts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        id_rule_1 TEXT,
                        id_rule_2 TEXT,
                        source_rule_1 TEXT,
                        source_rule_2 TEXT,
                        destination_rule_1 TEXT,
                        destination_rule_2 TEXT,
                        service TEXT,
                        action_rule_1 TEXT,
                        action_rule_2 TEXT,
                        conflict_type TEXT,      -- Tipo de conflicto (redundante, shadowed, any, etc.)
                        permissiveness TEXT,     -- any, ranges
                        shadowed TEXT,           -- fully, partially
                        violations TEXT,         -- Políticas de seguridad violadas
                        hit_count INTEGER,       -- Número de veces que la regla ha sido utilizada
                        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Fecha de detección del conflicto
                        first_used TIMESTAMP,    -- Primera vez que se usó la regla
                        last_used TIMESTAMP      -- Última vez que se usó la regla)
    ''')
    conn.commit()
    conn.close()

def insert_firewall_rule(rule):
    conn = sqlite3.connect(DB_FW_RULES)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO firewall_rules (
                policy, source, destination, schedule, service, action, ip_pool, nat, type,
                security_profiles, log, bytes, active_sessions, application_control, av, comments,
                cpu_bytes, cpu_packets, destination_address, dns_filter, email_filter, file_filter,
                groups, hit_count, inspection_mode, ips, name, nturbo_bytes, nturbo_packets,
                packets, protocol_options, source_address, spu_bytes, spu_packets,
                ssl_inspection, status, users, vpn_tunnel, web_filter, interface_pair
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule["Policy"], json.dumps(rule["Source"]), json.dumps(rule["Destination"]), json.dumps(rule["Schedule"]),
            json.dumps(rule["Service"]), rule["Action"], json.dumps(rule["IP Pool"]), rule["NAT"], rule["Type"],
            json.dumps(rule["Security Profiles"]), rule["Log"], rule["Bytes"], rule["Active Sessions"],
            json.dumps(rule["Application Control"]), json.dumps(rule["AV"]), rule["Comments"],
            rule["CPU Bytes"], rule["CPU Packets"], json.dumps(rule["Destination Address"]),
            json.dumps(rule["DNS Filter"]), json.dumps(rule["Email Filter"]), json.dumps(rule["File Filter"]),
            json.dumps(rule["Groups"]), rule["Hit Count"], rule["Inspection Mode"], json.dumps(rule["IPS"]),
            rule["Name"], rule["nTurbo Bytes"], rule["nTurbo Packets"], rule["Packets"],
            json.dumps(rule["Protocol Options"]), json.dumps(rule["Source Address"]), rule["SPU Bytes"],
            rule["SPU Packets"], json.dumps(rule["SSL Inspection"]), rule["Status"], json.dumps(rule["Users"]),
            json.dumps(rule["VPN Tunnel"]), json.dumps(rule["Web Filter"]), rule["Interface Pair"]
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        print(f"Regla con policy '{rule['Policy']}' ya existe en la base de datos.")
    finally:
        conn.close()