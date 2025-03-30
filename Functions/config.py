import os

INPUT_DATA_DIR = "Input data"
OUTPUT_DATA_DIR = "Output data"
DATABASES_DIR = "Databases"
#DB_FW_RULES = os.path.join(FILES_DIR, "firewall_rules.db")
DB_FW_CONFLICTS = os.path.join(DATABASES_DIR, "firewall_conflict_rules.db")
#JSON_FILE_PATH = os.path.join(FILES_DIR, "firewall_rules.json")
#JSON_FILE_PATH = os.path.join(FILES_DIR, "firewall_rules_final.json")
JSON_FILE_PATH = os.path.join(INPUT_DATA_DIR, "prueba.json")
CONFLICT_GRAPH_PATH = os.path.join(OUTPUT_DATA_DIR, "conflict_graph.pdf")
import ipaddress
from typing import Dict

STRICT_POLICY_INSECURE_PROTOCOLS = {
    "FTP": 21,
    "Telnet": 23,
    "SMTP (sin TLS)": 25,
    "DNS Zone Transfer (AXFR)": 53,  # TCP
    "TFTP": 69,
    "HTTP": 80,
    "POP3": 110,
    "NTP (monlist habilitado)": 123,
    "MSRPC": 135,
    "NetBIOS": "137-139",
    "IMAP": 143,
    "SNMPv1/v2c": "161,162",
    "LDAP (sin TLS)": 389,
    "SMBv1": 445,
    "Rlogin": 513,
    "Rsh": 514,
    "Syslog (UDP)": 514,
    "LPR/LDP": 515,
    "RIP v1": 520,
    "uPNP": 1900,
    "SSDP": 1900,
    "WSD": 3702,
    "mDNS": 5353
}

CRITICALITY = {
    "Not in use": "Low",
    "Disabled": "Low",
    "Redundant": "Low",

    "Fully Shadowed": "Medium",
    "Partially Shadowed": "Medium",
    "Bidirectional": "Medium",
    "Any: Application/protocol": "Medium",
    "Any: Origin": "Medium",

    "Any: Destination": "High",
    "Insecure": "High",

    "Any: 2 fields": "Critical",
    "Any: 3 fields": "Critical",
    "Remaining traffic not denied": "Critical"
}

# Estilos para los tipos de conflicto entre nodos
CONFLICT_LINE_STYLES = {
    "Redundant": ("solid", "green"),
    "Fully Shadowed": ("dashed", "orange"),
    "Partially Shadowed": ("dotted", "orange")
}

# Asignación de colores para conflictos con NULL
UNARY_CONFLICT_COLORS = {
    "Not in use": "green",
    "Disabled": "green",
    "Bidirectional": "orange",
    "Any: Application/protocol": "orange",
    "Any: Origin": "orange",
    "Any: Destination": "red",
    "Insecure": "red",
    "Any: 2 fields": "black",
    "Any: 3 fields": "black",
    "Remaining traffic not denied": "black"
}
