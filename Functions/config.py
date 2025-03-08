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

CONFLICT_STYLES = {
    # Low - Verde
    "Not in use": {"color": "green", "style": "-"},  # Línea sólida
    "Disabled": {"color": "green", "style": "--"},  # Línea discontinua
    "Redundant": {"color": "green", "style": "-."},  # Línea punteada

    # Medium - Amarillo
    "Fully Shadowed": {"color": "orange", "style": "-"},  # Línea sólida
    "Partially Shadowed": {"color": "orange", "style": "--"},  # Línea discontinua
    "Bidirectional": {"color": "orange", "style": "-."},  # Línea punteada
    "Any: Application/protocol": {"color": "orange", "style": ":"},  # Línea de puntos
    "Any: Origin": {"color": "orange", "style": (0, (3, 1, 1, 1))},  # Patrón personalizado (línea segmentada)

    # High - Rojo
    "Any: Destination": {"color": "red", "style": "-"},  # Línea sólida
    "Insecure": {"color": "red", "style": "--"},  # Línea discontinua

    # Critical - Negro
    "Any: 2 fields": {"color": "black", "style": "-"},  # Línea de puntos
    "Any: 3 fields": {"color": "black", "style": "-."},  # Línea punteada
    "Remaining traffic not denied": {"color": "black", "style": "-."},  # Línea discontinua
}
