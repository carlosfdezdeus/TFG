import os

INPUT_DATA_DIR = "Input data"
OUTPUT_DATA_DIR = "Output data"
DATABASES_DIR = "Databases"
DB_FW_RULES = os.path.join(DATABASES_DIR, "firewall_rules.db")
DB_FW_CONFLICTS = os.path.join(DATABASES_DIR, "firewall_conflict_rules.db")
#DB_FW_CONFLICTS = os.path.join(DATABASES_DIR, "prueba.db")
DB_FW_OPTIMIZED = os.path.join(DATABASES_DIR, "optimized_firewall_conflict_rules.db")

# JSON_FILE_PATH = os.path.join(INPUT_DATA_DIR, "reglas_ejemplo_memoria.json")
JSON_FILE_PATH = os.path.join(INPUT_DATA_DIR, "firewall_cliente_WiFi_rules.json")
# JSON_FILE_PATH = os.path.join(INPUT_DATA_DIR, "prueba_eficiencia_501.json")
# JSON_FILE_PATH = os.path.join(INPUT_DATA_DIR, "prueba_eficiencia_200.json")
OPTIMIZED_JSON_FILE_PATH = os.path.join(OUTPUT_DATA_DIR, "optimized_firewall_rules.json")
CONFLICT_GRAPH_PATH = os.path.join(OUTPUT_DATA_DIR, "conflict_graph.png")
OPTIMIZED_CONFLICT_GRAPH_PATH = os.path.join(OUTPUT_DATA_DIR, "optimized_conflict_graph.png")
REPORT = os.path.join(OUTPUT_DATA_DIR, "firewall_optimization_report.pdf")
PLANCIBER_LOGO = os.path.join(INPUT_DATA_DIR, "planciber_logo.jpeg")
PLANCIBER_PORTADA_IMG = os.path.join(INPUT_DATA_DIR, "planciber_portada.png")

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

# INSECURE_TO_SECURE_PROTOCOLS = {
#     "FTP": "FTPS/SFTP",
#     "Telnet": "SSH",
#     "SMTP (sin TLS)": "SMTPS",
#     "DNS Zone Transfer (AXFR)": "DNSSEC",
#     "HTTP": "HTTPS",
#     "POP3": "POP3S",
#     "NTP (monlist habilitado)": "NTS",
#     "IMAP": "IMAPS",
#     "SNMPv1/v2c": "SNMPv3",
#     "LDAP (sin TLS)": "LDAPS",
#     "SMBv1": "SMBv3",
#     "Rlogin": "SSH",
#     "Rsh": "SSH",
#     "Syslog (UDP)": "Syslog sobre TLS",
#     "LPR/LDP": "IPP sobre HTTPS",
#     "RIP v1": "RIPng/OSPF/BGP"
#     # Protocolos sin versión segura no se incluyen
# }

# SECURE_PROTOCOL_PORTS = {
#     "FTPS": 990,
#     "SFTP": 22,
#     "SSH": 22,
#     "SMTPS": 465,
#     "DNSSEC": 53,
#     "HTTPS": 443,
#     "POP3S": 995,
#     "IMAPS": 993,
#     "SNMPv3": "161/162",
#     "LDAPS": 636,
#     "SMBv3": 445,
#     "Syslog sobre TLS": 6514,
#     "IPP sobre HTTPS": 631,
#     "RIPng": 521,
#     "OSPF": 89,
#     "BGP": 179,
#     "NTS": 123
# }


CRITICALITY = {
    "Not in use": "Low",
    "Disabled": "Low",
    "Redundant": "Low",

    "Fully Shadowed": "High",
    "Partially Shadowed": "Medium",
    "Bidirectional": "Medium",
    # "Any: Application/protocol": "Medium",
    "Any: Service": "Medium",
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
    "Fully Shadowed": ("solid", "red"),
    "Partially Shadowed": ("solid", "orange")
}

# Asignación de colores para conflictos con NULL
UNARY_CONFLICT_COLORS = {
    "Not in use": "green",
    "Disabled": "green",
    "Bidirectional": "orange",
    "Any: Service": "orange",
    "Any: Origin": "orange",
    "Any: Destination": "red",
    "Insecure": "red",
    "Any: 2 fields": "black",
    "Any: 3 fields": "black",
    "Remaining traffic not denied": "black"
}
