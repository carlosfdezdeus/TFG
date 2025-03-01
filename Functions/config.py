import os

FILES_DIR = "Files"
DB_FW_RULES = os.path.join(FILES_DIR, "firewall_rules.db")
DB_FW_CONFLICTS = os.path.join(FILES_DIR, "firewall_conflict_rules.db")
#JSON_FILE_PATH = os.path.join(FILES_DIR, "firewall_rules.json")
#JSON_FILE_PATH = os.path.join(FILES_DIR, "firewall_rules_final.json")
JSON_FILE_PATH = os.path.join(FILES_DIR, "firewall_rules_dyc.json")
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