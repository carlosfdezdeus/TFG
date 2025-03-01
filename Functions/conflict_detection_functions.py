#from Functions.file_management_functions import load_rules_from_file
from Functions.config import STRICT_POLICY_INSECURE_PROTOCOLS
from typing import List, Dict
import ipaddress

# ************************************************************************** #
# ******************* GENERAL RULE DETECTION FUNCTIONS: ******************** #
# ************************************************************************** #

def is_subnet_of(subnet1: str, subnet2: str) -> bool:
    try:
        if "ANY" in subnet1:
            subnet1 = "0.0.0.0/0"
        if "ANY" in subnet2:
            subnet2 = "0.0.0.0/0"
        net1 = ipaddress.IPv4Network(subnet1, strict=False)
        net2 = ipaddress.IPv4Network(subnet2, strict=False)
        return net1.overlaps(net2)
    except ValueError:
        return False
    
def is_port_range_subset(port1, port2):
    """Verifica si el puerto2 está dentro del rango de puerto1."""
    def expand_ports(port):
        """Convierte una cadena de puertos en un conjunto de enteros."""
        if port == "ANY":
            return "ANY"
        ports = set()
        if ',' in port:
            ports.update(int(p) for p in port.split(','))
        elif '-' in port:
            start, end = map(int, port.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(port))  # Caso de un solo puerto
        return ports

    ports1 = expand_ports(port1)
    ports2 = expand_ports(port2)

    if ports1 == "ANY":
        return True
    if isinstance(ports1, set) and isinstance(ports2, set):
        return not ports1.isdisjoint(ports2)  # Devuelve True si hay intersección
    return False
# ************************************************************************** #
# ****************** REDUNDANT RULE DETECTION FUNCTIONS: ******************* #
# ************************************************************************** #

def is_redundant(rule1: Dict, rule2: Dict) -> bool:
    source_match = all(any(is_subnet_of(src2, src1) for src1 in rule1["Source"]) for src2 in rule2["Source"])
    #print(f"Source_match: {source_match}")
    destination_match = all(any(is_subnet_of(dst2, dst1) for dst1 in rule1["Destination"]) for dst2 in rule2["Destination"])
    #print(f"Destination_match: {destination_match}")
    service_match = any(any(is_port_range_subset(srv1, srv2) or is_port_range_subset(srv2, srv1) for srv1 in rule1["Service"]) for srv2 in rule2["Service"])    # "ANY" hataa que service_match sea True en cualquiera de las reglas
    #print(f"Service_match: {service_match}")
    action_match = rule1["Action"] == rule2["Action"]
    #print(f"Action_match: {action_match}")
    return source_match and destination_match and service_match and action_match

def find_redundant_rules(rules: List[Dict]) -> List[Dict]:
    """Encuentra reglas redundantes en la lista de reglas."""
    redundant_rules = []
    for i, rule1 in enumerate(rules):
        for j, rule2 in enumerate(rules):
            if i != j and is_redundant(rule1, rule2):
                redundant_rules.append({"Redundant Rule": rule2, "Covered By": rule1})
    return redundant_rules

# ************************************************************************** #
# ********************** 'ANY' DETECTION FUNCTIONS: ************************ #
# ************************************************************************** #
def rule_have_x_any(rule):
    quantity = 0
    have_any = False
    if rule["Source"] == "ANY":
        quantity += 1
        have_any = True
    if rule["Destination"] == "ANY":
        quantity += 1
        have_any = True
    if rule["Service"] == "ANY":
        quantity += 1
        have_any = True
    return have_any, quantity

def find_any_in_rules(rules: List[Dict]) -> List[Dict]:
    rules_with_any = []
    for i, rule in enumerate(rules):
        have_any, quantity = rule_have_x_any(rule)
        if have_any:
            type_text = f"Rule {rule['ID']} has {quantity} anys"
            print(type_text)
            # meter en la BD con X anys
            rules_with_any.append(rule)  # Agregar la regla a la lista en lugar de un valor vacío
    return rules_with_any

# ************************************************************************** #
# ****************** INSECURE RULE DETECTION FUNCTIONS: ******************** #
# ************************************************************************** #
def have_insecure_protocols(rule):
    """Verifica si una regla contiene servicios considerados inseguros."""
    for service in rule["Service"]:
        for protocol, port in STRICT_POLICY_INSECURE_PROTOCOLS.items():
            if is_port_range_subset(service, str(port)):
                return True
    return False

def find_insecure_rules(rules: List[Dict]) -> List[Dict]:
    rules_with_insecure_protocols = []
    for i, rule in enumerate(rules):
        if(have_insecure_protocols()):
            rules_with_insecure_protocols.append()
    return rules_with_insecure_protocols

# ************************************************************************** #
# **************** LAST RULE DENY ALL DETECTION FUNCTIONS: ***************** #
# ************************************************************************** #
def is_remaining_traffic_denied(rules: List[Dict]) -> bool:
    """Verifica si la última regla bloquea todo el tráfico restante."""
    if not rules:
        return False
    
    last_rule = rules[-1]  # Última regla
    if last_rule["Action"].upper() != "DENY":
        return False
    
    if last_rule["Source"] == ["ANY"] and last_rule["Destination"] == ["ANY"] and last_rule["Service"] == ["ANY"]:
        return True
    
    return False