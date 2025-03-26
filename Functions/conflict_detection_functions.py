#from Functions.file_management_functions import load_rules_from_file
from Functions.config import STRICT_POLICY_INSECURE_PROTOCOLS, CRITICALITY
from typing import List, Dict, Union
import ipaddress, re, logging

# ************************************************************************** #
# ******************* GENERAL RULE DETECTION FUNCTIONS: ******************** #
# ************************************************************************** #
def expand_ips(ip_str):    
    ip_str = ip_str.strip()

    if ip_str.upper() == "ANY" or ip_str.upper() == "ALL":
        return ipaddress.ip_network("0.0.0.0/0", strict=False)
    
    if ',' in ip_str:  # Caso de lista de IPs separadas por coma
        #print({ipaddress.ip_address(ip.strip()) for ip in ip_str.split(",")})
        return {ipaddress.ip_address(ip.strip()) for ip in ip_str.split(",")}
    
    if '/' in ip_str:
        return ipaddress.ip_network(ip_str, strict=False)
    
    match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)", ip_str)
    if match:
        start_ip = ipaddress.ip_address(match.group(1))
        end_ip = ipaddress.ip_address(match.group(2))
        #print({ipaddress.ip_address(ip) for ip in range(int(start_ip), int(end_ip) + 1)})
        return {ipaddress.ip_address(ip) for ip in range(int(start_ip), int(end_ip) + 1)}
    
    return {ipaddress.ip_address(ip_str)}

def is_subnet_of(subnet1: str, subnet2: str) -> Union[bool, str]:
    """Verifica si subnet1 está completamente o parcialmente contenida dentro de subnet2.
       Retorna:
       - True si subnet1 está completamente contenida en subnet2.
       - 'partial' si subnet1 solo tiene una coincidencia parcial con subnet2.
       - False si no hay coincidencia.
    """
    try:
        net1 = expand_ips(subnet1)
        net2 = expand_ips(subnet2)

        # Caso en el que ambos son subredes
        if isinstance(net1, ipaddress.IPv4Network) and isinstance(net2, ipaddress.IPv4Network):
            if net1.overlaps(net2) or net2.overlaps(net1):
                return True if net1 == net2 else "Partial"

        # Caso en el que subnet1 es una lista de IPs o rango y subnet2 es una subred
        if isinstance(net1, set) and isinstance(net2, ipaddress.IPv4Network):
            if all(ip in net2 for ip in net1):  
                return True
            elif any(ip in net2 for ip in net1):  
                return "Partial"

        # Caso en el que subnet2 es un conjunto de IPs y subnet1 es una subred o IP individual
        if isinstance(net2, set) and isinstance(net1, ipaddress.IPv4Network):
            if all(ip in net1 for ip in net2):  
                return True
            elif any(ip in net1 for ip in net2):  
                return "Partial"

        # Caso en el que ambas son listas de IPs
        if isinstance(net1, set) and isinstance(net2, set):
            intersection = net1 & net2
            if intersection == net1:  # Todas las IPs de subnet1 están en subnet2
                return True
            elif intersection:  # Hay coincidencia parcial
                return "Partial"

        return False
    except ValueError:
        return False


def is_port_range_subset(port1, port2):
    """Verifica si el puerto2 está dentro del rango de puerto1."""
    def expand_ports(port):
        """Convierte una cadena de puertos en un conjunto de enteros."""
        if port == "ALL":
            port = "ANY"
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
    if ports1 == "ANY":
        return True  # "ANY" incluye todos los puertos

    if isinstance(ports1, set) and isinstance(ports2, set):
        if ports2.issubset(ports1):  # Todos los puertos de ports2 están en ports1
            return True
        elif ports1 & ports2:  # Hay intersección pero ports2 no está completamente en ports1
            return "Partial"
    return False
# ************************************************************************** #
# ****************** REDUNDANT RULE DETECTION FUNCTIONS: ******************* #
# ************************************************************************** #

def is_redundant(rule1: Dict, rule2: Dict) -> bool:
    logging.info("FUNCTION: is_redundant()")

    if "Enabled" in rule1.get("Status", "") and "Enabled" in rule2.get("Status", ""):
        source_match = is_subnet_of(rule1.get("Source")[0], rule2.get("Source")[0])
        # print(f"Source_match: {source_match}")
        destination_match = is_subnet_of(rule1.get("Destination")[0], rule2.get("Destination")[0])
        # print(f"Destination_match: {destination_match}")
        service_match = is_port_range_subset(rule1.get("Service")[0], rule2.get("Service")[0]) 
        # print(f"Service_match: {service_match}")
        action_match = rule1["Action"] == rule2["Action"]
        # print(f"Action_match: {action_match}")
        return source_match and destination_match and service_match and action_match
    else: 
        return False
    
# ************************************************************************** #
# ********************** 'ANY' DETECTION FUNCTIONS: ************************ #
# ************************************************************************** #
def rule_have_x_any(rule):
    logging.info("FUNCTION: rule_have_x_any()")

    quantity = 0
    have_any = False
    conflict_type = ""
    if "Enabled" in rule.get("Status", ""):
        if "ANY" in rule["Source"] or "ALL" in rule["Source"]:
            quantity += 1
            have_any = True
            conflict_type = "Any: Origin"
        if "ANY" in rule["Destination"] or "ALL" in rule["Destination"]:
            quantity += 1
            have_any = True
            conflict_type = "Any: Destination"
        if "ANY" in rule["Service"] or "ALL" in rule["Service"]:
            quantity += 1
            have_any = True
            conflict_type = "Any: Application/protocol"
        if quantity == 2:
            conflict_type = "Any: 2 fields"
        if quantity == 3:
            conflict_type = "Any: 3 fields"
    return have_any, conflict_type
    
# ************************************************************************** #
# ****************** INSECURE RULE DETECTION FUNCTIONS: ******************** #
# ************************************************************************** #
def have_insecure_protocols(rule):
    logging.info("FUNCTION: have_insecure_protocols()")

    """Verifica si una regla contiene servicios considerados inseguros."""
    if "Enabled" in rule.get("Status", ""):
        if "ACCEPT" in rule.get("Action") or "ALLOW" in rule.get("Action"):
            for service in rule["Service"]:
                if service == "ANY" or service == "ALL":
                    return True
                for protocol, port in STRICT_POLICY_INSECURE_PROTOCOLS.items():
                    if is_port_range_subset(service, str(port)):
                        return True
    return False

# ************************************************************************** #
# **************** LAST RULE DENY ALL DETECTION FUNCTIONS: ***************** #
# ************************************************************************** #
def is_remaining_traffic_denied(rule):
    logging.info("FUNCTION: is_remaining_traffic_denied()")

    #if "Enabled" in rule.get("Status", ""):
    if "Enabled" in rule["Status"]:
        if rule["Action"].upper() != "DENY":
            return False
        if ("ANY" in rule["Source"] or "ALL" in rule["Source"]) and \
           ("ANY" in rule["Destination"] or "ALL" in rule["Destination"]) and \
           ("ANY" in rule["Service"] or "ALL" in rule["Service"]):
            return True

    return False  



# ************************************************************************** #
# ****************** DISABLED RULES DETECTION FUNCTION: ******************** #
# ************************************************************************** #
def is_disabled(rule):
    logging.info("FUNCTION: is_disabled()")

    if "Disabled" in rule.get("Status", "").strip():
        return True
    else:
        return False

# ************************************************************************** #
# ******************** NOT IN USE DETECTION FUNCTION: ********************** #
# ************************************************************************** #
def is_not_in_use(rule) -> bool:
    logging.info("FUNCTION: is_not_in_use()")

    if "Enabled" in rule.get("Status", ""):
        if rule["Hit Count"] == 0:
            return True
        else:
            return False
    
# ************************************************************************** #
# ******************* SHADOW RULE DETECTION FUNCTION: ********************** #
# ************************************************************************** #
def is_shadowed(rule_lower: Dict, rule_upper: Dict):
    logging.info("FUNCTION: is_shadowed()")
    #print(rule_lower.get("ID"))
    #print(rule_upper.get("ID"))

    """
    Determina si la regla `rule_lower` está opacada por la regla `rule_upper`.
    """
    if "Enabled" in rule_lower.get("Status", "") and "Enabled" in rule_upper.get("Status", ""):
        action_lower = rule_lower['Action']
        action_upper = rule_upper['Action']
        # print(rule_lower.get("Source"))
        # print(rule_lower.get("Source"))
        # print(rule_lower['Source'][0])

        ip_src_relation = is_subnet_of(rule_lower['Source'][0], rule_upper['Source'][0])
        # print(f"IP src relation: {ip_src_relation}")
        ip_dst_relation = is_subnet_of(rule_lower['Destination'][0], rule_upper['Destination'][0])
        # print(f"IP src relation: {ip_dst_relation}")
        port_relation = is_port_range_subset(rule_lower['Service'][0], rule_upper['Service'][0])
        # print(f"IP src relation: {port_relation}")

        if ip_src_relation and ip_dst_relation and port_relation:
            if any(isinstance(value, str) and "Partial" in value for value in [ip_src_relation, ip_dst_relation, port_relation]):
                return True, "Partially Shadowed" 
            return True, "Fully Shadowed"
    return False, "Not Shadowed"