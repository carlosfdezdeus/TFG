#from Functions.file_management_functions import load_rules_from_file
from Functions.config import STRICT_POLICY_INSECURE_PROTOCOLS, CRITICALITY
from typing import List, Dict, Union
import ipaddress, re, logging

# ************************************************************************** #
# ******************* GENERAL RULE DETECTION FUNCTIONS: ******************** #
# ************************************************************************** #
import ipaddress
import re
from typing import Union

def expand_ips(ip_str: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv4Network, set]:
    ip_str = ip_str.strip()

    if ip_str.upper() in {"ANY", "ALL"}:
        # print(f"RESULTADO expand_ips: {ipaddress.ip_network('0.0.0.0/0', strict=False)}")

        return ipaddress.ip_network("0.0.0.0/0", strict=False)

    # Separar por coma si hay múltiples partes
    parts = [part.strip() for part in ip_str.split(",")]
    # print(parts)
    result = set()
    mixed_input = len(parts) > 1

    if len(parts) == 1:
        part = parts[0]

        # Rango de IPs
        range_match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)", part)
        if range_match:
            start_ip = ipaddress.ip_address(range_match.group(1))
            end_ip = ipaddress.ip_address(range_match.group(2))
            return {ipaddress.ip_address(ip) for ip in range(int(start_ip), int(end_ip) + 1)}

        # Subred
        if '/' in part:
            return ipaddress.ip_network(part, strict=False)

        # IP
        return ipaddress.ip_address(part)
        

    # Si hay múltiples entradas separadas por coma
    for part in parts:
        # Rango
        range_match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)", part)
        if range_match:
            start_ip = ipaddress.ip_address(range_match.group(1))
            end_ip = ipaddress.ip_address(range_match.group(2))
            result.update(ipaddress.ip_address(ip) for ip in range(int(start_ip), int(end_ip) + 1))
            continue

        # Subred
        if '/' in part:
            result.add(ipaddress.ip_network(part, strict=False))
            continue

        # IP individual
        result.add(ipaddress.ip_address(part))

    # print(f"RESULTADO expand_ips_v2: {result}")
    return result

def is_subnet_of(subnet1: str, subnet2: str) -> Union[bool, str]:
    """
    Evalúa si subnet2 está completamente o parcialmente contenida dentro de subnet1.
    Retorna:
    - True si subnet2 está completamente contenida en subnet1.
    - 'Partial' si subnet2 solapa parcialmente con subnet1.
    - False si no hay solapamiento.
    """
    try:
        net1 = expand_ips(subnet1)
        net2 = expand_ips(subnet2)

        # Caso especial: alguno de los dos es 0.0.0.0/0
        def is_zero_net(obj):
            return isinstance(obj, ipaddress.IPv4Network) and obj.prefixlen == 0

        if is_zero_net(net1) and is_zero_net(net2):
            return True  # Son iguales

        if is_zero_net(net1):
            return True  # net1 incluye todo

        if is_zero_net(net2):
            if isinstance(net1, ipaddress.IPv4Network):
                return True if net2.subnet_of(net1) else "Partial"
            elif isinstance(net1, set):
                return "Partial"
            else:
                return "Partial"

        # Caso base: objetos individuales
        if isinstance(net1, (ipaddress.IPv4Network, ipaddress.IPv4Address)) and isinstance(net2, (ipaddress.IPv4Network, ipaddress.IPv4Address)):
            if isinstance(net1, ipaddress.IPv4Network):
                if isinstance(net2, ipaddress.IPv4Network):
                    if net2.subnet_of(net1):
                        return True
                    elif net1.overlaps(net2):
                        return "Partial"
                elif isinstance(net2, ipaddress.IPv4Address):
                    return True if net2 in net1 else False
            elif isinstance(net1, ipaddress.IPv4Address):
                if isinstance(net2, ipaddress.IPv4Network):
                    return "Partial" if net1 in net2 else False
                elif isinstance(net2, ipaddress.IPv4Address):
                    return True if net1 == net2 else False

        # Caso: set vs objeto
        if isinstance(net1, set) and isinstance(net2, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
            inside = 0
            total = len(net1)
            for elem in net1:
                if isinstance(net2, ipaddress.IPv4Address):
                    if isinstance(elem, ipaddress.IPv4Address) and elem == net2:
                        return True
                    elif isinstance(elem, ipaddress.IPv4Network) and net2 in elem:
                        return True
                elif isinstance(net2, ipaddress.IPv4Network):
                    if isinstance(elem, ipaddress.IPv4Address) and elem in net2:
                        inside += 1
                    elif isinstance(elem, ipaddress.IPv4Network):
                        if elem.overlaps(net2):
                            if elem.subnet_of(net2):
                                inside += 1
                            else:
                                return "Partial"
            if inside == total and total > 0:
                return True
            elif inside > 0:
                return "Partial"
            else:
                return False

        # Caso: objeto vs set (aquí estaba el error corregido)
        if isinstance(net2, set) and isinstance(net1, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
            inside = 0
            total = len(net2)
            for elem in net2:
                if isinstance(net1, ipaddress.IPv4Network):
                    if isinstance(elem, ipaddress.IPv4Address) and elem in net1:
                        inside += 1
                    elif isinstance(elem, ipaddress.IPv4Network):
                        if elem.overlaps(net1):
                            if elem.subnet_of(net1):
                                inside += 1
                            else:
                                return "Partial"
                elif isinstance(net1, ipaddress.IPv4Address):
                    if isinstance(elem, ipaddress.IPv4Address) and elem == net1:
                        inside += 1
                    elif isinstance(elem, ipaddress.IPv4Network) and net1 in elem:
                        inside += 1  # 🔧 FIX APLICADO AQUÍ
            if inside == total and total > 0:
                return True
            elif inside > 0:
                return "Partial"
            else:
                return False

        # Ambos son conjuntos
        if isinstance(net1, set) and isinstance(net2, set):
            if net2 <= net1:
                return True
            elif net1 & net2:
                return "Partial"
            else:
                return False

        return False

    except ValueError:
        return False

# def expand_ports(port):
#         """Convierte una cadena de puertos en un conjunto de enteros."""
#         print(port)
#         if port == "ALL":
#             port = "ANY"
#         if port == "ANY":
#             return "ANY"
#         ports = set()
#         if ',' in port:
#             ports.update(int(p) for p in port.split(','))
#         elif '-' in port:
#             start, end = map(int, port.split('-'))
#             ports.update(range(start, end + 1))
#         else:
#             ports.add(int(port))  # Caso de un solo puerto
#         return ports

def expand_ports(port):
    """Convierte una cadena de puertos en un conjunto de enteros o marca 'ANY'."""
    if not isinstance(port, str):
        port = str(port)

    port = port.strip().upper()
    
    if port == "ALL" or port == "ANY":
        return {"ANY"}  # usar set con valor especial para tratarlo luego

    ports = set()
    try:
        for p in port.split(','):
            p = p.strip()
            if '-' in p:
                start, end = map(int, p.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(p))
    except ValueError:
        # Aquí puedes registrar un warning si quieres saber qué puerto falló
        # por ejemplo: logger.warning(f"Puerto inválido detectado: {p}")
        pass  # ignorar entrada no válida

    return ports


def is_port_range_subset(port1, port2):
    """Verifica si el puerto2 está dentro del rango de puerto1."""
    # print(port1)
    ports1 = expand_ports(port1)
    # print(ports1)
    # print(port2)
    ports2 = expand_ports(port2)
    # print(ports2)

    if ports1 == "ANY":
        return True
    if ports2 == "ANY":
        return "Partial"  # "ANY" incluye todos los puertos

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
    # logging.info("FUNCTION: is_redundant()")

    if "Enabled" in rule1.get("Status", "") and "Enabled" in rule2.get("Status", ""):
        source_match = all(any(is_subnet_of(src2, src1) for src1 in rule1["Source"]) for src2 in rule2["Source"])
        # print(f"Source_match: {source_match}")
        destination_match = all(any(is_subnet_of(dst2, dst1) for dst1 in rule1["Destination"]) for dst2 in rule2["Destination"])
        # print(f"Destination_match: {destination_match}")
        service_match = any(any(is_port_range_subset(srv1, srv2) or is_port_range_subset(srv2, srv1) for srv1 in rule1["Service"]) for srv2 in rule2["Service"])    # "ANY" hataa que service_match sea True en cualquiera de las reglas
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
    if "Enabled" in rule.get("Status", "") and "ALLOW" in rule.get("Action", "").upper():
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
            conflict_type = "Any: Service"

        if quantity == 2:
            conflict_type = "Any: 2 fields"
        if quantity == 3:
            conflict_type = "Any: 3 fields"
    return have_any, conflict_type
    
# ************************************************************************** #
# ****************** INSECURE RULE DETECTION FUNCTIONS: ******************** #
# ************************************************************************** #
# def have_insecure_protocols(rule):
#     logging.info("FUNCTION: have_insecure_protocols()")
#     print(rule)

#     """Verifica si una regla contiene servicios considerados inseguros."""
#     if "Enabled" in rule.get("Status", ""):
#         if "ACCEPT" in rule.get("Action") or "ALLOW" in rule.get("Action"):
#             for service in rule["Service"]:
#                 print(f"Service: {service}")
#                 if service == "ANY" or service == "ALL":
#                     return True
#                 for protocol, port in STRICT_POLICY_INSECURE_PROTOCOLS.items():
#                     if is_port_range_subset(service, str(port)):
#                         return True
#     return False

def have_insecure_protocols(rule):
    logging.info("FUNCTION: have_insecure_protocols()")
    # print(rule)

    """Verifica si una regla contiene servicios considerados inseguros."""
    if "Enabled" in rule.get("Status", "").capitalize():
        if rule.get("Action", "").upper() in ["ACCEPT", "ALLOW"]:

            # Asegurarse de que Service sea una lista
            service_field = rule.get("Service", "")
            if "ANY" in service_field or "ALL" in service_field:
                return False  # "ANY" o "ALL" no se consideran inseguros
            if isinstance(service_field, str):
                service_list = [s.strip() for s in service_field.split(",")]
            else:
                service_list = service_field  # ya es lista

            for service in service_list:
                # print(f"Service: {service}")
                if service.upper() in ["ANY", "ALL"]:
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
        if ("ANY" in rule["Source"] or "ALL" in rule["Source"] or "0.0.0.0/0" in rule["Source"]) and \
           ("ANY" in rule["Destination"] or "ALL" in rule["Destination"] or "0.0.0.0/0" in rule["Destination"]) and \
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
    # logging.info("FUNCTION: is_shadowed()")
    if rule_lower.get("ID") == "24":
        print(rule_lower.get("ID"))
        print(rule_upper.get("ID"))

    """
    Determina si la regla `rule_lower` está opacada por la regla `rule_upper`.
    """
    if "Enabled" in rule_lower.get("Status", "") and "Enabled" in rule_upper.get("Status", ""):
        # action_lower = rule_lower['Action']
        # action_upper = rule_upper['Action']
        # print(rule_lower.get("Source"))
        # print(rule_lower.get("Source"))

        ip_src_relation = is_subnet_of(rule_lower['Source'][0], rule_upper['Source'][0])
        if rule_lower.get("ID") == "24":
            print(f"IP src relation: {ip_src_relation}")
        ip_dst_relation = is_subnet_of(rule_lower['Destination'][0], rule_upper['Destination'][0])
        if rule_lower.get("ID") == "24":
            print(f"IP dst relation: {ip_dst_relation}")
        port_relation = is_port_range_subset(rule_lower['Service'][0], rule_upper['Service'][0])
        if rule_lower.get("ID") == "24":
                print(f"IP port relation: {port_relation}")

        if ip_src_relation and ip_dst_relation and port_relation:
            if any(isinstance(value, str) and "Partial" in value for value in [ip_src_relation, ip_dst_relation, port_relation]):
                # print(f"Partially shadowed: {rule_lower.get('ID')} by {rule_upper.get('ID')}")
                return True, "Partially Shadowed"
            # print(f"Fully shadowed: {rule_lower.get('ID')} by {rule_upper.get('ID')}") 
            return True, "Fully Shadowed"
        # print(f"Not shadowed: {rule_lower.get('ID')} by {rule_upper.get('ID')}")
    return False, "Not Shadowed"