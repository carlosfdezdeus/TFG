from Functions.file_management_functions import get_redundant_rules, get_fully_shadowed_rules, get_not_in_use_rules_without_shadowing, get_rules_with_any_id, copiar_db_sqlite_backup, remove_insecure_and_disabled_rules_db, remove_redundant_from_db, remove_not_in_use_rules_db, swap_fully_shadowed_rules, get_insecure_rules_id, get_disabled_rules_id, is_remaining_traffic_denied_conflict, getConflicts
from Functions.conflict_detection_functions import expand_ips, expand_ports
import ipaddress
import pandas as pd
import ast



def count_values(values):
    """Returns the number of elements in a set or IP network, or a large value if it's ANY."""
    num_addresses = 0
    num_services = 0
    for value in values:
        if isinstance(value, ipaddress._BaseNetwork):
            num_addresses = num_addresses + value.num_addresses
        elif isinstance(value, set):
            num_services = num_services + len(value)
            
    if num_addresses == 0:
        return num_services
    else:
        return num_addresses
        


def optimization_1(rules_to_optimize):
    optimization_text_1 = []
    copiar_db_sqlite_backup()
    optimized_rules, insecure_and_disabled_rules_to_eliminate = remove_insecure_and_disabled_rules(rules_to_optimize)

    optimization_text_1 = optimize_rules_with_any(optimization_text_1)

    optimization_text_1 = optimize_insecure_rules(optimization_text_1)

    optimized_rules, not_in_use_rules_to_eliminate = remove_not_in_use_rules_without_shadowing(optimized_rules)

    rules_to_eliminate = {**insecure_and_disabled_rules_to_eliminate, **not_in_use_rules_to_eliminate}

    for rule_id, reason in rules_to_eliminate.items():
        print(f"OPTIMIZATION: Rule with ID {rule_id} should be removed because it is classified as a {reason} rule.")
        optimization_text_1.append(
            f"OPTIMIZATION: Rule with ID {rule_id} should be removed because it is classified as a {reason} rule."
        )
    

    # optimized_rules = optimize_remaining_traffic_not_denied(optimization_text_1, optimized_rules)
    #print(optimized_rules)


    return optimized_rules, optimization_text_1

def remove_insecure_and_disabled_rules(rules_to_optimize):
    optimized_rules = rules_to_optimize
        # insecure_rules = set(str(id_tuple[0]) for id_tuple in get_insecure_rules_id())
    # print("REGLAS INSEGURAS:")
    # print(f"{insecure_rules} \n")
    disabled_rules = set(str(id_tuple[0]) for id_tuple in get_disabled_rules_id())
    # print("REGLAS DESHABILITADAS:")
    # print(f"{disabled_rules} \n")

    # ids_to_remove = insecure_rules.union(disabled_rules)
    ids_to_remove = disabled_rules

    # print(ids_to_remove)

    # Creamos diccionario con el tipo de conflicto
    conflict_reason = {}
    # for rule_id in insecure_rules:
    #     conflict_reason[rule_id] = "Insecure"
    for rule_id in disabled_rules:
        conflict_reason[rule_id] = "Disabled"

    optimized_rules = [
        rule for rule in rules_to_optimize
        if str(rule.get("ID")) not in ids_to_remove
    ]

    remove_insecure_and_disabled_rules_db(ids_to_remove)
    return optimized_rules, conflict_reason

def optimize_insecure_rules(optimization_text_1):
    insecure_rules = set(str(id_tuple[0]) for id_tuple in get_insecure_rules_id())

    for rule_id in set(insecure_rules):
        print(f"OPTIMIZATION: Rule ID {rule_id} should be monitored to eventually remove insecure protocols or replace them with secure alternatives.")
        optimization_text_1.append(
            f"OPTIMIZATION: Rule ID {rule_id} should be monitored to eventually remove insecure protocols or replace them with secure alternatives."
        )
        
    return optimization_text_1

def remove_not_in_use_rules_without_shadowing(rules_to_optimize):
    optimized_rules = rules_to_optimize

    not_in_use_to_remove = get_not_in_use_rules_without_shadowing()

    conflict_reason = {}
    for rule_id in not_in_use_to_remove:
        conflict_reason[rule_id] = "Not in use"

    # print(not_in_use_to_remove)
    # print(f"ANTES:{optimized_rules}")
    not_in_use_to_remove = {str(x) for x in not_in_use_to_remove}
    optimized_rules = [
        rule for rule in rules_to_optimize
        if str(rule.get("ID")) not in not_in_use_to_remove
    ]
    # print(f"DESPUES:{optimized_rules}")

    remove_not_in_use_rules_db(not_in_use_to_remove)
    return optimized_rules, conflict_reason

def optimize_rules_with_any(optimization_text_1):
    rules_with_any = get_rules_with_any_id()

    for rule_id in set(rules_with_any):
        print(f"OPTIMIZATION: Traffic from rule ID {rule_id} should be monitored in order to eventually remove the ANY, ALL or  wildcard.")
        optimization_text_1.append(
            f"OPTIMIZATION: Traffic from rule ID {rule_id} should be monitored in order to eventually remove the ANY, ALL or wildcard."
        )
        
    return optimization_text_1

def optimize_remaining_traffic_not_denied(optimization_text_1, rules_to_optimize):
    last_rule_id, conflict_exists = is_remaining_traffic_denied_conflict()
    if conflict_exists:
        message = (
            f"OPTIMIZATION: Rule {last_rule_id} does not deny remaining traffic. "
            f"A new DENY rule should be created with ID {last_rule_id + 1} to block all remaining traffic."
        )
        print(message)
        optimization_text_1.append(message)

        # Crear nueva regla DENY para todo el tráfico restante
        new_rule = {
            'ID': last_rule_id + 1,
            'Policy': 'Added to block remaining traffic',
            'Source': ['0.0.0.0/0'],
            'Destination': ['0.0.0.0/0'],
            'Schedule': ['always'],
            'Service': ['ANY'],
            'Action': 'DENY',
            'Log': 'All',
            'Application Control': ['default'],
            'Comments': 'Auto-added to block remaining traffic',
            'Hit Count': 0,
            'Status': 'Enabled'
        }

        # Añadir la nueva regla a la lista de reglas en memoria
        rules_to_optimize.append(new_rule)

    return rules_to_optimize


def optimization_2(rules_to_optimize):
    optimization_text_2 = []

    optimized_rules = rules_to_optimize

    redundant_to_remove = remove_redundant(rules_to_optimize, optimization_text_2)
    
    # print(f"{redundant_to_remove}")

    optimized_rules = [
        rule for rule in rules_to_optimize
        if str(rule.get("ID")) not in redundant_to_remove
    ]
    return optimized_rules, optimization_text_2

def rule_specificity(rule):
    return 




def remove_redundant(rules_to_optimize, optimization_text_2):
    """
    Returns a list of rule IDs that are candidates for removal
    in redundancy conflicts, keeping the more general rule unless it contains ANY.
    """
    redundant_rules = get_redundant_rules()
    current_rule_ids = {str(rule['ID']) for rule in rules_to_optimize}
    removal_candidates_ids = set()
    specificities = {}

    for rule_pair in redundant_rules:
        rule1_id, rule2_id = str(rule_pair[0]), str(rule_pair[1])
        if rule1_id in removal_candidates_ids or rule2_id in removal_candidates_ids:
            continue

        rule1 = {
            'id': rule1_id,
            'source': rule_pair[2],
            'destination': rule_pair[4],
            'service': rule_pair[6],
            'hit_count': rule_pair[8]
        }

        rule2 = {
            'id': rule2_id,
            'source': rule_pair[3],
            'destination': rule_pair[5],
            'service': rule_pair[7],
            'hit_count': rule_pair[9]
        }

        if contains_any_or_0_subnet(rule1) or contains_any_or_0_subnet(rule2):
            continue

        print(f"Comparing rules {rule1_id} and {rule2_id}")
        
        if rule1_id not in specificities:
            specificities[rule1_id] = calculate_specificity(rule1)
        if rule2_id not in specificities:
            specificities[rule2_id] = calculate_specificity(rule2)

        spec1 = specificities[rule1_id]
        spec2 = specificities[rule2_id]

        if spec1 > spec2:
            less_specific_rule = rule2
        elif spec2 > spec1:
            less_specific_rule = rule1
        else:
            if rule1['hit_count'] > rule2['hit_count']:
                less_specific_rule = rule2
            elif rule2['hit_count'] > rule1['hit_count']:
                less_specific_rule = rule1
            else:
                continue

        rid = less_specific_rule['id']
        if rid in current_rule_ids:
            removal_candidates_ids.add(rid)
            optimization_text_2.append(
                f"OPTIMIZATION: Rule with ID {rid} should be removed because it is a less specific redundant rule."
            )

    if removal_candidates_ids:
        remove_redundant_from_db(list(removal_candidates_ids))

    return list(removal_candidates_ids)






# def remove_redundant(rules_to_optimize, optimization_text_2):
#     """
#     Returns a list of rule IDs that are candidates for removal
#     in redundancy conflicts, keeping the more general rule unless it contains ANY.
#     """
    
#     redundant_rules = get_redundant_rules()
#     current_rule_ids = {str(rule['ID']) for rule in rules_to_optimize}
#     removal_candidates_ids = set()

#     for i, rule in enumerate(redundant_rules):
#         # print(f"Analizando par {i+1}/{len(redundant_rules)}: ID {rule[0]} vs ID {rule[1]}")
#         rule1_id = str(rule[0])
#         rule2_id = str(rule[1])
#         print(rule1_id, rule2_id)

#         # ❗ Saltar si cualquiera de las dos reglas ya ha sido marcada para eliminación
#         if rule1_id in removal_candidates_ids or rule2_id in removal_candidates_ids:
#             continue

#         rule1 = {
#             'id': str(rule[0]),
#             'source': rule[2],
#             'destination': rule[4],
#             'service': rule[6],
#             'hit_count': rule[8]
#         }
#         # print(rule1)
#         rule2 = {
#             'id': str(rule[1]),
#             'source': rule[3],
#             'destination': rule[5],
#             'service': rule[7],
#             'hit_count': rule[9]
#         }
    
#         if contains_any_or_0_subnet(rule1) or contains_any_or_0_subnet(rule2):
#             continue
        
#         spec1 = calculate_specificity(rule1)
#         # print(spec1)
#         spec2 = calculate_specificity(rule2)
#         # print(spec2)

#         if spec1 > spec2:
#             less_specific_rule = rule2
#         elif spec2 > spec1:
#             less_specific_rule = rule1
#         else:
#             # If both are equally general, keep the one with higher hit count
#             if rule1['hit_count'] > rule2['hit_count']:
#                 less_specific_rule = rule2
#             elif rule2['hit_count'] > rule1['hit_count']:
#                 less_specific_rule = rule1
#             else:
#                 continue

#         print(f"OPTIMIZATION: Rule with ID {less_specific_rule['id']} should be removed because it is a less specific redundant rule.")
#         optimization_text_2.append(
#             f"OPTIMIZATION: Rule with ID {less_specific_rule['id']} should be removed because it is a less specific redundant rule."
#         )
#         # Solo añadir si aún está en rules_to_optimize
#         if less_specific_rule['id'] in current_rule_ids:
#             removal_candidates_ids.add(less_specific_rule['id'])

#         if removal_candidates_ids:
#             remove_redundant_from_db(list(removal_candidates_ids))
    
#     return list(removal_candidates_ids)











# def calculate_specificity(rule):
#     """Calcula la especificidad de una regla: menos combinaciones = más específica"""

#     # Cargar listas reales desde strings tipo '["1.1.1.1"]'
#     source_list = rule['source']
#     destination_list = rule['destination']
#     service_list = rule['service']

#     if isinstance(source_list, str):
#         source_list = ast.literal_eval(source_list)
#     if isinstance(destination_list, str):
#         destination_list = ast.literal_eval(destination_list)
#     if isinstance(service_list, str):
#         service_list = ast.literal_eval(service_list)

#     # # Expandir IPs origen
#     # source = set()
#     # for src in source_list:
#     #     result = expand_ips(src)
#     #     if isinstance(result, ipaddress.IPv4Network):
#     #         source.update(result.hosts())
#     #     else:
#     #         source.update(result)

#     # # Expandir IPs destino
#     # destination = set()
#     # for dst in destination_list:
#     #     result = expand_ips(dst)
#     #     if isinstance(result, ipaddress.IPv4Network):
#     #         destination.update(result.hosts())
#     #     else:
#     #         destination.update(result)

#     # Expandir IPs origen
#     source = set()
#     for src in source_list:
#         result = expand_ips(src)
#         if isinstance(result, ipaddress.IPv4Network):
#             source.update(result.hosts())
#         elif isinstance(result, ipaddress.IPv4Address):
#             source.add(result)
#         elif isinstance(result, set):
#             for r in result:
#                 if isinstance(r, ipaddress.IPv4Network):
#                     source.update(r.hosts())
#                 else:
#                     source.add(r)

#     # Expandir IPs destino
#     destination = set()
#     for dst in destination_list:
#         result = expand_ips(dst)
#         if isinstance(result, ipaddress.IPv4Network):
#             destination.update(result.hosts())
#         elif isinstance(result, ipaddress.IPv4Address):
#             destination.add(result)
#         elif isinstance(result, set):
#             for r in result:
#                 if isinstance(r, ipaddress.IPv4Network):
#                     destination.update(r.hosts())
#                 else:
#                     destination.add(r)

#     # Expandir puertos
#     service = set()
#     for svc in service_list:
#         service.update(expand_ports(svc))  # Debe devolver un set de puertos

#     # Especificidad = número de combinaciones
#     return len(source) * len(destination) * len(service)

def calculate_specificity(rule):
    """Calcula la especificidad de una regla: menos combinaciones = más específica"""

    # Cargar listas reales desde strings tipo '["1.1.1.1"]'
    source_list = rule['source']
    destination_list = rule['destination']
    service_list = rule['service']

    if isinstance(source_list, str):
        source_list = ast.literal_eval(source_list)
    if isinstance(destination_list, str):
        destination_list = ast.literal_eval(destination_list)
    if isinstance(service_list, str):
        service_list = ast.literal_eval(service_list)

    # # Expandir IPs origen
    # source = set()
    # for src in source_list:
    #     result = expand_ips(src)
    #     if isinstance(result, ipaddress.IPv4Network):
    #         source.update(result.hosts())
    #     else:
    #         source.update(result)

    # # Expandir IPs destino
    # destination = set()
    # for dst in destination_list:
    #     result = expand_ips(dst)
    #     if isinstance(result, ipaddress.IPv4Network):
    #         destination.update(result.hosts())
    #     else:
    #         destination.update(result)

    # Expandir IPs origen
    source = set()
    for src in source_list:
        result = expand_ips(src)
        if isinstance(result, ipaddress.IPv4Network):
            source.update(result.hosts())
        elif isinstance(result, ipaddress.IPv4Address):
            source.add(result)
        elif isinstance(result, set):
            for r in result:
                if isinstance(r, ipaddress.IPv4Network):
                    source.update(r.hosts())
                else:
                    source.add(r)

    # Expandir IPs destino
    destination = set()
    for dst in destination_list:
        result = expand_ips(dst)
        if isinstance(result, ipaddress.IPv4Network):
            destination.update(result.hosts())
        elif isinstance(result, ipaddress.IPv4Address):
            destination.add(result)
        elif isinstance(result, set):
            for r in result:
                if isinstance(r, ipaddress.IPv4Network):
                    destination.update(r.hosts())
                else:
                    destination.add(r)

    # Expandir puertos
    service = set()
    for svc in service_list:
        service.update(expand_ports(svc))  # Debe devolver un set de puertos

    # Especificidad = número de combinaciones
    return len(source) * len(destination) * len(service)

def contains_any_or_0_subnet(rule):
    """Checks if any of the fields are 'ANY' or cover all traffic."""
    def parse(value):
        # Si es string tipo '["x"]', conviértelo a lista real
        if isinstance(value, str):
            try:
                evaluated = ast.literal_eval(value)
                return evaluated if isinstance(evaluated, list) else [evaluated]
            except Exception:
                return [value]
        elif isinstance(value, list):
            return value
        else:
            return [str(value)]

    def contains_any(value_list):
        return any(v.strip().upper() in ['ANY', '0.0.0.0/0', 'ALL'] for v in value_list if isinstance(v, str))

    source = parse(rule['source'])
    destination = parse(rule['destination'])
    service = parse(rule['service'])

    return (
        contains_any(source) or
        contains_any(destination) or
        contains_any(service)
    )




def optimization_3(rules_to_optimize):
    optimized_rules = rules_to_optimize

    proposed_swaps = propose_fully_shadowed_rules_new_position()

    # print(f"PROPOSED SWAPS: {proposed_swaps}")

    optimized_rules = swap_fully_shadowed_rules(proposed_swaps, optimized_rules)

    return optimized_rules

def propose_fully_shadowed_rules_new_position():
    conflicts = getConflicts()
    fully_shadowed_rules = get_fully_shadowed_rules()

    proposed_swaps = []

    # Obtener todos los IDs (id_rule_1 y id_rule_2 pueden contener valores)
    _, conflict_exists = is_remaining_traffic_denied_conflict()

    conflicts = getConflicts()
    all_ids = set()
    for r1, r2, _ in conflicts:
        if r1 is not None:
            all_ids.add(int(r1))
        if r2 not in (None, 'NULL'):
            all_ids.add(int(r2))
    last_id = max(all_ids)

    for rule in fully_shadowed_rules:
        rule1 = {
            'id': str(rule[0]),
            'source': rule[2],
            'destination': rule[4],
            'service': rule[6],
            'action': rule[8],
            'hit_count': rule[10]
        }

        # print(rule1)
        rule2 = {
            'id': str(rule[1]),
            'source': rule[3],
            'destination': rule[5],
            'service': rule[7],
            'action': rule[9],
            'hit_count': rule[11]
        }
        # print(rule2)

        if int(rule1['id']) == int(last_id) or int(rule2['id']) == int(last_id) and not conflict_exists:
            continue  # No proponer swaps con la última regla, que es la que deniega todo el tráfico

        # Proponer cambio solo si la regla 2 (DENY) está completamente sombreada por la 1 (ALLOW)
        # if "ALLOW" in rule1['action'] or "ACCEPT" in rule1['action'] and "DENY" in rule2['action']:
        if ("ALLOW" in rule1['action'] or "ACCEPT" in rule1['action']) and "DENY" in rule2['action']:
            swap = {
                'move_rule_id': rule2['id'],
                'above_rule_id': rule1['id'],
                'reason': 'DENY rule is fully shadowed by ALLOW rule - reordering suggested'
            }
            proposed_swaps.append(swap)

    return proposed_swaps


def swap_fully_shadowed_rules(proposed_swaps, rules_to_optimize):
    """
    Mueve la regla 'move_rule_id' justo antes de 'above_rule_id', sin alterar los IDs ni ordenar por ID al final.
    """
    optimization_text_3 = []
    for swap in proposed_swaps:
        move_id = str(swap['move_rule_id'])
        above_id = str(swap['above_rule_id'])

        id_to_index = {str(rule['ID']): i for i, rule in enumerate(rules_to_optimize)}

        if move_id not in id_to_index or above_id not in id_to_index:
            # print(f"Regla {move_id} o {above_id} no encontrada, se omite swap.")
            continue

        move_idx = id_to_index[move_id]
        above_idx = id_to_index[above_id]

        rule_to_move = rules_to_optimize.pop(move_idx)

        # Si la regla venía antes, al quitarla el índice objetivo disminuye
        if move_idx < above_idx:
            above_idx -= 1

        rules_to_optimize.insert(above_idx, rule_to_move)

        # Mensaje explicativo
        message = (
            f"OPTIMIZATION: Rule with ID {move_id} should be placed immediately before the rule with ID {above_id}, "
            f"due to a 'Fully Shadowed' overlap where a higher-priority DENY rule "
            f"is hidden behind a more general ACCEPT rule."
        )

        optimization_text_3.append(message)
        print(message)

    # 🔁 Reasignar IDs según el nuevo orden
    ids_ordenados = sorted(int(rule['ID']) for rule in rules_to_optimize)
    for i, rule in enumerate(rules_to_optimize):
        rule['ID'] = str(ids_ordenados[i])

    return rules_to_optimize, optimization_text_3