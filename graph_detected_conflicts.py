import logging, threading
import time
from Functions.config import (
    DB_FW_CONFLICTS,
    DB_FW_OPTIMIZED
)

from Functions.file_management_functions import (
    load_rules_from_file,
    create_conflict_database,
    insert_conflict_rule,
    erase_optimized_db
)
from Functions.conflict_detection_functions import (
    is_redundant,
    rule_have_x_any,
    is_disabled,
    is_not_in_use,
    have_insecure_protocols,
    is_shadowed,
    is_remaining_traffic_denied
)

from Functions.graphFunctions import draw_conflict_graph

def conflict_rule_detector(show_graph: bool = False, optimized_rules: list = None):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    create_conflict_database()
    # Seleccionar base de datos según si hay reglas optimizadas
    if optimized_rules is not None:
        database = DB_FW_OPTIMIZED
        rules = optimized_rules
        erase_optimized_db()
    else:
        database = DB_FW_CONFLICTS
        rules = load_rules_from_file()  # Cargar reglas originales
    # Copia de trabajo para aplicar optimizaciones
    rules_to_optimize = rules.copy()

    last_enabled_rule = None

    for i, rule1 in enumerate(rules):
        # print(rule1)

        if is_disabled(rule1):
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} is DISABLED.")
            insert_conflict_rule(rule1, None, "Disabled", database)
        else:
            last_enabled_rule = rule1

        if is_not_in_use(rule1):
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} is NOT IN USE.")
            insert_conflict_rule(rule1, None, "Not in use", database)

        if have_insecure_protocols(rule1):
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} allows traffic from INSECURE PROTOCOLS.")
            insert_conflict_rule(rule1, None, "Insecure", database)

        have_any, conflict_type = rule_have_x_any(rule1)
        if have_any:
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} have the following conflict type: {conflict_type.upper()}.")
            insert_conflict_rule(rule1, None, conflict_type, database)
        for j, rule2 in enumerate(rules):            
            if i != j and (int(rule2['ID']) > int(rule1['ID'])):
                if is_redundant(rule1, rule2):
                    logging.info(f"CONFLICT DETECTED: Rule with ID: {rule2['ID']} is REDUNDANT with {rule1['ID']}.")
                    insert_conflict_rule(rule1, rule2, "Redundant", database)

                shadowed, conflict_type = is_shadowed(rule1, rule2)
                if shadowed:
                        logging.info(f"CONFLICT DETECTED: Rule with ID: {rule2['ID']} is {conflict_type.upper()} with {rule1['ID']}.")
                        insert_conflict_rule(rule1, rule2, conflict_type, database)

        if i == len(rules) - 1 and not is_remaining_traffic_denied(last_enabled_rule):
            logging.info(f"CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")
            insert_conflict_rule(rule1, None, "Remaining traffic not denied", database)

        print("\n")

    if show_graph:
        threading.Thread(target=draw_conflict_graph, kwargs={"show": True}, daemon=True).start()
    else:
        if optimized_rules is not None:
            start_graph = time.time()
            draw_conflict_graph(show=False, database=DB_FW_OPTIMIZED, optimized=True)
            graph_time = time.time() - start_graph
        else:
            start_graph = time.time()
            draw_conflict_graph(show=False, database=DB_FW_CONFLICTS)
            graph_time = time.time() - start_graph


    return rules_to_optimize, graph_time