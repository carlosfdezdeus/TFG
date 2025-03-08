from Functions.file_management_functions import load_rules_from_file, create_conflict_database, insert_conflict_rule, diplay_conflictive_rules
from Functions.conflict_detection_functions import is_redundant, rule_have_x_any, is_disabled, is_not_in_use, have_insecure_protocols, is_shadowed, is_remaining_traffic_denied
import argparse, logging

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Configurar los argumentos de la terminal
    # Configurar los argumentos de la terminal con una mejor descripción
    parser = argparse.ArgumentParser(
        description="Genera y guarda un grafo de conflictos entre reglas de firewall basado en datos de una base de datos.\n"
                    "El grafo se guarda como un archivo PDF y se puede mostrar en pantalla si se desea.",
        formatter_class=argparse.RawTextHelpFormatter  # Permite saltos de línea en --help
    )    
    parser.add_argument(
        "--show",
        dest="show_graph",
        action="store_true",
        help="Muestra el gráfico en pantalla además de guardarlo."
    )
    
    parser.add_argument(
        "--no-show",
        dest="show_graph",
        action="store_false",
        help="Solo guarda el gráfico sin mostrarlo en pantalla."
    )

    parser.set_defaults(show_graph=True)  # Por defecto, el gráfico se muestra

    args = parser.parse_args()

    # Detección de reglas conflictivas:
    create_conflict_database()
    rules = load_rules_from_file()

    last_enabled_rule = None  # Variable para almacenar la última regla habilitada
    for i, rule1 in enumerate(rules):   
        print(rule1)
        if is_disabled(rule1): #FUNCIONA
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} is DISABLED.")
            insert_conflict_rule(rule1, None, "Disabled")
        else:
            last_enabled_rule = rule1

        if is_not_in_use(rule1) == True:    #FUNCIONA
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} is NOT IN USE.")
            insert_conflict_rule(rule1, None, "Not in use")

        if have_insecure_protocols(rule1) == True:  #FUNCIONA
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} allows traffic from INSECURE PROTOCOLS.")
            insert_conflict_rule(rule1, None, "Insecure")

        have_any, conflict_type = rule_have_x_any(rule1)
        if have_any:
            logging.info(f"CONFLICT DETECTED: Rule with ID: {rule1['ID']} have the following conlict type, {conflict_type.upper()}.")
            insert_conflict_rule(rule1, None, conflict_type)
    
        for j, rule2 in enumerate(rules):
            if i != j:
                if is_redundant(rule1, rule2):
                    logging.info(f"CONFLICT DETECTED: Rules with IDs: {rule2['ID']} is REDUNDANT with {rule1['ID']}.")
                    insert_conflict_rule(rule1, rule2, "Redundant")

                shadowed, conflict_type = is_shadowed(rule1, rule2)
                if shadowed == True:
                    logging.info(f"CONFLICT DETECTED: Rules with IDs: {rule2['ID']} is {conflict_type.upper()} with {rule1['ID']}.")
                    insert_conflict_rule(rule1, rule2, conflict_type)

        if i == len(rules) - 1:
            if not is_remaining_traffic_denied(last_enabled_rule):
                logging.info(f"CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")
                insert_conflict_rule(rule1, None, "Remaining traffic not denied")

        print("\n")
    #diplay_conflictive_rules()