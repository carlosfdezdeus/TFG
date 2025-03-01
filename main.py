from Functions.conflict_detection_functions import firewall_rule_analizer
from Functions.database_management_functions import create_firewall_rules_database, read_firewall_rules, display_rules
import argparse

if __name__ == '__main__':
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
    
    create_firewall_rules_database()
    read_firewall_rules()
    display_rules()
    
    rules = firewall_rule_analizer()
    print(rules)