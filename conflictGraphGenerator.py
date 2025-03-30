from Functions.graphFunctions import draw_conflict_graph
#, prueba, draw_conflict_graph
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
    
    # Llamar a la función con el parámetro seleccionado desde la terminal
    draw_conflict_graph(show=args.show_graph)
