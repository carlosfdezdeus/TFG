import sqlite3
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D  
from Functions.config import DB_FW_CONFLICTS, CONFLICT_STYLES, CONFLICT_GRAPH_PATH

# Diccionario de estilos por tipo de conflicto


def getConflicts():
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()

    query = "SELECT id_rule_1, id_rule_2, conflict_type FROM firewall_conflict_rules"
    cursor.execute(query)
    conflicts = cursor.fetchall()

    conn.close()
    
    return conflicts

def graph_creator():
    conflicts = getConflicts()

    conflictGraph = nx.Graph()
    # Agregar nodos y aristas con etiquetas de conflicto
    for rule1, rule2, conflict_type in conflicts:
        edge_style = CONFLICT_STYLES.get(conflict_type.split(" (")[0], {"color": "gray", "style": "-"})  # Evitar error si no está en diccionario
        conflictGraph.add_edge(rule1, rule2, conflict_type=conflict_type, **edge_style)


    return conflictGraph


def plot_graph(show_graph=True):
    """Genera el grafo de conflictos y lo guarda en un archivo PDF."""
    conflictGraph = graph_creator()  

    # Crear figura
    plt.figure(figsize=(10, 7))
    pos = nx.spring_layout(conflictGraph)  

    # Dibujar nodos
    nx.draw(conflictGraph, pos, with_labels=True, node_color="lightblue", edge_color="gray", node_size=2000, font_size=12)

    # Dibujar aristas con estilos diferentes
    for (u, v, attrs) in conflictGraph.edges(data=True):
        nx.draw_networkx_edges(
            conflictGraph, pos, edgelist=[(u, v)], edge_color=attrs["color"], style=attrs["style"], width=2
        )

    # Crear la leyenda
    legend_elements = [
        Line2D([0], [0], color=style["color"], linestyle=style["style"], lw=2, label=conflict_type)
        for conflict_type, style in CONFLICT_STYLES.items()
    ]
    
    plt.legend(handles=legend_elements, title="Tipos de Conflicto", loc="best")
    plt.title("Grafo de Conflictos entre Reglas de Firewall")

    # Guardar la figura en un archivo PDF
    plt.savefig(CONFLICT_GRAPH_PATH, format="pdf", bbox_inches="tight")
    
    if show_graph:
        plt.show()

    print(f"✅ Grafo guardado en: {CONFLICT_GRAPH_PATH}")
    if not show_graph:
        print("ℹ️ El gráfico se ha guardado, pero no se mostrará en pantalla.")

    

# def plot_graph():
#     conflictGraph = graph_creator()
#     # Dibujar el grafo
#     plt.figure(figsize=(10, 7))
#     pos = nx.spring_layout(conflictGraph)  # Algoritmo de distribución de nodos
#     edge_labels = nx.get_edge_attributes(conflictGraph, 'label')  # Etiquetas de conflictos

#     # Dibujar nodos y conexiones
#     nx.draw(conflictGraph, pos, with_labels=True, node_color="lightblue", edge_color="gray", node_size=2000, font_size=12)
#     nx.draw_networkx_edge_labels(conflictGraph, pos, edge_labels=edge_labels, font_size=9, bbox=dict(facecolor='white', edgecolor='none', alpha=0.7))

#     plt.title("Grafo de Conflictos entre Reglas de Firewall")
#     plt.show()



