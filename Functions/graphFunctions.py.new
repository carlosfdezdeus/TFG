import sqlite3
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D  
from Functions.config import DB_FW_CONFLICTS, CONFLICT_LINE_STYLES, CONFLICT_NODE_STYLES, CONFLICT_GRAPH_PATH
from Functions.file_management_functions import get_conflict_rules

import networkx as nx
import matplotlib.pyplot as plt


def graph_creator():
    conflicts = get_conflict_rules()
    conflictGraph = nx.Graph()
    # Agregar nodos y aristas con etiquetas de conflicto
    for rule1, rule2, conflict_type in conflicts:
        print(rule1)

        edge_style = CONFLICT_LINE_STYLES.get(conflict_type.split(" (")[0], {"color": "gray", "style": "-"})  # Evitar error si no está en diccionario
        conflictGraph.add_edge(rule1, rule2, conflict_type=conflict_type, **edge_style)

    return conflictGraph


def plot_graph(show_graph=True):
    """Genera el grafo de conflictos y lo guarda en un archivo PDF."""
    conflictGraph = graph_creator()  

    # Remover el nodo NULL si está presente
    if "NULL" in conflictGraph:
        conflictGraph.remove_node("NULL")

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
        for conflict_type, style in CONFLICT_LINE_STYLES.items()
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

def prueba(show_graph=True):
    """Genera el grafo de conflictos y lo guarda en un archivo PDF."""
    conflictGraph = graph_creator()

    # Remover el nodo NULL si está presente
    if "NULL" in conflictGraph:
        conflictGraph.remove_node("NULL")

    # Crear figura
    plt.figure(figsize=(10, 7))
    pos = nx.spring_layout(conflictGraph)  

    # Determinar el color de cada nodo según CONFLICT_NODE_STYLES
    node_colors = []
    for node in conflictGraph.nodes():
        conflict_type = next((t for t in CONFLICT_NODE_STYLES if t in str(node)), None)
        
        node_color = CONFLICT_NODE_STYLES.get(conflict_type)["color"]
        node_colors.append(node_color)

    # Dibujar nodos con los colores asignados
    nx.draw(conflictGraph, pos, with_labels=True, node_color=node_colors, edge_color="gray", 
            node_size=2000, font_size=12)

    # Dibujar aristas con estilos diferentes
    for (u, v, attrs) in conflictGraph.edges(data=True):
        nx.draw_networkx_edges(
            conflictGraph, pos, edgelist=[(u, v)], edge_color=attrs["color"], style=attrs["style"], width=2
        )

    # Crear la leyenda para las aristas
    legend_elements_edges = [
        Line2D([0], [0], color=style["color"], linestyle=style["style"], lw=2, label=conflict_type)
        for conflict_type, style in CONFLICT_LINE_STYLES.items()
    ]
    
    # Crear la leyenda para los nodos
    legend_elements_nodes = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor=style["color"], markersize=10, label=conflict_type)
        for conflict_type, style in CONFLICT_NODE_STYLES.items()
    ]
    
    plt.legend(handles=legend_elements_edges + legend_elements_nodes, title="Tipos de Conflicto", loc="best")
    plt.title("Grafo de Conflictos entre Reglas de Firewall")

    # Guardar la figura en un archivo PDF
    plt.savefig(CONFLICT_GRAPH_PATH, format="pdf", bbox_inches="tight")
    
    if show_graph:
        plt.show()

    print(f"✅ Grafo guardado en: {CONFLICT_GRAPH_PATH}")
    if not show_graph:
        print("ℹ️ El gráfico se ha guardado, pero no se mostrará en pantalla.")







def draw_conflict_graph():
    conflicts = get_conflict_rules()
    
    # Crear el grafo
    G = nx.Graph()
    
    for rule1, rule2, conflict_type in conflicts:
        G.add_edge(rule1, rule2, label=conflict_type)  # Agregar relaciones al grafo

  
    
    # Dibujar el grafo
    pos = nx.spring_layout(G)  # Posicionamiento de nodos
    plt.figure(figsize=(10, 6))
    
    nx.draw(G, pos, with_labels=True, node_color="lightblue", edge_color="gray", node_size=2000, font_size=10)
    
    # Agregar etiquetas a los bordes (tipo de conflicto)
    edge_labels = {(rule1, rule2): conflict for rule1, rule2, conflict in conflicts}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=9, font_color="red")
    
    plt.title("Grafo de Conflictos de Firewall")
    plt.show()
