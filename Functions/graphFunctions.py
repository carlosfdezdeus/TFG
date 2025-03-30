import sqlite3
import networkx as nx
import numpy as np
from matplotlib.patches import FancyArrowPatch
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D  
from collections import defaultdict, Counter
from Functions.config import DB_FW_CONFLICTS, CONFLICT_GRAPH_PATH, CONFLICT_LINE_STYLES, UNARY_CONFLICT_COLORS
from Functions.file_management_functions import save_conflict_graph


def getConflicts():
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()

    query = "SELECT id_rule_1, id_rule_2, conflict_type FROM firewall_conflict_rules"
    cursor.execute(query)
    conflicts = cursor.fetchall()

    conn.close()

    print(conflicts)
    
    return conflicts

# Construir grafo con estilos
def build_conflict_graph(conflicts):
    G = nx.Graph()
    edge_styles = defaultdict(set)
    node_conflicts = defaultdict(set)

    for rule1, rule2, conflict_type in conflicts:
        print(f"{rule1} - {rule2}: {conflict_type}")

        rule1 = int(rule1)
        if rule2 != "NULL":
            rule2 = int(rule2)
            if conflict_type in CONFLICT_LINE_STYLES:
                G.add_node(rule1)
                G.add_node(rule2)
                edge_styles[(min(rule1, rule2), max(rule1, rule2))].add(conflict_type)
        else:
            G.add_node(rule1)
            node_conflicts[conflict_type].add(rule1)

    return G, edge_styles, node_conflicts

# Dibujar el grafo y la leyenda
def draw_conflict_graph(show=True):
    conflicts = getConflicts()
    G, edge_styles, node_conflicts = build_conflict_graph(conflicts)

    fig = plt.figure(figsize=(14, 10))
    ax = fig.add_subplot(1, 1, 1)
    pos = nx.spring_layout(G, seed=42)

    for (n1, n2), conflict_types in edge_styles.items():
        conflict_types = list(conflict_types)
        total = len(conflict_types)
        for i, conflict_type in enumerate(conflict_types):
            style, color = CONFLICT_LINE_STYLES[conflict_type]
            angle = 0.2 * (i - (total - 1) / 2)
            arrow = FancyArrowPatch(
                posA=pos[n1],
                posB=pos[n2],
                connectionstyle=f"arc3,rad={angle}",
                arrowstyle='-',
                linewidth=2,
                linestyle=style,
                color=color,
                alpha=0.8
            )
            ax.add_patch(arrow)

    nx.draw_networkx_nodes(G, pos, node_size=1200, node_color='skyblue', ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold', ax=ax)

    # Mapeo de conflictos por nodo
    node_conflict_map = defaultdict(list)
    for conflict_type, nodes in node_conflicts.items():
        if conflict_type in ["Redundant", "Fully Shadowed", "Partially Shadowed"]:
            continue
        color = UNARY_CONFLICT_COLORS.get(conflict_type, "gray")
        for node in nodes:
            node_conflict_map[node].append(color)

    # Calcular el centroide del grafo
    all_x = [x for x, y in pos.values()]
    all_y = [y for x, y in pos.values()]
    center_x = sum(all_x) / len(all_x)
    center_y = sum(all_y) / len(all_y)

    # Dibujar los puntos alejados del centroide (dirección radial)
    spacing = 0.06
    for node, colors in node_conflict_map.items():
        if node in pos:
            x, y = pos[node]
            dx = x - center_x
            dy = y - center_y
            norm = np.hypot(dx, dy)
            if norm == 0:
                dx, dy = 1, 0  # default right
                norm = 1
            dx /= norm
            dy /= norm
            base_x = x + dx * 0.15
            base_y = y + dy * 0.15
            for i, color in enumerate(colors):
                dot_x = base_x + dx * i * spacing
                dot_y = base_y + dy * i * spacing
                ax.plot(dot_x, dot_y, 'o', color=color, markersize=10)



    legend_lines = [
        Line2D([0], [0], color=color, linestyle=style, linewidth=2, label=conf)
        for conf, (style, color) in CONFLICT_LINE_STYLES.items()
    ]

    grouped = defaultdict(list)
    for conflict, nodes in node_conflicts.items():
        color = UNARY_CONFLICT_COLORS.get(conflict, "gray")
        label = f"{conflict}: {', '.join(map(str, sorted(nodes)))}"
        grouped[color].append(label)

    for color in ["green", "orange", "red", "black"]:
        for label in grouped.get(color, []):
            legend_lines.append(
                Line2D([0], [0],
                       marker='o',
                       linestyle='None',
                       color='white',
                       markerfacecolor=color,
                       markersize=10,
                       label=label)
            )

    ax.legend(handles=legend_lines, loc='center left', bbox_to_anchor=(1, 0.5), fontsize='small', frameon=True)
    ax.set_title("Grafo de Conflictos de Reglas de Firewall")
    ax.axis('off')

    # 🔁 Guardar automáticamente
    save_conflict_graph(fig, path=CONFLICT_GRAPH_PATH)

    # Mostrar si se pide
    if show:
        plt.show()
    else:
        plt.close(fig)
