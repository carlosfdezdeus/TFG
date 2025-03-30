import sqlite3
import networkx as nx
import numpy as np
from matplotlib.patches import FancyArrowPatch
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D  
from collections import defaultdict, deque
from Functions.config import DB_FW_CONFLICTS, CONFLICT_GRAPH_PATH, CONFLICT_LINE_STYLES, UNARY_CONFLICT_COLORS
from Functions.file_management_functions import save_conflict_graph, get_hits


def getConflicts():
    conn = sqlite3.connect(DB_FW_CONFLICTS)
    cursor = conn.cursor()

    query = "SELECT id_rule_1, id_rule_2, conflict_type FROM firewall_conflict_rules"
    cursor.execute(query)
    conflicts = cursor.fetchall()

    conn.close()

    print(conflicts)
    
    return conflicts

# Construir grafo con estilos para dibujar
def build_drawable_conflict_graph():
    conflicts = getConflicts()
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

def build_real_conflict_graph():
    conflicts = getConflicts()
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
                G.add_edge(rule1, rule2, conflict=conflict_type)  # ✅ <-- Añadir arista real al grafo
                edge_styles[(min(rule1, rule2), max(rule1, rule2))].add(conflict_type)
        else:
            G.add_node(rule1)
            node_conflicts[conflict_type].add(rule1)

    return G

# Dibujar el grafo y la leyenda
def draw_conflict_graph(show=True):
    G, edge_styles, node_conflicts = build_drawable_conflict_graph()

    conflict_graph = plt.figure(figsize=(14, 10))
    ax = conflict_graph.add_subplot(1, 1, 1)
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
    save_conflict_graph(conflict_graph, path=CONFLICT_GRAPH_PATH)

    # Mostrar si se pide
    if show:
        plt.show()
    else:
        plt.close(conflict_graph)

    return G 


    
# ************************************************************************** #
# ************************ GRAPH TRAVESER FUNCTIONS: *********************** #
# ************************************************************************** #


# BFS to extract a connected component
def bfs_connected_component(graph, start_node, visited):
    queue = deque([start_node])
    component = set()

    while queue:
        node = queue.popleft()
        if node not in visited:
            visited.add(node)
            component.add(node)
            for neighbor in graph.neighbors(node):
                if neighbor not in visited:
                    queue.append(neighbor)

    return component

# DFS to go deeper from a node with many conflicts
def dfs_deep_conflict_chain(graph, start_node, visited_dfs):
    stack = [start_node]
    chain = []

    while stack:
        node = stack.pop()
        if node not in visited_dfs:
            visited_dfs.add(node)
            chain.append(node)
            for neighbor in graph.neighbors(node):
                stack.append(neighbor)

    return chain

# Count conflicts per node using BFS
def count_conflicts_by_type(graph, component):
    conflicts_per_node = defaultdict(lambda: defaultdict(int))

    for node in component:
        for neighbor in graph.neighbors(node):
            if neighbor in component:
                conflict_type = graph.edges[node, neighbor].get("conflict", "Unknown")
                conflicts_per_node[node][conflict_type] += 1

    return conflicts_per_node

def hit_analyzer(components, hits_per_rule):
    graph_total_hits = sum(hits_per_rule.values())
    print(f"\n📊 Total hits across entire graph: {graph_total_hits}\n")

    component_hits = []  # To rank components

    for i, comp in enumerate(components, 1):
        print(f"📈 Hit analysis for Component {i}:")

        component_total_hits = sum(hits_per_rule.get(node, 0) for node in comp)
        component_hits.append((i, component_total_hits))

        print(f"  🔹 Total hits in this component: {component_total_hits}")

        if graph_total_hits > 0:
            print(f"  🔸 This is {component_total_hits / graph_total_hits * 100:.1f}% of total graph hits")
        else:
            print(f"  🔸 No hit data available for graph.")

        for node in sorted(comp):
            node_hits = hits_per_rule.get(node, 0)
            pct_component = (node_hits / component_total_hits * 100) if component_total_hits > 0 else 0
            pct_graph = (node_hits / graph_total_hits * 100) if graph_total_hits > 0 else 0
            print(f"  Node {node}: {node_hits} hits ({pct_component:.1f}% of component, {pct_graph:.1f}% of graph)")

        if component_total_hits > 0:
            top_node = max(comp, key=lambda n: hits_per_rule.get(n, 0))
            print(f"  🔺 Dominant node: {top_node} with {hits_per_rule.get(top_node, 0)} hits")
        else:
            print("  ⚠️ No hit data for this component.")

    # Recommendation: prioritize components by hit volume
    print("\n🧭 Recommendation: Consider applying firewall rules from components with highest hit counts first:")
    component_hits.sort(key=lambda x: x[1], reverse=True)
    for comp_id, total in component_hits:
        print(f"  → Component {comp_id} (total hits: {total})")

# Main analysis function
def analyze_conflict_graph(graph, dfs_threshold=3):
    visited = set()
    components = []

    # Detect connected components
    for node in graph.nodes:
        if node not in visited:
            component = bfs_connected_component(graph, node, visited)
            components.append(component)

    components.sort(key=len, reverse=True)
    main_component_nodes = components[0]
    other_component_nodes = set()
    for comp in components[1:]:
        other_component_nodes.update(comp)

    print(f"🔎 Total connected components: {len(components)}\n")

    # Analyze conflict types and DFS per component
    for i, comp in enumerate(components, 1):
        print(f"🧩 Component {i}: {sorted(comp)}")

        conflict_stats = count_conflicts_by_type(graph, comp)
        for node, conflict_types in conflict_stats.items():
            total_conflicts = sum(conflict_types.values())
            print(f"  Node {node}: {total_conflicts} conflict(s): {dict(conflict_types)}")
            if total_conflicts >= dfs_threshold:
                dfs_chain = dfs_deep_conflict_chain(graph, node, set())
                print(f"    ↳ DFS from node {node}: {dfs_chain}")

    # Call hit analyzer at the end
    hits_per_rule = get_hits()
    hit_analyzer(components, hits_per_rule)

    return main_component_nodes, other_component_nodes, len(components)

