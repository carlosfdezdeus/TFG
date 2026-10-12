import sqlite3
import networkx as nx
import numpy as np
from matplotlib.patches import FancyArrowPatch
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D  
from collections import defaultdict, deque
from Functions.config import DB_FW_CONFLICTS, CONFLICT_GRAPH_PATH, OPTIMIZED_CONFLICT_GRAPH_PATH, CONFLICT_LINE_STYLES, UNARY_CONFLICT_COLORS
from Functions.file_management_functions import save_conflict_graph, get_hits, getConflicts


# Construir grafo con estilos para dibujar
def build_drawable_conflict_graph(database):
    conflicts = getConflicts(database)
    G = nx.Graph()
    edge_styles = defaultdict(set)
    node_conflicts = defaultdict(set)

    for rule1, rule2, conflict_type in conflicts:
        # print(f"{rule1} - {rule2}: {conflict_type}")

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

def build_real_conflict_graph(database):
    conflicts = getConflicts(database)
    G = nx.Graph()
    edge_styles = defaultdict(set)
    node_conflicts = defaultdict(set)

    for rule1, rule2, conflict_type in conflicts:
        # print(f"{rule1} - {rule2}: {conflict_type}")

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

def draw_conflict_graph(show=True, database=DB_FW_CONFLICTS, optimized=False):
    def generar_leyenda_completa(node_conflicts, output_path="legend_conflicts_full.png"):
        import textwrap
        legend_items = []

        # Conflictos binarios → líneas
        for conflict, (style, color) in CONFLICT_LINE_STYLES.items():
            legend_items.append(
                Line2D([0], [0], color=color, linestyle=style, linewidth=2, label=conflict)
            )

        # Conflictos unarios → puntos con lista completa de nodos
        for conflict, nodes in node_conflicts.items():
            if conflict in UNARY_CONFLICT_COLORS:
                color = UNARY_CONFLICT_COLORS[conflict]
                nodos_txt = ', '.join(map(str, sorted(nodes)))

                # ⚠️ Envuelve si el texto supera cierto largo (~80 caracteres)
                wrapped_lines = textwrap.wrap(nodos_txt, width=160)
                for i, line in enumerate(wrapped_lines):
                    label = f"{conflict}: {line}" if i == 0 else f"    {line}"
                    legend_items.append(
                        Line2D([0], [0],
                            marker='o',
                            linestyle='None',
                            color='white',
                            markerfacecolor=color,
                            markersize=10,
                            label=label)
                    )

        # Crear figura solo con la leyenda
        fig_height = max(3, len(legend_items) * 0.6)
        fig, ax = plt.subplots(figsize=(12, fig_height))
        ax.axis('off')

        ax.legend(
            handles=legend_items,
            loc='center',
            frameon=True,
            fontsize=8
        )

        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close(fig)

        print(f"✅ Leyenda completa guardada en: {output_path}")



    monitorice = False
    title = "Grafo de Conflictos de Reglas de Firewall sin optimizar"
    if optimized:
        title = "Grafo de Conflictos de Reglas de Firewall optimizadas"

    G, edge_styles, node_conflicts = build_drawable_conflict_graph(database)

    conflict_graph = plt.figure(figsize=(18, 12))
    ax = conflict_graph.add_subplot(1, 1, 1)
    pos = nx.spring_layout(G, seed=42)

    last_node = max(G.nodes)
    remaining_conflict_nodes = node_conflicts.get("Remaining traffic not denied", set())
    hide_last_node = last_node not in remaining_conflict_nodes
    if hide_last_node:
        G.remove_node(last_node)
        pos.pop(last_node, None)

    for (n1, n2), conflict_types in edge_styles.items():
        if n1 not in G.nodes or n2 not in G.nodes:
            continue
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

    node_conflict_map = defaultdict(list)
    for conflict_type, nodes in node_conflicts.items():
        if conflict_type in ["Redundant", "Fully Shadowed", "Partially Shadowed"]:
            continue
        color = UNARY_CONFLICT_COLORS.get(conflict_type, "gray")
        for node in nodes:
            if node in G.nodes:
                node_conflict_map[node].append(color)

    all_x = [x for x, y in pos.values()]
    all_y = [y for x, y in pos.values()]
    center_x = sum(all_x) / len(all_x)
    center_y = sum(all_y) / len(all_y)

    spacing = 0.06
    for node in G.nodes:
        colors = node_conflict_map.get(node, [])

        any_conflicts = {
            "Any: Service",
            "Any: Origin",
            "Any: Destination",
            "Any: 2 fields",
            "Any: 3 fields"
        }

        should_monitor = False
        if optimized:
            if "Insecure" in node_conflicts and node in node_conflicts["Insecure"]:
                should_monitor = True
            else:
                for any_type in any_conflicts:
                    if any_type in node_conflicts and node in node_conflicts[any_type]:
                        should_monitor = True
                        break

        if should_monitor:
            colors = colors + ["darkblue"]
            monitorice = True

        if not colors:
            continue

        if node in pos:
            x, y = pos[node]
            dx = x - center_x
            dy = y - center_y
            norm = np.hypot(dx, dy)
            if norm == 0:
                dx, dy = 1, 0
                norm = 1
            dx /= norm
            dy /= norm
            base_x = x + dx * 0.15
            base_y = y + dy * 0.15
            for i, color in enumerate(colors):
                dot_x = base_x + dx * i * spacing
                dot_y = base_y + dy * i * spacing
                ax.plot(dot_x, dot_y, 'o', color=color, markersize=10)

    # Leyenda
    legend_lines = [
        Line2D([0], [0], color=color, linestyle=style, linewidth=2, label=conf)
        for conf, (style, color) in CONFLICT_LINE_STYLES.items()
    ]

    grouped = defaultdict(list)
    for conflict, nodes in node_conflicts.items():
        color = UNARY_CONFLICT_COLORS.get(conflict, "gray")
        label = conflict
        grouped[color].append(label)

    if optimized and monitorice:
        legend_lines.append(
            Line2D([0], [0],
                   marker='o',
                   linestyle='None',
                   color='white',
                   markerfacecolor='darkblue',
                   markersize=10,
                   #label="Regla a monitorizar")
                   label="Rule to monitor")

        )

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

    ax.legend(
        handles=legend_lines,
        loc='upper center',
        bbox_to_anchor=(0.5, -0.15),
        fontsize='small',
        frameon=True,
        ncol=2
    )

    ax.set_title(title)
    ax.axis('off')
    plt.subplots_adjust(bottom=0.25)

    if hide_last_node:
        ax.text(
            1.01, 0.01,
            f"The rule with ID $\\bf{{{last_node}}}$ denies all remaining\n"
            "traffic (source: 0.0.0.0/0, destination:\n"
            "0.0.0.0/0, service: ALL, action: DENY)\n"
            "Its conflicts are expected and acceptable\n"
            "by design.",
            transform=ax.transAxes,
            fontsize='small',
            ha='left',
            va='top',
            linespacing=1.4,
            bbox=dict(
                boxstyle='round,pad=0.3',
                edgecolor='#cccccc',
                facecolor='white',
                linewidth=1
            )
        )

    # 🔽 Generar imagen adicional con todos los nodos por conflicto
    conflict_txt_img = "conflict_summary.png" if not optimized else "conflict_summary_optimized.png"
    generar_leyenda_completa(node_conflicts, output_path=conflict_txt_img)

    # Guardar imagen principal
    if optimized:
        save_conflict_graph(conflict_graph, path=OPTIMIZED_CONFLICT_GRAPH_PATH)
    else:
        save_conflict_graph(conflict_graph, path=CONFLICT_GRAPH_PATH)

    if show:
        plt.ion()
        plt.show()
        plt.pause(0.001)
    else:
        plt.close(conflict_graph)

    return G




# def draw_conflict_graph(show=True, database=DB_FW_CONFLICTS, optimized=False):
#     monitorice = False
#     title = "Grafo de Conflictos de Reglas de Firewall sin optimizar"
#     if optimized:
#         title = "Grafo de Conflictos de Reglas de Firewall optimizadas"

#     G, edge_styles, node_conflicts = build_drawable_conflict_graph(database)

#     conflict_graph = plt.figure(figsize=(14, 10))
#     ax = conflict_graph.add_subplot(1, 1, 1)
#     pos = nx.spring_layout(G, seed=42)

#     # Paso 1: Detectar la última regla (último nodo según número)
#     last_node = max(G.nodes)

#     # Paso 2: Verificar si tiene el conflicto 'Remaining traffic not denied'
#     remaining_conflict_nodes = node_conflicts.get("Remaining traffic not denied", set())

#     # Paso 3: Si no tiene ese conflicto, eliminar el nodo del grafo
#     hide_last_node = last_node not in remaining_conflict_nodes
#     if hide_last_node:
#         G.remove_node(last_node)
#         pos.pop(last_node, None)  # remover de posiciones si ya está calculado

#     # Pintar aristas con estilo según tipo de conflicto
#     for (n1, n2), conflict_types in edge_styles.items():
#         if n1 not in G.nodes or n2 not in G.nodes:
#             continue
#         conflict_types = list(conflict_types)
#         total = len(conflict_types)
#         for i, conflict_type in enumerate(conflict_types):
#             style, color = CONFLICT_LINE_STYLES[conflict_type]
#             angle = 0.2 * (i - (total - 1) / 2)
#             arrow = FancyArrowPatch(
#                 posA=pos[n1],
#                 posB=pos[n2],
#                 connectionstyle=f"arc3,rad={angle}",
#                 arrowstyle='-',
#                 linewidth=2,
#                 linestyle=style,
#                 color=color,
#                 alpha=0.8
#             )
#             ax.add_patch(arrow)

#     nx.draw_networkx_nodes(G, pos, node_size=1200, node_color='skyblue', ax=ax)
#     nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold', ax=ax)

#     # Mapeo de conflictos por nodo
#     node_conflict_map = defaultdict(list)
#     for conflict_type, nodes in node_conflicts.items():
#         if conflict_type in ["Redundant", "Fully Shadowed", "Partially Shadowed"]:
#             continue
#         color = UNARY_CONFLICT_COLORS.get(conflict_type, "gray")
#         for node in nodes:
#             if node in G.nodes:
#                 node_conflict_map[node].append(color)

#     # Calcular el centroide del grafo
#     all_x = [x for x, y in pos.values()]
#     all_y = [y for x, y in pos.values()]
#     center_x = sum(all_x) / len(all_x)
#     center_y = sum(all_y) / len(all_y)

#     # Dibujar los puntos de conflictos unarios (radialmente)
#     spacing = 0.06
#     for node in G.nodes:
#         colors = node_conflict_map.get(node, [])

#         # Añadir el punto azul si optimized y el nodo está afectado por Insecure o por algún tipo de Any
#         any_conflicts = {
#             "Any: Service",
#             "Any: Origin",
#             "Any: Destination",
#             "Any: 2 fields",
#             "Any: 3 fields"
#         }

#         should_monitor = False
#         if optimized:
#             if "Insecure" in node_conflicts and node in node_conflicts["Insecure"]:
#                 should_monitor = True
#             else:
#                 for any_type in any_conflicts:
#                     if any_type in node_conflicts and node in node_conflicts[any_type]:
#                         should_monitor = True
#                         break

#         if should_monitor:
#             colors = colors + ["darkblue"]
#             monitorice = True

#         if not colors:
#             continue

#         if node in pos:
#             x, y = pos[node]
#             dx = x - center_x
#             dy = y - center_y
#             norm = np.hypot(dx, dy)
#             if norm == 0:
#                 dx, dy = 1, 0
#                 norm = 1
#             dx /= norm
#             dy /= norm
#             base_x = x + dx * 0.15
#             base_y = y + dy * 0.15
#             for i, color in enumerate(colors):
#                 dot_x = base_x + dx * i * spacing
#                 dot_y = base_y + dy * i * spacing
#                 ax.plot(dot_x, dot_y, 'o', color=color, markersize=10)

#     # for node, colors in node_conflict_map.items():
#     #     if node in pos:
#     #         x, y = pos[node]
#     #         dx = x - center_x
#     #         dy = y - center_y
#     #         norm = np.hypot(dx, dy)
#     #         if norm == 0:
#     #             dx, dy = 1, 0
#     #             norm = 1
#     #         dx /= norm
#     #         dy /= norm
#     #         base_x = x + dx * 0.15
#     #         base_y = y + dy * 0.15
#     #         for i, color in enumerate(colors):
#     #             dot_x = base_x + dx * i * spacing
#     #             dot_y = base_y + dy * i * spacing
#     #             ax.plot(dot_x, dot_y, 'o', color=color, markersize=10)



#     # Leyenda de conflictos binarios
#     legend_lines = [
#         Line2D([0], [0], color=color, linestyle=style, linewidth=2, label=conf)
#         for conf, (style, color) in CONFLICT_LINE_STYLES.items()
#     ]

#     # Leyenda de conflictos unarios con nodos
#     grouped = defaultdict(list)
#     for conflict, nodes in node_conflicts.items():
#         color = UNARY_CONFLICT_COLORS.get(conflict, "gray")
#         label = f"{conflict}: {', '.join(map(str, sorted(nodes)))}"
#         grouped[color].append(label)

#     # Leyenda para nodos monitorizados
#     if optimized and monitorice:
#         legend_lines.append(
#             Line2D([0], [0],
#                 marker='o',
#                 linestyle='None',
#                 color='white',
#                 markerfacecolor='darkblue',
#                 markersize=10,
#                 label="Regla a monitorizar")
#         )


#     for color in ["green", "orange", "red", "black"]:
#         for label in grouped.get(color, []):
#             legend_lines.append(
#                 Line2D([0], [0],
#                        marker='o',
#                        linestyle='None',
#                        color='white',
#                        markerfacecolor=color,
#                        markersize=10,
#                        label=label)
#             )

#     legend = ax.legend(handles=legend_lines, loc='center left', bbox_to_anchor=(1, 0.5), fontsize='small', frameon=True)
#     # 🔧 Forzar rendering para obtener tamaño correcto
#     fig = plt.gcf()
#     fig.canvas.draw()  # necesario para calcular el tamaño de la leyenda

#     # Obtener altura final de la leyenda en coordenadas de figura
#     bbox = legend.get_window_extent(renderer=fig.canvas.get_renderer())
#     inv = fig.transFigure.inverted()
#     legend_bbox_fig_coords = inv.transform(bbox)
#     legend_bottom_y = legend_bbox_fig_coords[0][1]  # coordenada Y inferior

#     ax.set_title(title)
#     ax.axis('off')

#     plt.subplots_adjust(bottom=0.4)  # 🔧 más alto aún para que haya espacio real
   
#     # Nota adicional si la última regla deniega todo el tráfico
#     init_last_node_leyend = legend_bottom_y - 0.02
    
#     if hide_last_node:
#         ax.text(
#             1.01, init_last_node_leyend,
#             f"The rule with ID $\\bf{{{last_node}}}$ denies all remaining      \n"
#             "traffic (source: 0.0.0.0/0, destination: \n"
#             "0.0.0.0/0, service: ALL, action: DENY)\n"
#             "Its conflicts are expected and acceptable \n"
#             "by design.",
#             transform=ax.transAxes,
#             fontsize='small',
#             ha='left',
#             va='top',
#             linespacing=1.4,
#             bbox=dict(
#                 boxstyle='round,pad=0.3',
#                 edgecolor='#cccccc',
#                 facecolor='white',
#                 linewidth=1
#             )
#         )

#     # Guardar imagen
#     if optimized:
#         save_conflict_graph(conflict_graph, path=OPTIMIZED_CONFLICT_GRAPH_PATH)
#     else:
#         save_conflict_graph(conflict_graph, path=CONFLICT_GRAPH_PATH)

#     # Mostrar si se pide
#     if show:
#         plt.ion()
#         plt.show()
#         plt.pause(0.001)
#     else:
#         plt.close(conflict_graph)

#     return G


    
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

def hit_analyzer(components, hits_per_rule, lines):
    graph_total_hits = sum(hits_per_rule.values())
    # print(f"\n📊 Total hits across entire graph: {graph_total_hits}\n")

    component_hits = []  # To rank components

    for i, comp in enumerate(components, 1):
        print(f"Hit analysis for Component {i}:")
        # print(f"Analisis del número de hits del Subrafo {i}:")


        component_total_hits = sum(hits_per_rule.get(node, 0) for node in comp)
        component_hits.append((i, component_total_hits))

        # print(f"  🔷 Total hits in this component: {component_total_hits}")
        print(f"  - Total hits in this component: {component_total_hits}")

        if graph_total_hits > 0:
            # print(f"  🔸 This is {component_total_hits / graph_total_hits * 100:.1f}% of total graph hits")
            print(f"  - This is {component_total_hits / graph_total_hits * 100:.1f}% of total graph hits")

        else:
            print(f"  🔸 No hit data available for graph.")

        for node in sorted(comp):
            node_hits = hits_per_rule.get(node, 0)
            pct_component = (node_hits / component_total_hits * 100) if component_total_hits > 0 else 0
            pct_graph = (node_hits / graph_total_hits * 100) if graph_total_hits > 0 else 0
            print(f"  - Node {node}: {node_hits} hits ({pct_component:.1f}% of component, {pct_graph:.1f}% of graph)")

        if component_total_hits > 0:
            top_node = max(comp, key=lambda n: hits_per_rule.get(n, 0))
            print(f"  - Dominant node: {top_node} with {hits_per_rule.get(top_node, 0)} hits")
        else:
            print("  - No hit data for this component.")

    print("\n")
    
    # Recommendation: prioritize components by hit volume
    print("\n OPTIMIZATION: Consider applying firewall rules from components with highest hit counts first:")
    #PDF
    lines.append("\nOPTIMIZATION: Consider applying firewall rules from components with highest hit counts first:")
    component_hits.sort(key=lambda x: x[1], reverse=True)
    for comp_id, total in component_hits:
        print(f"  → Component {comp_id} (total hits: {total})")
        #PDF
        lines.append(f"   Component {comp_id} (total hits: {total})")
    
    return "\n".join(lines)

# Main analysis function
def analyze_conflict_graph(dfs_threshold=3):
    graph = build_real_conflict_graph(DB_FW_CONFLICTS)
    visited = set()
    components = []
    # PDF
    lines = []
    
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

    # print(f"🔎 Total connected components: {len(components)}\n")

    # Analyze conflict types and DFS per component
    for i, comp in enumerate(components, 1):
        print(f"Component {i}: {sorted(comp)}")
        #PDF
        lines.append(f"Component {i}: {sorted(comp)} \n")

        conflict_stats = count_conflicts_by_type(graph, comp)
        for node, conflict_types in conflict_stats.items():
            total_conflicts = sum(conflict_types.values())
            # print(f"  - Node {node}: {total_conflicts} conflict(s): {dict(conflict_types)}")
            if total_conflicts >= dfs_threshold:
                dfs_chain = dfs_deep_conflict_chain(graph, node, set())
                # print(f"     ↳ DFS from node {node}: {dfs_chain}")
    print("\n")
    # Call hit analyzer at the end
    hits_per_rule = get_hits()
    optimization_text_0 = hit_analyzer(components, hits_per_rule, lines)

    return optimization_text_0
    # return main_component_nodes, other_component_nodes, len(components)

