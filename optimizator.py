import time

from graph_detected_conflicts import conflict_rule_detector
from Functions.graphFunctions import build_real_conflict_graph, analyze_conflict_graph
from Functions.optimization_functions import optimization_1, optimization_2, optimization_3
from Functions.file_management_functions import export_pdf, display_conflictive_rules, export_json
from Functions.config import REPORT, CONFLICT_GRAPH_PATH, OPTIMIZED_CONFLICT_GRAPH_PATH


if __name__ == '__main__':
    start_total = time.time()
    optimization_sections = {}

    # Detecto los conflictos y creo el grafo
    start_detect = time.time()
    rules_to_optimize, graph_time = conflict_rule_detector()
    detect_time = time.time() - start_detect
    # for rule_to_optimize in rules_to_optimize:
    #     print(rule_to_optimize)

    print("**************** OPTIMIZACIÓN 0: ****************")
    start_opt = time.time()
    conflictive_rules_text = display_conflictive_rules()
    optimization_text_0 = analyze_conflict_graph()
    optimization_sections["OPTIMIZATION 0 – Subgraph Prioritization"] = optimization_text_0.splitlines()

    print("**************** OPTIMIZACIÓN 1: ****************")
    optimized_rules, optimization_text_1 = optimization_1(rules_to_optimize)
    optimization_sections["OPTIMIZATION 1 – Individual Anomalies (Disabled, Insecure, Not in use and ANY)"] = optimization_text_1

    print("**************** OPTIMIZACIÓN 2: ****************")
    optimized_rules, optimization_text_2 = optimization_2(optimized_rules)
    optimization_sections["OPTIMIZATION 2 – Redundant Anomalies"] = optimization_text_2
    

    print("**************** OPTIMIZACIÓN 3: ****************")
    optimized_rules, optimization_text_3 = optimization_3(optimized_rules)
    optimization_sections["OPTIMIZATION 3 – Fully Shadowed Anomalies"] = optimization_text_3
    opt_time = time.time() - start_opt
    total_time_without_export = time.time() - start_total

    print("\n")

    # for optimized_rule in optimized_rules:
    #     print(f"OPTIMIZED RULE: {optimized_rule}")

    conflict_rule_detector(False, optimized_rules)
    

    export_pdf(REPORT, optimization_sections, CONFLICT_GRAPH_PATH, OPTIMIZED_CONFLICT_GRAPH_PATH, "Carlos Fernando Fernández Deus")

    export_json(optimized_rules)
    total_time_with_export = time.time() - start_total

    print("\n🕒 RESULTADOS DE TIEMPO DE EJECUCIÓN")
    print("--------------------------------------")
    print(f"⏱️ Tiempo total con exportación: {total_time_with_export:.2f} segundos")
    print(f"⏱️ Tiempo total sin exportación: {total_time_without_export:.2f} segundos")
    print(f"🔍 Tiempo Algoritmo de Detección de conflictos (1ª vez): {detect_time:.2f} segundos")
    print(f"📊 Tiempo Algoritmo de Graficado de conflictos (1ª vez): {graph_time:.2f} segundos")
    print(f"🛠️ Tiempo Algoritmo de Optimización: {opt_time:.2f} segundos")

