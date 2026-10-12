from Functions.conflict_detection_functions import is_port_range_subset,is_redundant, rule_have_x_any, have_insecure_protocols, is_remaining_traffic_denied, is_disabled, is_not_in_use, is_shadowed, is_subnet_of_v2
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ************************************************************************** #
# ******************** PRUEBA FUNCIÓN SOLAPE DE PUERTOS ******************** #
# ************************************************************************** #
print("- PRUEBA FUNCIÓN SOLAPE DE PUERTOS:")
print(f"    ¿Hay solape entre ANY y 85,95? - {is_port_range_subset('ANY', '85,95')}")  # True
print(f"    ¿Hay solape entre 80-90 y ANY? - {is_port_range_subset('80-90', 'ANY')}")  # True


print(f"    ¿Hay solape entre 80-90 y 85,95? - {is_port_range_subset('80-90', '85,95')}")  # True
print(f"    ¿Hay solape entre 80,90 y 75? - {is_port_range_subset('80,90', '75')}")       # False
print(f"    ¿Hay solape entre 80,75 y 75? - {is_port_range_subset('80,75', '75')}")       # True
print(f"    ¿Hay solape entre ANY y 443? - {is_port_range_subset('ANY', '443')}")       # True
print(f"    ¿Hay solape entre ANY y ANY? - {is_port_range_subset('ANY', 'ANY')}")       # True
print(f"    ¿Hay solape entre ANY y 80? - {is_port_range_subset('ANY', '80')}")       # True
print("")



# ************************************************************************** #
# ******************** PRUEBA FUNCIÓN SOLAPE DE SUBREDES ******************* #
# ************************************************************************** #
print("- PRUEBA FUNCIÓN SOLAPE DE SUBREDES:")
print(f"    ¿Hay solape entre 0.0.0.0/0 y 10.0.0.0/24? - {is_subnet_of_v2('0.0.0.0/0', '10.0.0.0/24')}")  # True
print(f"    ¿Hay solape entre 10.0.0.0/24 y 0.0.0.0/0? - {is_subnet_of_v2('10.0.0.0/24', '0.0.0.0/0')}")  # partial

print(f"    ¿Hay solape entre 10.0.0.0/24 y 10.0.0.0/23? - {is_subnet_of_v2('10.0.0.0/24', '10.0.0.0/23')}")  # partial
print(f"    ¿Hay solape entre 10.0.0.0/24 y 10.0.1.0/24? - {is_subnet_of_v2('10.0.0.0/24', '10.0.1.0/24')}")  # False
print(f"    ¿Hay solape entre 10.0.0.0/24 y 10.0.0.0/24? - {is_subnet_of_v2('10.0.0.0/24', '10.0.0.0/24')}")  # True
print(f"    ¿Hay solape entre 10.0.0.0/24 y 10.0.0.128/25? - {is_subnet_of_v2('10.0.0.0/24', '10.0.0.128/25')}")  # partial
print(f"    ¿Hay solape entre 10.0.0.0/24 y 10.0.0.64/26? - {is_subnet_of_v2('10.0.0.0/24', '10.0.0.64/26')}")  # partial
print(f"    ¿Hay solape entre 10.0.0.0/25 y 10.0.0.0/24? - {is_subnet_of_v2('10.0.0.0/25', '10.0.0.0/24')}")  # partial
print(f"    ¿Hay solape entre 10.0.0.50 y 10.0.0.0/24? - {is_subnet_of_v2('10.0.0.50', '10.0.0.0/24')}")  # True
print(f"    ¿Hay solape entre 10.0.0.50,10.0.0.100 y 10.0.0.0/25? - {is_subnet_of_v2('10.0.0.50,10.0.0.100', '10.0.0.0/25')}")  # partial
print(f"    ¿Hay solape entre 10.0.0.50-10.0.0.100 y 10.0.0.1,10.0.0.100? - {is_subnet_of_v2('10.0.0.50-10.0.0.100', '10.0.0.1,10.0.0.100')}")  # partial
print("")




# ************************************************************************** #
# ******************* PRUEBA FUNCIÓN REGLAS REDUNDANTES ******************** #
# ************************************************************************** #
# Reglas redundantes entre sí

redundant_rule1 = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.0.0.0/16"],
    "Service": ["443"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

redundant_rule2 = {
    "Source": ["192.168.1.100"],
    "Destination": ["10.0.0.50"],
    "Service": ["443"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Redundante con redundant_rule1 (source, destination y service están contenidos)

redundant_rule3 = {
    "Source": ["10.1.1.0/24"],
    "Destination": ["192.168.10.0/24"],
    "Service": ["22-24"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

redundant_rule4 = {
    "Source": ["10.1.1.50"],
    "Destination": ["192.168.10.5"],
    "Service": ["23"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Redundante con redundant_rule3 (source, destination y service están dentro de los rangos)

redundant_rule5 = {
    "Source": ["ANY"],
    "Destination": ["10.10.10.0/24"],
    "Service": ["ANY"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

redundant_rule6 = {
    "Source": ["192.168.100.0/24"],
    "Destination": ["10.10.10.50"],
    "Service": ["80"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Redundante con redundant_rule5 (ANY lo abarca todo)

redundant_rule7 = {
    "Source": ["172.132.0.0/24, 192.168.1.1"],
    "Destination": ["10.10.10.50"],
    "Service": ["80"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  

redundant_rule8 = {
    "Source": ["172.132.0.1"],
    "Destination": ["10.10.10.50"],
    "Service": ["80"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
} 

# Ejecutamos pruebas
print("- PRUEBA FUNCIÓN REGLAS REDUNDANTES:")
print(f"    {is_redundant(redundant_rule1, redundant_rule2)}")  # True
print(f"    {is_redundant(redundant_rule3, redundant_rule4)}")  # True
print(f"    {is_redundant(redundant_rule5, redundant_rule6)}")  # True
print(f"    {is_redundant(redundant_rule6, redundant_rule7)}")  # True
print(f"    {is_redundant(redundant_rule7, redundant_rule8)}")  # True



# Diferente origen
ruleA = {
    "Source": ["192.168.10.0/24"],
    "Destination": ["10.0.0.0/16"],
    "Service": ["443"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

ruleB = {
    "Source": ["192.168.20.0/24"],  # No hay solape con ruleA
    "Destination": ["10.0.0.0/16"],
    "Service": ["443"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}
print(f"    {is_redundant(ruleA, ruleB)}")  # False

# Diferente destino
ruleC = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.10.0.0/16"],
    "Service": ["80"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

ruleD = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.20.0.0/16"],  # Destino distinto
    "Service": ["80"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}
print(f"    {is_redundant(ruleC, ruleD)}")  # False

# Diferente servicio
ruleE = {
    "Source": ["10.0.0.0/8"],
    "Destination": ["192.168.0.0/16"],
    "Service": ["22-24"],  # SSH y Telnet
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

ruleF = {
    "Source": ["10.0.0.0/8"],
    "Destination": ["192.168.0.0/16"],
    "Service": ["25"],  # SMTP (no está en 22-24)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}
print(f"    {is_redundant(ruleE, ruleF)}")  # False

# Diferente acción
ruleG = {
    "Source": ["10.0.0.0/24"],
    "Destination": ["192.168.1.0/24"],
    "Service": ["443"],
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

ruleH = {
    "Source": ["10.0.0.0/24"],
    "Destination": ["192.168.1.0/24"],
    "Service": ["443"],
    "Action": "DENY",   # Accion distinta
    "Hit Count": "341",
    "Status": "Enabled"
}
print(f"    {is_redundant(ruleG, ruleH)}")  # False

# No hay intersección en ningún campo
ruleI = {
    "Source": ["172.16.1.0/24"],
    "Destination": ["192.168.100.0/24"],
    "Service": ["3389"],  # RDP
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}

ruleJ = {
    "Source": ["10.10.10.0/24"],  # Origen distinto
    "Destination": ["10.20.20.0/24"],  # Destino distinto
    "Service": ["53"],  # DNS, servicio distinto
    "Action": "DENY",  # Accion distinta
    "Hit Count": "341",
    "Status": "Enabled" 
}
print(f"    {is_redundant(ruleI, ruleJ)}")  # False
print("")



# ************************************************************************** #
# ********************* PRUEBA FUNCIÓN REGLAS CON ANY ********************** #
# ************************************************************************** #
# Reglas de prueba
rule1 = {
    "Source": "ANY",
    "Destination": "10.0.0.0/24",
    "Service": "80",
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Tiene 1 "ANY"

rule2 = {
    "Source": "ANY",
    "Destination": "ANY",
    "Service": "443",
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Tiene 2 "ANY"

rule3 = {
    "Source": "192.168.1.0/24",
    "Destination": "10.0.0.0/24",
    "Service": "ANY",
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Tiene 1 "ANY"

rule4 = {
    "Source": "ANY",
    "Destination": "ANY",
    "Service": "ANY",
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Tiene 3 "ANY"

rule5 = {
    "Source": "192.168.1.0/24",
    "Destination": "10.0.0.0/24",
    "Service": "443",
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # No tiene "ANY"

# Pruebas e impresión de resultados
print("- PRUEBA FUNCIÓN REGLAS CON ANY:")
for i, rule in enumerate([rule1, rule2, rule3, rule4, rule5], start=1):
    have_any, quantity = rule_have_x_any(rule)
    print(f"    Regla {i}: Tiene ANY? {have_any}, Cantidad de ANYs: {quantity}")
print("")


# ************************************************************************** #
# ******************* PRUEBA FUNCIÓN PROTOCOLOS INSEGUROS ****************** #
# ************************************************************************** #
# Reglas de prueba
rule1 = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["443, 53, 21, 47, 80, 81, 82, 83, 87, 443, 500, 4500, 500, 143, 993, 88, 123, 110, 1723, 554, 80, 25, 465, 22, 1024-65535, 85, 86, 90, 125, 451, 563, 587, 778, 779, 873, 880, 4, 8, 23, 1024-65535, 2000, 10000"],  # FTP (inseguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Debe devolver True

rule2 = {
    "Source": ["ANY"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["80", "443"],  # HTTP (inseguro) + HTTPS (seguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Debe devolver True

rule3 = {
    "Source": ["192.168.2.0/24"],
    "Destination": ["10.10.10.0/24"],
    "Service": ["443"],  # HTTPS (seguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Debe devolver False

rule4 = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["137", "139"],  # NetBIOS (inseguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Debe devolver True

rule5 = {
    "Source": ["10.10.10.0/24"],
    "Destination": ["192.168.1.0/24"],
    "Service": ["514"],  # Syslog UDP (inseguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Debe devolver True

rule6 = {
    "Source": ["192.168.5.0/24"],
    "Destination": ["10.20.20.0/24"],
    "Service": ["53", "443"],  # DNS (seguro en UDP, pero AXFR es inseguro en TCP)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Debe devolver True (porque AXFR en TCP es inseguro)

rule7 = {
    "Source": ["10.0.0.0/8"],
    "Destination": ["192.168.0.0/16"],
    "Service": ["22"],  # SSH (seguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  # Debe devolver False

# Pruebas e impresión de resultados
print("- PRUEBA FUNCIÓN PROTOCOLOS INSEGUROS:")
rules = [rule1, rule2, rule3, rule4, rule5, rule6, rule7]
for i, rule in enumerate(rules, start=1):
    result = have_insecure_protocols(rule)
    print(f"    Regla {i}: Tiene protocolos inseguros? {result}")
print("")

# ************************************************************************** #
# ***************** PRUEBA FUNCIÓN DENIEGO TRÁFICO RESTANTE **************** #
# ************************************************************************** #
# Reglas de prueba

# Caso 1: Última regla bloquea todo el tráfico (debe devolver True)
rules1 = [
    {"Source": ["192.168.1.0/24"], "Destination": ["10.0.0.0/24"], "Service": ["80"], "Action": "ALLOW", "Hit Count": "341", "Status": "Enabled"},
    {"Source": ["ANY"], "Destination": ["ANY"], "Service": ["ANY"], "Action": "DENY", "Hit Count": "341", "Status": "Enabled"}  # Bloquea todo
]

# Caso 2: Última regla bloquea solo un subconjunto del tráfico (debe devolver False)
rules2 = [
    {"Source": ["192.168.1.0/24"], "Destination": ["10.0.0.0/24"], "Service": ["80"], "Action": "ALLOW", "Hit Count": "341", "Status": "Enabled"},
    {"Source": ["192.168.1.0/24"], "Destination": ["10.0.0.0/24"], "Service": ["ANY"], "Action": "DENY", "Hit Count": "341", "Status": "Enabled"}  # No bloquea todo
]

# Caso 3: No hay reglas (debe devolver False)
rules3 = []

# Caso 4: Última regla permite todo el tráfico (debe devolver False)
rules4 = [
    {"Source": ["ANY"], "Destination": ["ANY"], "Service": ["ANY"], "Action": "ALLOW", "Hit Count": "341", "Status": "Enabled"}
]

# Caso 5: Última regla bloquea tráfico pero no todos los destinos (debe devolver False)
rules5 = [
    {"Source": ["ANY"], "Destination": ["10.0.0.0/24"], "Service": ["ANY"], "Action": "DENY", "Hit Count": "341", "Status": "Enabled"}
]

rules6 = rules2 + rules3 + rules4 + rules5 + rules1
# Ejecutamos las pruebas
print("- PRUEBA FUNCIÓN DENIEGO TRÁFICO RESTANTE:")

last_enabled_rule = None  # Variable para almacenar la última regla habilitada
for i, rule1 in enumerate(rules1):
    if i == len(rules) - 1:
        if not is_remaining_traffic_denied(last_enabled_rule):
            logging.info(f"Caso 1:  CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")
last_enabled_rule = None  # Variable para almacenar la última regla habilitada
for i, rule1 in enumerate(rules2):
    if i == len(rules) - 1:
        if not is_remaining_traffic_denied(last_enabled_rule):
            logging.info(f"Caso 2:  CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")
last_enabled_rule = None  # Variable para almacenar la última regla habilitada
for i, rule1 in enumerate(rules3):
    if i == len(rules) - 1:
        if not is_remaining_traffic_denied(last_enabled_rule):
            logging.info(f"Caso 3:  CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")
last_enabled_rule = None  # Variable para almacenar la última regla habilitada
for i, rule1 in enumerate(rules4):
    if i == len(rules) - 1:
        if not is_remaining_traffic_denied(last_enabled_rule):
            logging.info(f"Caso 4:  CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")
last_enabled_rule = None  # Variable para almacenar la última regla habilitada
for i, rule1 in enumerate(rules5):
    if i == len(rules) - 1:
        if not is_remaining_traffic_denied(last_enabled_rule):
            logging.info(f"Caso 5:  CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")
last_enabled_rule = None  # Variable para almacenar la última regla habilitada
for i, rule1 in enumerate(rules6):
    if i == len(rules) - 1:
        if not is_remaining_traffic_denied(last_enabled_rule):
            logging.info(f"Caso 6:  CONFLICT DETECTED: Last rule, with ID: {rule1['ID']}, does NOT DENY REMAINING TRAFFIC.")

# print("     Caso 1:", is_remaining_traffic_denied(rules1))  # True
# print("     Caso 2:", is_remaining_traffic_denied(rules2))  # False
# print("     Caso 3:", is_remaining_traffic_denied(rules3))  # False
# print("     Caso 4:", is_remaining_traffic_denied(rules4))  # False
# print("     Caso 5:", is_remaining_traffic_denied(rules5))  # False
# print("     Caso 6:", is_remaining_traffic_denied(rules6))  # False

# ************************************************************************** #
# ******************* PRUEBA FUNCIÓN REGLAS DESHABILITADAS ***************** #
# ************************************************************************** #
rule_enabled_1 = {
    "Source": ["ANY"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["80", "443"],  # HTTP (inseguro) + HTTPS (seguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  

rule_enabled_2 = {
    "Source": ["ANY"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["80", "443"],  # HTTP (inseguro) + HTTPS (seguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Enabled"
}  

rule_disabled_1 = {
    "Source": ["ANY"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["80", "443"],  # HTTP (inseguro) + HTTPS (seguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Disabled"
}  

rule_disabled_2 = {
    "Source": ["ANY"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["80", "443"],  # HTTP (inseguro) + HTTPS (seguro)
    "Action": "ALLOW",
    "Hit Count": "341",
    "Status": "Disabled"
}  

print("- PRUEBA FUNCIÓN IS_DISABLED:")
for i, rule in enumerate([rule_enabled_1, rule_enabled_2, rule_disabled_1, rule_disabled_2], start=1):
    print(f"    Regla {i}: Está deshabilitada? {is_disabled(rule)}")
print("")



# ************************************************************************** #
# ********************* PRUEBA FUNCIÓN IS_NOT_IN_USE *********************** #
# ************************************************************************** #
rule_with_hits = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.0.0.0/16"],
    "Service": ["443"],
    "Action": "ALLOW",
    "Status": "Disabled",
    "Hit Count": "0"
}

rule_without_hits = {
    "Source": ["192.168.1.100"],
    "Destination": ["10.0.0.50"],
    "Service": ["443"],
    "Action": "ALLOW",
    "Status": "Disabled",
    "Hit Count": "5"
}  

print("- PRUEBA FUNCIÓN IS_NOT_IN_USE:")
for i, rule in enumerate([rule_with_hits, rule_without_hits], start=1):
    print(f"    Regla {i}: No está en uso? {is_not_in_use(rule)}")
print("")



# ************************************************************************** #
# ********************* PRUEBA FUNCIÓN REGLAS SHADOWED ********************* #
# ************************************************************************** #
test_rules = [
    {"ID": 14, "Source": ["192.168.1.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["ALL"], "Action": "ALLOW", "Status": "Enabled"},
    #{"ID": 16, "Source": ["192.168.1.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["ALL"], "Action": "DENY", "Status": "Enabled"},      # Partially Shadow with 3
    {"ID": 103, "Source": ["192.168.1.0/24"], "Destination": ["10.0.1.0/24, 1.1.1.1"], "Service": ["ALL"], "Action": "DENY", "Status": "Enabled"},             # Partially Shadow with 3
    #{"ID": 104, "Source": ["192.168.1.1"], "Destination": ["1.1.1.1"], "Service": ["ALL"], "Action": "DENY", "Status": "Enabled"},             # Partially Shadow with 3
    {"ID": 105, "Source": ["0.0.0.0/0"], "Destination": ["0.0.0.0/0"], "Service": ["ALL"], "Action": "DENY", "Status": "Enabled"}]             # Partially Shadow with 3
    
# test_rules = [
#     {"ID": 3, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["80, 8080, 443"], "Action": "ALLOW", "Status": "Enabled"},
#     {"ID": 4, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["8080, 8081"], "Action": "DENY", "Status": "Enabled"},      # Partially Shadow with 3
#     {"ID": 5, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/16"], "Service": ["80"], "Action": "ALLOW", "Status": "Enabled"},             # Partially Shadow with 3
#     {"ID": 6, "Source": ["10.0.0.0/28"], "Destination": ["10.0.1.0/24"], "Service": ["80"], "Action": "DENY", "Status": "Enabled"},              # Fully Shadow with 3 & 5
#     {"ID": 7, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["80"], "Action": "ALLOW", "Status": "Enabled"},
#     {"ID": 8, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/16"], "Service": ["80"], "Action": "DENY", "Status": "Enabled"},
#     {"ID": 9, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["80"], "Action": "ALLOW", "Status": "Enabled"},
#     {"ID": 10, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["3128 - 3200"], "Action": "DENY", "Status": "Enabled"},
#     {"ID": 11, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["80"], "Action": "ALLOW", "Status": "Enabled"},
#     {"ID": 12, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["80"], "Action": "DENY", "Status": "Enabled"},
#     {"ID": 13, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["80, 8080"], "Action": "ALLOW", "Status": "Enabled"},
#     {"ID": 14, "Source": ["10.0.0.0/24"], "Destination": ["10.0.1.0/24"], "Service": ["8080"], "Action": "DENY", "Status": "Enabled"}
# ]

# Ejecutamos pruebas
print("\n\n\n- PRUEBA FUNCIÓN REGLAS SHADOW:")
conflicts = []
for i, rule1 in enumerate(test_rules):
    
    print(f"  INICIO ITERACIÓN REGLA {rule1['ID']}")
    
    for j, rule2 in enumerate(test_rules):
        print(int(rule2['ID']) > int(rule1['ID']))
        if i != j and (int(rule2['ID']) > int(rule1['ID'])):
            print(f"  Regla {rule1['ID']}: {rule1}")
            print(f"  Regla {rule2['ID']}: {rule2}")
            
            shadowed, conflict_type = is_shadowed(rule1, rule2)
            if shadowed:
                logging.info(f"CONFLICT DETECTED: Rule with ID {rule2['ID']} is {conflict_type.upper()} with {rule1['ID']}.")
                print(f"  Regla {rule1['ID']}: {rule1}")
                print(f"  Regla {rule2['ID']}: {rule2}")
                print(f"  Shadow Type: {conflict_type}")
                print("  --------------------------------")
                conflicts.append(conflict_type)
        print(f"FIN ITERACIÓN REGLA {rule1['ID']} con {rule2['ID']}")
    print(f"  FIN ITERACIÓN REGLA {rule1['ID']}\n")

print(conflicts)



cases = [
        # Subred completamente contenida
        ("10.0.0.0/8", "10.1.1.0/24", True),
        ("192.168.1.0/24", "192.168.1.0/25", True),

        # Subred parcialmente solapada (corregido)
        ("192.168.1.0/25", "192.168.1.64/24", "Partial"),

        # Subred completamente fuera
        ("192.168.1.0/24", "10.0.0.0/24", False),

        # IP individual dentro
        ("192.168.1.0/24", "192.168.1.42", True),

        # IP fuera
        ("192.168.1.0/24", "10.0.0.1", False),

        # Rango completamente dentro
        ("192.168.1.0/24", "192.168.1.1 - 192.168.1.3", True),

        # Rango parcialmente dentro
        ("192.168.1.0/24", "192.168.1.250 - 192.168.2.10", "Partial"),

        # Mezcla: IP + subred contenidas
        ("192.168.0.0/16", "192.168.1.1, 192.168.1.0/24", True),

        # Mezcla: una dentro y otra fuera
        ("192.168.1.0/24", "192.168.1.1, 10.0.0.1", "Partial"),

        # 0.0.0.0/0 (todo el espacio) como contenedor
        ("0.0.0.0/0", "8.8.8.8", True),
        ("0.0.0.0/0", "192.168.1.0/24", True),
        ("0.0.0.0/0", "10.0.0.0/8, 8.8.8.8", True),

        # Inverso: elemento contra 0.0.0.0/0
        ("192.168.1.0/24", "0.0.0.0/0", "Partial"),
        ("192.168.1.1", "0.0.0.0/0", "Partial"),

        # ✅ Nuevo caso: mezcla rango + red vs dos subredes
        ("10.0.0.1-10.0.0.15, 10.0.1.0/24", "10.0.0.0/24, 10.0.1.0/24", "Partial"),

        # ✅ Nuevo caso: set + 0.0.0.0
        ("10.0.1.0/24, 1.1.1.1", "0.0.0.0/0", "Partial"),

        ("172.132.0.1", "172.132.0.0/24, 192.168.1.1", "Partial"),

        ("172.132.0.0/24, 192.168.1.1", "172.132.0.1", True),


    ]

for i, (subnet1, subnet2, expected) in enumerate(cases, 1):
    result = is_subnet_of_v2(subnet1, subnet2)
    print(result)
    assert result == expected, f"❌ Test {i} failed: {subnet1} vs {subnet2} => got {result}, expected {expected}"
    print(f"✅ Test {i} passed: {subnet1} vs {subnet2} => {result}")


print("\n- TEST FORMAL: is_redundant con asserts")

redundant_test_cases = [
    # Totalmente redundante
    (redundant_rule1, redundant_rule2, True),
    (redundant_rule3, redundant_rule4, True),
    (redundant_rule5, redundant_rule6, True),
    (redundant_rule6, redundant_rule7, False),
    (redundant_rule7, redundant_rule8, True),

    # Distinta fuente
    (ruleA, ruleB, False),

    # Distinto destino
    (ruleC, ruleD, False),

    # Distinto servicio
    (ruleE, ruleF, False),

    # Distinta acción
    (ruleG, ruleH, False),

    # No hay solapamiento en ningún campo
    (ruleI, ruleJ, False),
]

result = is_subnet_of_v2("172.132.0.1", "172.132.0.0/24, 192.168.1.1")
print(f"Resultado Prueba: {result}")

for i, (r1, r2, expected) in enumerate(redundant_test_cases, start=1):
    print(f"\nTest {i}:")
    print(f"    - Rule1: {r1}")
    print(f"    - Rule2: {r2}")
    result = is_redundant(r1, r2)
    assert result == expected, f"❌ Test {i} failed: expected {expected}, got {result}"
    print(f"✅ Test {i} passed: expected {expected}, got {result}")