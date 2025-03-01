from Functions.conflict_detection_functions import is_port_range_subset, is_redundant, rule_have_x_any, have_insecure_protocols, is_remaining_traffic_denied

# ************************************************************************** #
# ******************** PRUEBA FUNCIÓN SOLAPE DE PUERTOS ******************** #
# ************************************************************************** #
print("- PRUEBA FUNCIÓN SOLAPE DE PUERTOS:")
print(f"    ¿Hay solape entre 80-90 y 85? - {is_port_range_subset('80-90', '85')}")  # True
print(f"    ¿Hay solape entre 80-90 y 75? - {is_port_range_subset('80-90', '75')}")       # False
print(f"    ¿Hay solape entre ANY y 443? - {is_port_range_subset('ANY', '443')}")       # True
print(f"    ¿Hay solape entre ANY y ANY? - {is_port_range_subset('ANY', 'ANY')}")       # True
print(f"    ¿Hay solape entre ANY y 80? - {is_port_range_subset('ANY', '80')}")       # True
print("")



# ************************************************************************** #
# ******************* PRUEBA FUNCIÓN REGLAS REDUNDANTES ******************** #
# ************************************************************************** #
# Reglas redundantes entre sí

redundant_rule1 = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.0.0.0/16"],
    "Service": ["443"],
    "Action": "ALLOW"
}

redundant_rule2 = {
    "Source": ["192.168.1.100"],
    "Destination": ["10.0.0.50"],
    "Service": ["443"],
    "Action": "ALLOW"
}  # Redundante con redundant_rule1 (source, destination y service están contenidos)

redundant_rule3 = {
    "Source": ["10.1.1.0/24"],
    "Destination": ["192.168.10.0/24"],
    "Service": ["22-24"],
    "Action": "ALLOW"
}

redundant_rule4 = {
    "Source": ["10.1.1.50"],
    "Destination": ["192.168.10.5"],
    "Service": ["23"],
    "Action": "ALLOW"
}  # Redundante con redundant_rule3 (source, destination y service están dentro de los rangos)

redundant_rule5 = {
    "Source": ["ANY"],
    "Destination": ["10.10.10.0/24"],
    "Service": ["ANY"],
    "Action": "ALLOW"
}

redundant_rule6 = {
    "Source": ["192.168.100.0/24"],
    "Destination": ["10.10.10.50"],
    "Service": ["80"],
    "Action": "ALLOW"
}  # Redundante con redundant_rule5 (ANY lo abarca todo)

# Ejecutamos pruebas
print("- PRUEBA FUNCIÓN REGLAS REDUNDANTES:")
print(f"    {is_redundant(redundant_rule1, redundant_rule2)}")  # True
print(f"    {is_redundant(redundant_rule3, redundant_rule4)}")  # True
print(f"    {is_redundant(redundant_rule5, redundant_rule6)}")  # True

# Diferente origen
ruleA = {
    "Source": ["192.168.10.0/24"],
    "Destination": ["10.0.0.0/16"],
    "Service": ["443"],
    "Action": "ALLOW"
}

ruleB = {
    "Source": ["192.168.20.0/24"],  # No hay solape con ruleA
    "Destination": ["10.0.0.0/16"],
    "Service": ["443"],
    "Action": "ALLOW"
}
print(f"    {is_redundant(ruleA, ruleB)}")  # False

# Diferente destino
ruleC = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.10.0.0/16"],
    "Service": ["80"],
    "Action": "ALLOW"
}

ruleD = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.20.0.0/16"],  # Destino distinto
    "Service": ["80"],
    "Action": "ALLOW"
}
print(f"    {is_redundant(ruleC, ruleD)}")  # False

# Diferente servicio
ruleE = {
    "Source": ["10.0.0.0/8"],
    "Destination": ["192.168.0.0/16"],
    "Service": ["22-24"],  # SSH y Telnet
    "Action": "ALLOW"
}

ruleF = {
    "Source": ["10.0.0.0/8"],
    "Destination": ["192.168.0.0/16"],
    "Service": ["25"],  # SMTP (no está en 22-24)
    "Action": "ALLOW"
}
print(f"    {is_redundant(ruleE, ruleF)}")  # False

# Diferente acción
ruleG = {
    "Source": ["10.0.0.0/24"],
    "Destination": ["192.168.1.0/24"],
    "Service": ["443"],
    "Action": "ALLOW"
}

ruleH = {
    "Source": ["10.0.0.0/24"],
    "Destination": ["192.168.1.0/24"],
    "Service": ["443"],
    "Action": "DENY"  # Diferente acción
}
print(f"    {is_redundant(ruleG, ruleH)}")  # False

# No hay intersección en ningún campo
ruleI = {
    "Source": ["172.16.1.0/24"],
    "Destination": ["192.168.100.0/24"],
    "Service": ["3389"],  # RDP
    "Action": "ALLOW"
}

ruleJ = {
    "Source": ["10.10.10.0/24"],  # Origen distinto
    "Destination": ["10.20.20.0/24"],  # Destino distinto
    "Service": ["53"],  # DNS, servicio distinto
    "Action": "DENY"  # Acción distinta
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
    "Action": "ALLOW"
}  # Tiene 1 "ANY"

rule2 = {
    "Source": "ANY",
    "Destination": "ANY",
    "Service": "443",
    "Action": "ALLOW"
}  # Tiene 2 "ANY"

rule3 = {
    "Source": "192.168.1.0/24",
    "Destination": "10.0.0.0/24",
    "Service": "ANY",
    "Action": "ALLOW"
}  # Tiene 1 "ANY"

rule4 = {
    "Source": "ANY",
    "Destination": "ANY",
    "Service": "ANY",
    "Action": "ALLOW"
}  # Tiene 3 "ANY"

rule5 = {
    "Source": "192.168.1.0/24",
    "Destination": "10.0.0.0/24",
    "Service": "443",
    "Action": "ALLOW"
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
    "Service": ["21"],  # FTP (inseguro)
    "Action": "ALLOW"
}  # Debe devolver True

rule2 = {
    "Source": ["ANY"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["80", "443"],  # HTTP (inseguro) + HTTPS (seguro)
    "Action": "ALLOW"
}  # Debe devolver True

rule3 = {
    "Source": ["192.168.2.0/24"],
    "Destination": ["10.10.10.0/24"],
    "Service": ["443"],  # HTTPS (seguro)
    "Action": "ALLOW"
}  # Debe devolver False

rule4 = {
    "Source": ["192.168.1.0/24"],
    "Destination": ["10.0.0.0/24"],
    "Service": ["137", "139"],  # NetBIOS (inseguro)
    "Action": "ALLOW"
}  # Debe devolver True

rule5 = {
    "Source": ["10.10.10.0/24"],
    "Destination": ["192.168.1.0/24"],
    "Service": ["514"],  # Syslog UDP (inseguro)
    "Action": "ALLOW"
}  # Debe devolver True

rule6 = {
    "Source": ["192.168.5.0/24"],
    "Destination": ["10.20.20.0/24"],
    "Service": ["53", "443"],  # DNS (seguro en UDP, pero AXFR es inseguro en TCP)
    "Action": "ALLOW"
}  # Debe devolver True (porque AXFR en TCP es inseguro)

rule7 = {
    "Source": ["10.0.0.0/8"],
    "Destination": ["192.168.0.0/16"],
    "Service": ["22"],  # SSH (seguro)
    "Action": "ALLOW"
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
    {"Source": ["192.168.1.0/24"], "Destination": ["10.0.0.0/24"], "Service": ["80"], "Action": "ALLOW"},
    {"Source": ["ANY"], "Destination": ["ANY"], "Service": ["ANY"], "Action": "DENY"}  # Bloquea todo
]

# Caso 2: Última regla bloquea solo un subconjunto del tráfico (debe devolver False)
rules2 = [
    {"Source": ["192.168.1.0/24"], "Destination": ["10.0.0.0/24"], "Service": ["80"], "Action": "ALLOW"},
    {"Source": ["192.168.1.0/24"], "Destination": ["10.0.0.0/24"], "Service": ["ANY"], "Action": "DENY"}  # No bloquea todo
]

# Caso 3: No hay reglas (debe devolver False)
rules3 = []

# Caso 4: Última regla permite todo el tráfico (debe devolver False)
rules4 = [
    {"Source": ["ANY"], "Destination": ["ANY"], "Service": ["ANY"], "Action": "ALLOW"}
]

# Caso 5: Última regla bloquea tráfico pero no todos los destinos (debe devolver False)
rules5 = [
    {"Source": ["ANY"], "Destination": ["10.0.0.0/24"], "Service": ["ANY"], "Action": "DENY"}
]

rules6 = rules2 + rules3 + rules4 + rules5 + rules1
# Ejecutamos las pruebas
print("- PRUEBA FUNCIÓN DENIEGO TRÁFICO RESTANTE:")
print("     Caso 1:", is_remaining_traffic_denied(rules1))  # True
print("     Caso 2:", is_remaining_traffic_denied(rules2))  # False
print("     Caso 3:", is_remaining_traffic_denied(rules3))  # False
print("     Caso 4:", is_remaining_traffic_denied(rules4))  # False
print("     Caso 5:", is_remaining_traffic_denied(rules5))  # False
print("     Caso 6:", is_remaining_traffic_denied(rules6))  # False

