# FIREWALL SECURITY POLICY COMPLIANCE SCRIPT
This document details the functionality of the firewall security policy compliance script. It explains everything from reading rules from a JSON to saving conflictive rules in a DB.

## Conflictive rules:
- Redundant Rules
- Shadowed Rules
- Rules with ANY
- Insecure Rules
- Bidirecctional Rules
- Unused Rules
- Disabled Rules
- Deny remaining traffic Rule

## Project estructure
The project is organised as follows:

```
VULNERABILITY_AUTOMATIZATION/
│
├── Input data/
│   └── "firewall_rules.json"   # Firewall rules exported as JSON
│
├── Functions/
│   └── config.py                           # Script configuration
│   └── conflict_detection_functions.py     # Python file which contains the functions dedicated to the detect conflict rules
│   └── file_management_functions.py        # Python file with which contains the functions dedicated to the management of files like getting rules from JSON or creating a DB.
└── main.py                    # Main script file to start the revision of the firewall security policy.
```# TFG
