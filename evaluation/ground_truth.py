# ground truth contains only sequences consisting of techniques that were executed during scenarios
# and detected by Wazuh
GROUND_TRUTH = [
    # scenario Windows 1
    ['T1059.001', 'T1555.004', 'T1569.002', 'T1105', 'T1496'],
    ['T1059.001', 'T1555.004', 'T1018'],
    ['T1059.001', 'T1555.004', 'T1105', 'T1496'],
    ['T1059.001', 'T1078.001', 'T1569.002', 'T1105', 'T1496'],
    ['T1059.001', 'T1078.001', 'T1018'],
    ['T1059.001', 'T1078.001', 'T1105', 'T1496'],
    ['T1059.001', 'T1105', 'T1496'],
    ['T1059.001', 'T1112', 'T1105', 'T1496'],
    # scenario Windows 2
    ['T1531'],
    ['T1489'],
    ['T1082', 'T1531'],
    ['T1082', 'T1489'],
    ['T1110', 'T1082', 'T1531'],
    ['T1110', 'T1531'],
    ['T1110', 'T1489'],
    ['T1110', 'T1564.002', 'T1543.003', 'T1082', 'T1531'],
    ['T1110', 'T1564.002', 'T1543.003', 'T1082', 'T1489'],
    ['T1110', 'T1564.002', 'T1543.003', 'T1531'],
    ['T1110', 'T1564.002', 'T1543.003', 'T1489'],
    ['T1110', 'T1047', 'T1082', 'T1531'],
    ['T1110', 'T1047', 'T1082', 'T1489'],
    ['T1110', 'T1047', 'T1531'],
    ['T1110', 'T1047', 'T1489'],
    ['T1110', 'T1564', 'T1082', 'T1531'],
    ['T1110', 'T1564', 'T1082', 'T1489'],
    ['T1110', 'T1564', 'T1531'],
    ['T1110', 'T1564', 'T1489'],
    ['T1047', 'T1082', 'T1531'],
    ['T1047', 'T1082', 'T1489'],
    ['T1047', 'T1531'],
    ['T1047', 'T1489'],
    ['T1564', 'T1082', 'T1531'],
    ['T1564', 'T1082', 'T1489'],
    ['T1564', 'T1531'],
    ['T1564', 'T1489'],
    # scenario Ubuntu 1
    ['T1046', 'T1021.004', 'T1529'],
    ['T1556.003', 'T1046', 'T1021.004', 'T1529'],
    ['T1548.003', 'T1046', 'T1021.004', 'T1529'],
    ['T1136.001', 'T1046', 'T1021.004', 'T1529'],
    ['T1136.001', 'T1556.003', 'T1046', 'T1021.004', 'T1529'],
    ['T1136.001', 'T1548.003', 'T1046', 'T1021.004', 'T1529'],
    # scenario Ubuntu 2
    ['T1003.008', 'T1574.010', 'T1033', 'T1486'],
    ['T1003.008', 'T1574.010', 'T1486'],
    ['T1003.008', 'T1556.003', 'T1033', 'T1486'],
    ['T1003.008', 'T1556.003', 'T1486'],
    ['T1003.008', 'T1548.003', 'T1033', 'T1486'],
    ['T1003.008', 'T1548.003', 'T1486'],
    ['T1003.008', 'T1033', 'T1486'],
    ['T1003.008', 'T1486'],
    ['T1574.010', 'T1033', 'T1486'],
    ['T1574.010', 'T1486'],
    ['T1556.003', 'T1033', 'T1486'],
    ['T1556.003', 'T1486'],
    ['T1548.003', 'T1033', 'T1486'],
    ['T1548.003', 'T1486'],
    ['T1033', 'T1486'],
    ['T1486'],
    # scenario Ubuntu 3
    ['T1059.004', 'T1078.003', 'T1548.001', 'T1033', 'T1560.001', 'T1048'],
    ['T1059.004', 'T1078.003', 'T1033', 'T1560.001', 'T1048'],
    ['T1059.004', 'T1548.001', 'T1033', 'T1560.001', 'T1048'],
    ['T1078.003', 'T1548.001', 'T1033', 'T1560.001', 'T1048'],
    ['T1078.003', 'T1033', 'T1560.001', 'T1048'],
    ['T1548.001', 'T1033', 'T1560.001', 'T1048'],
    ['T1033', 'T1560.001', 'T1048']
]

# IDs of true positive alerts
TRUE_POSITIVE_IDS = ["T1078", "T1531", "T1098", "T1543.003", "T1112", "T1105", "T1496", "T1110", "T1489", "T1136",
                     "T1556.003", "T1548.003", "T1570", "T1529", "T1048.002"]

# SCENARIOs contains attack paths for IP addresses if only detected IDs are considered
SCENARIOS = {
        # Windows 1
        "10.12.1.10": [
            ["T1078", "T1098", "T1543.003", "T1112", "T1105", "T1496"],
            ["T1531", "T1098", "T1543.003", "T1112", "T1105", "T1496"]
        ],
        # Windows 2
        "10.12.1.20": [
            ["T1098", "T1543.003", "T1098", "T1489"]
        ],
        "10.77.77.77": [
            ["T1110"]
        ],
        # Ubuntu 1
        "10.12.3.10": [
            ["T1136", "T1556.003", "T1548.003", "T1570"]
        ],
        "10.12.2.10": [
            ["T1570", "T1529"]
        ],
        # Ubuntu 2
        "10.12.3.20": [
            ["T1556.003", "T1548.003"]
        ],
        # Ubuntu 3
        "10.12.2.20": [
            ["T1136", "T1548.003", "T1048.002"],
            ["T1136", "T1078", "T1048.002"],
            ["T1078", "T1548.003", "T1048.002"]
        ]
    }

# MAPPING created for attack procedures from CALDERA that were assigned wrong ATT&CK ID in the UI but should
# be assigned different ID
MAPPING_PROCEDURES_ALERTS = {
    'T1059.001': 'T1078',  # This attack procedure was called "Impersonate user". T1078 is more relevant ID.
    'T1078.001': 'T1098',  # Similar functionality, attack procedure was "Activate Guest Account".
    'T1569.002': 'T1543.003',  # Similar functionality, attack procedure was "Execute a Command as a Service".
    'T1564.002': 'T1098',  # Attack procedure was "Create Hidden User in Registry", T1098 is not far from the truth.
    'T1564': 'T1543.003',  # Attack procedure was "Create and Hide a Service with sc.exe", T1543.003 is relevant.
    'T1531': 'T1098',  # Attack procedure was "Change User Password - Windows", T1098 is also relevant.
    'T1136.001': 'T1136',  # Parent technique.
    'T1021.004': 'T1570',  # Attack procedure "Start 54ndc47 (2)" also trasmits the agent file, T1570 is relevant.
    'T1078.003': 'T1136',  # Attack procedure was "Create local account (Linux)", T1136 is also relevant.
    'T1548.001': 'T1548.003',  # Sibling techniques.
}

# Mapping between parent techniques, subtechniques, and sibling subtechniques.
MAPPING_ALERTS_PATH = {
    "T1543.003": "T1543",
    "T1136": "T1136.001",
    "T1548.003": "T1548.001",
    "T1078.003": "T1078",
    "T1078.001": "T1078"
}
