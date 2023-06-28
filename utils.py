from copy import deepcopy

# A set of utilized kill chain phases
P = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
     'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
     'Exfiltration', 'Impact']

# This dictionary contains for each phase its successor phases
partially_ordered_phases = {
    'Reconnaissance': ['Credential Access', 'Initial Access', 'Execution', 'Privilege Escalation', 'Persistence',
                       'Defense Evasion', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
                       'Impact', 'Exfiltration'],
    'Resource Development': ['Credential Access', 'Initial Access', 'Execution', 'Privilege Escalation', 'Persistence',
                             'Defense Evasion', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
                             'Impact', 'Exfiltration'],
    'Credential Access': ['Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Initial Access': ['Execution', 'Privilege Escalation', 'Persistence', 'Defense Evasion', 'Credential Access',
                       'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Persistence': ['Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Defense Evasion': ['Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Execution': ['Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Privilege Escalation': ['Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Discovery': ['Lateral Movement', 'Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Lateral Movement': ['Collection', 'Command and Control', 'Impact', 'Exfiltration'],
    'Collection': ['Command and Control', 'Exfiltration'],
    'Command and Control': ['Exfiltration'],
    'Exfiltration': [],
    'Impact': []
}


# This dictionary contains for each technique its kill chain phases
# T1046 - Network Service Scanning has also the Reconnaissance phase as T1595 - Active Scanning
mapping_function = {
    'T1594': ['Reconnaissance'],  # Search Victim-Owned Websites
    'T1595': ['Reconnaissance'],  # Active Scanning
    'T1190': ['Initial Access'],  # Exploit Public-Facing Application
    'T1133': ['Initial Access'],  # External Remote Services
    'T1566.002': ['Initial Access'],  # Spearphishing Link
    'T1566.001': ['Initial Access'],  # Spearphishing Attachment
    'T1078': ['Initial Access', 'Privilege Escalation'],  # T1078 - Valid Accounts
    'T1078.001': ['Initial Access', 'Privilege Escalation'],  # T1078.001: Default accounts
    'T1059.008': ['Execution'],      # T1059.008: Command and Scripting Interpreter - Network Device CLI
    'T1203': ['Execution'],      # Exploitation for Client Execution
    'T1204.001': ['Execution'],      # User Execution - Malicious link
    'T1204.002': ['Execution'],   # User Execution - Malicious File
    'T1068': ['Privilege Escalation'],  # Exploitation for Privilege Escalation
    'T1110': ['Credential Access'],  # Brute Force
    'T1557': ['Credential Access', 'Collection'],  # Man in the Middle
    'T1040': ['Credential Access', 'Discovery'],  # Network Sniffing
    'T1046': ['Discovery', 'Reconnaissance'],          # Network Service Scanning
    'T1049': ['Discovery'],          # System Network Connections Discovery
    'T1018': ['Discovery'],          # Remote System Discovery
    'T1083': ['Discovery'],          # File and Directory Discovery
    'T1210': ['Lateral Movement'],   # Exploitation of Remote Services
    'T1534': ['Lateral Movement'],   # Internal Spearphishing
    'T1563.001': ['Lateral Movement'],   # Remote Service Session Hijacking - SSH Hijacking
    'T1021': ['Lateral Movement'],   # Remote Services
    'T1114': ['Collection'],         # Email Collection
    'T1185': ['Collection'],         # Man in the Browser
    'T1005': ['Collection'],         # Data from Local System
    'T1071': ['Command and Control'],  # Application Layer Protocol
    'T1573': ['Command and Control'],  # Encrypted Channel
    'T1095': ['Command and Control'],  # Non-Application Layer Protocol
    'T1571': ['Command and Control'],  # Non-Standard Port
    'T1219': ['Command and Control'],  # Remote Access Software
    'T1090': ['Command and Control'],  # Proxy
    'T1102': ['Command and Control'],  # Web Service
    'T1048': ['Exfiltration'],        # Exfiltration Over Alternative Protocol
    'T1041': ['Exfiltration'],        # Exfiltration Over C2 Channel
    'T1567': ['Exfiltration'],        # Exfiltration Over Web Service
    'T1499.004': ['Impact'],              # Endpoint Denial of Service - Application or System Exploitation
    'T1498': ['Impact'],              # Network Denial of Service
    'T1489': ['Impact'],              # Service Stop
    'T1486': ['Impact'],              # Data Encrypted for Impact
    'T1565.001': ['Impact'],          # Data Manipulation - Stored Data Manipulation
    'T1485': ['Impact'],               # Data Destruction
    'T1562.001': ['Defense Evasion'],  # Impair Defenses: Disable or Modify Tools
    'T1112': ['Defense Evasion'],  # Modify Registry
    'T1070.004': ['Defense Evasion'],  # File Deletion
    'T1548.003': ['Privilege Escalation', 'Defense Evasion'],  # Sudo and Sudo Caching
    'T1543.003': ['Persistence', 'Privilege Escalation']  # Windows Service
    }


def get_phases():
    """
    Return a set of phases utilized in the implementation.
    """
    return P


def get_scope_of_techniques():
    """
    Return utilized attack techniques.
    """
    set_t = mapping_function.keys()
    return set_t


def get_phase_for_technique(technique_id):
    """
    Returns kill chain phase(s) for technique's ID.
    """
    return mapping_function[technique_id]


def get_mapping_function():
    """
    Returns mapping function utilized in implementation.
    """
    return mapping_function


def determine_kill_chain_phases(attack_graph, attack_path):
    """
    Takes as an input attack path where each vertex is assigned all possible kill chain phases.
    It holds that each path will be consistent w.r.t. the order of phases when each path of length
    two is consistent w.r.t. the order of the kill chain phases.
    Returns path where each vertex is assigned correct kill chain phases w.r.t. the order of phases.
    :param attack_graph: attack graph to be processed
    :param attack_path: path to be checked
    """
    techniques = []
    for vertex in attack_path:
        if attack_graph.nodes[vertex]['label'] == 'TECHNIQUE':
            techniques.append(vertex)

    for list_index in range(len(techniques)):
        if list_index > 0:
            previous_index = list_index - 1
            current_vertex = attack_graph.nodes[techniques[list_index]]
            previous_vertex = attack_graph.nodes[techniques[previous_index]]
            check_vertices(previous_vertex, current_vertex)

        if list_index < len(techniques) - 1:
            next_index = list_index + 1
            current_vertex = attack_graph.nodes[techniques[list_index]]
            next_vertex = attack_graph.nodes[techniques[next_index]]
            check_vertices(current_vertex, next_vertex)


def check_vertices(previous_vertex, next_vertex):
    """
    This method checks consistency of the assigned kill chain phases for the specified pair of vertices
    from the same attack path.
    :param previous_vertex: first vertex from the pair of vertices
    :param next_vertex: second vertex from the pair of vertices
    """
    previous_phases = deepcopy(previous_vertex['phases'])
    following_phases = deepcopy(next_vertex['phases'])

    combinations = []
    for first_phase in previous_phases:
        for second_phase in following_phases:
            combinations.append((first_phase, second_phase))

    for first_phase in previous_vertex['phases']:
        for second_phase in next_vertex['phases']:
            if first_phase in partially_ordered_phases[second_phase]:
                combinations.remove((first_phase, second_phase))

    first_satisfactory_phases = set()
    second_satisfactory_phases = set()
    for (first_phase, second_phase) in combinations:
        first_satisfactory_phases.add(first_phase)
        second_satisfactory_phases.add(second_phase)

    remove_unsatisfactory_phases(previous_phases, first_satisfactory_phases, previous_vertex)
    remove_unsatisfactory_phases(following_phases, second_satisfactory_phases, next_vertex)


def remove_unsatisfactory_phases(possible_phases, satisfactory_phases, vertex):
    """
    Procedure processes phases of attack techniques.
    The procedure removes from the list of all possible phases those phases that are not present
    in the list of phases that satisfied the partial ordering of phases.
    :param possible_phases: list of all possible techniques for attack technique
    :param satisfactory_phases: list of satisfactory techniques that were computed for the technique
    :param vertex: attack technique vertex which is modified
    """
    list_index = 0
    length = len(possible_phases)

    while list_index < length:
        if possible_phases[list_index] not in satisfactory_phases:
            vertex['phases'].remove(possible_phases[list_index])
        list_index += 1
