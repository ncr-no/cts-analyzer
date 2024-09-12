import json
import re
from pprint import pprint
import networkx as nx
import utils

# ARCS_FILE and VERTICES_FILE should be set to the location where the relevant files reside
# ARCS_FILE = '/tmp/mulval_dir/ARCS.CSV'
# VERTICES_FILE = '/tmp/mulval_dir/VERTICES.CSV'

ARCS_FILE = 'outputs/ARCS.CSV'
VERTICES_FILE = 'outputs/VERTICES.CSV'

# Predicates describing level of control over assets
LEVELS = {
    'externalActor',
    'networkConnection',
    'account',
    'person',
    'system',
    'application',
    'file',
    'sentEmail',
    'openFile',
    'credential',
    'copyFile'
}

# Predicates describing asset properties
PROPERTIES = {
    'vulnerableAsset',
    'accessAllowed',
    'inNetwork',
    'networkService',
    'installed',
    'hasAccount',
    'defaultAccount',
    'receivesEmails',
    'userCanClick',
    'mailOnWeb',
    'softwareOpensFiles',
    'plaintextProtocol'
}

# Predicates describing countermeasures
COUNTERMEASURES = {
    'inboundTrafficFiltering',
    'homoglyphDetection',
    'urlAnalysis',
    'senderMTAReputationAnalysis',
    'senderReputationAnalysis',
    'strongPasswordPolicy',
    'multifactorAuthentication',
    'accountLocking',
    'encryptedDisk',
    'dataBackup',
    'softwareUpdate',
    'userTraining',
    'passwordPolicies',
    'userAccountManagement',
    'restrictRegistryPermissions'
}


def create_and_postprocess_kcag():
    """
    Procedure determines attack paths, strategic phases, strategic techniques. Each vertex
    obtains a label indicating its group (1-5). The labels are 'LEVEL', 'PROPERTY',
    'COUNTERMEASURE', 'TECHNIQUE', and 'GOAL'.
    """

    attacker_vertex = None
    goals = []

    # process edges
    incidence_list = {}
    with open(ARCS_FILE, "r", encoding="UTF-8") as txtfile:
        for line in txtfile:
            result = re.match(r'(?P<end>[0-9]+),(?P<start>[0-9]+),-1', line)
            if result['start'] in incidence_list:
                incidence_list[result['start']].append(result['end'])
            else:
                incidence_list[result['start']] = []
                incidence_list[result['start']].append(result['end'])

    # process vertices
    nodes_dict = {}
    with open(VERTICES_FILE, "r", encoding="UTF-8") as txtfile:
        for line in txtfile:
            result = re.match(
                r'(?P<id>\d+),"(?P<description>.+)","(?P<relation>[A-Z]+)",(?P<coef>[0-9\.]+)',
                line)
            nodes_dict[result['id']] = {'description': result['description'],
                                        'relation': result['relation']}
            for level in LEVELS:
                if result['description'].startswith(level):
                    nodes_dict[result['id']]['label'] = 'LEVEL'

            for asset_property in PROPERTIES:
                if result['description'].startswith(asset_property):
                    nodes_dict[result['id']]['label'] = 'PROPERTY'

            for countermeasure in COUNTERMEASURES:
                if result['description'].startswith(countermeasure):
                    nodes_dict[result['id']]['label'] = 'COUNTERMEASURE'

            if result['relation'] == 'AND':
                rule_result = re.match(
                    r'RULE \d+ \((?P<attack_id>T\d{4}.?\d*) - .*', result['description'])
                if rule_result:
                    nodes_dict[result['id']]['attack_id'] = rule_result['attack_id']
                    nodes_dict[result['id']]['phases'] = utils.get_phase_for_technique(rule_result['attack_id'])
                    nodes_dict[result['id']]['label'] = 'TECHNIQUE'

            if 'externalActor' in result['description']:
                attacker_vertex = result['id']

    attack_graph = nx.DiGraph()
    for edge_start in incidence_list:
        for edge_end in incidence_list[edge_start]:
            attack_graph.add_edge(edge_start, edge_end)

    for node in nodes_dict:
        attack_graph.add_node(node, **nodes_dict[node])

    for (vertex, out_degree) in attack_graph.out_degree():
        if out_degree == 0:
            attack_graph.nodes[vertex]['label'] = 'GOAL'
            goals.append(vertex)

    # Uncomment the following line to see all vertices
    # output_attack_graph(attack_graph)
    # print_strategic_techniques(attack_graph, attacker_vertex, goals)
    return get_attack_path_techniques(attack_graph, attacker_vertex, goals)


def output_attack_graph(attack_graph):
    """
    This procedure outputs basic information about an attack graph.
    :param attack_graph: the attack graph to be processed
    :return:
    """
    print("The output kill chain attack graph")
    print("__________________________________")
    print("Vertices")
    print(attack_graph.nodes.data())
    print()
    print("Edges")
    print(attack_graph.edges.data())
    print()
    print("Kill chain phases")
    pprint(utils.get_phases())
    print()
    print("Mapping function")
    pprint(utils.get_mapping_function())
    print()


def print_strategic_techniques(graph, attacker_vertex, goals):
    """
    This procedure prints possible attack paths, including their strategic techniques
    and countermeasures.
    :param graph: attack graph
    :param attacker_vertex: external actor vertex
    :param goals: goals of the attack graph
    """

    candidate_vertices = []
    global_appearance_count = {}
    global_count_of_paths = 0
    strategic_countermeasures = set()

    for vertex in graph.nodes:
        if graph.nodes[vertex]['label'] == 'COUNTERMEASURE':
            strategic_countermeasures.add(vertex)

    for goal in goals:
        count_of_paths = 0
        local_appearance_count = {}

        print("Paths to goal:", goal)
        print("---------------------------------------------")
        print()

        for path in nx.algorithms.all_simple_paths(graph, attacker_vertex, goal, cutoff=10):
            utils.determine_kill_chain_phases(graph, path)
            path_countermeasures = set()

            count_of_paths += 1
            print("Path:", path)
            for vertex in path:
                if vertex not in local_appearance_count:
                    local_appearance_count[vertex] = 0

                if vertex not in global_appearance_count:
                    global_appearance_count[vertex] = 0

                if graph.nodes[vertex]['label'] == 'TECHNIQUE':
                    for predecessor in graph.predecessors(vertex):
                        if graph.nodes[predecessor]['label'] == 'COUNTERMEASURE':
                            path_countermeasures.add(predecessor)

                local_appearance_count[vertex] += 1
                global_appearance_count[vertex] += 1
                print(graph.nodes[vertex])

            strategic_countermeasures = strategic_countermeasures.intersection(path_countermeasures)
            print("---------------------------------------------")
            print()

        global_count_of_paths += count_of_paths
        for vertex_id in local_appearance_count:
            if local_appearance_count[vertex_id] == count_of_paths:
                candidate_vertices.append(vertex_id)

        print("Strategic techniques for goal:", goal)
        for vertex in local_appearance_count:
            if local_appearance_count[vertex] == count_of_paths and 'label' in graph.nodes[vertex] and \
                    graph.nodes[vertex]['label'] == 'TECHNIQUE':
                print(graph.nodes[vertex])

    print("_________________________")
    print()
    print("Strategic techniques for the attack graph:")

    # strategic technique - for all paths to attack goals
    for vertex in global_appearance_count:
        if global_appearance_count[vertex] == global_count_of_paths and 'label' in graph.nodes[vertex] and \
                graph.nodes[vertex]['label'] == 'TECHNIQUE':
            print(graph.nodes[vertex])

    print("__________________________")
    print()
    print("Strategic countermeasures:")

    # strategic countermeasures those that can be applied against all attack paths
    for vertex in strategic_countermeasures:
        print(graph.nodes[vertex])


def get_attack_path_techniques(graph, attacker_vertex, goals):
    """
    This procedure returns technique organized as attack paths.
    :param graph: attack graph to be processed
    :param attacker_vertex: vertex from which the attacker started the attack
    :param goals: goals of the attack in the attack graph
    :return:
    """
    paths = []
    for goal in goals:
        # cutoff=10 is feasible to compute
        for path in nx.algorithms.all_simple_paths(graph, attacker_vertex, goal, cutoff=10):
            utils.determine_kill_chain_phases(graph, path)
            current_path = {"vertices": [], "lateral_movement": False, "ip_addresses": [], "lm_indices": []}
            current_index = 0
            current_path["lm_indices"].append(current_index)
            for vertex in path:
                if graph.nodes[vertex]['label'] == 'TECHNIQUE':
                    current_path["vertices"].append(graph.nodes[vertex])
                    current_index += 1
                    if 'Lateral Movement' in graph.nodes[vertex]['phases']:
                        current_path["lateral_movement"] = True

                else:
                    line_parts = graph.nodes[vertex]['description'].split(",")
                    for part in line_parts:
                        if part.isdigit() and part not in current_path["ip_addresses"]:
                            current_path["ip_addresses"].append(part)
                            current_path["lm_indices"].append(current_index)
            current_path["lm_indices"].append(current_index - 1)

            if current_path not in paths:
                paths.append(current_path)

    # Uncomment the following lines to store attack paths in file
    # with open("attack_paths.json", "w", encoding='utf-8') as outfile:
    #     json.dump(paths, outfile, indent=4)

    return paths
