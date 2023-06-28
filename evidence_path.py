import csv
import json
from pprint import pprint
from utils import partially_ordered_phases
from copy import deepcopy
import ipaddress
from final_report import final_evaluation
from custom_detection import check_encryption_technique

# The following values were used during the table-top exercise in May 2023.
# -------------------------------------------------------------------------
CRITICAL_IPS = ['10.11.1.10', '10.11.1.20', '10.77.77.77']
TECHNIQUE_FILENAMES = ['inputs/wazuh-alerts.csv']
COMMUNICATION_FILENAMES = []

# Default indices for CSV files, they are updated by searching for the column name
# in relevant procedures. Wazuh always changes count of columns and their order.
# CSVs cannot be used in any case in production.
TECHNIQUE_INDEX = 75
AGENT_IP_INDEX = 102
MITRE_ID_INDEX = 76
TIMESTAMP_INDEX = 30
SRC_IP_INDEX = 102
DEST_IP_INDEX = 102
# -------------------------------------------------------------------------


MAPPING_OF_TECHNIQUES = {
    "T1565.001": ["Impact"],
    "T1112": ["Defense Evasion"],
    "T1070.004": ["Defense Evasion"],
    "T1485": ["Impact"],
    "T1078": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1021": ["Lateral Movement"],
    "T1040": ["Credential Access", "Discovery"],
    "T1562.001": ["Defense Evasion"],
    "T1548.003": ["Privilege Escalation", "Defense Evasion"],
    "T1543.003": ["Persistence", "Privilege Escalation"],
    "T1136": ["Persistence"],
    "T1098": ["Persistence"],
    "T1484": ["Defense Evasion", "Privilege Escalation"],
    "T1531": ["Impact"],
    "T1486": ["Impact"],
    "T1550.002": ["Defense Evasion", "Lateral Movement"]
}

NAMES_OF_TECHNIQUES = {
    "T1565.001": "Stored Data Manipulation",
    "T1112": "Modify Registry",
    "T1070.004": "File Deletion",
    "T1485": "Data Destruction",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1040": "Network Sniffing",
    "T1562.001": "Disable or Modify Tools",
    "T1548.003": "Sudo and Sudo Caching",
    "T1543.003": "Windows Service",
    "T1136": "Create Account",
    "T1098": "Account Manipulation",
    "T1484": "Domain Policy Modification",
    "T1531": "Account Access Removal",
    "T1486": "Data Encrypted for Impact",
    "T1550.002": "Pass the Hash"
}


def check_techniques(previous_technique, next_technique):
    """
    This procedure checks the MITRE ATT&CK kill chain phases (tactics) of two techniques and
    removes the unsatisfactory ones.
    :param previous_technique: the first technique
    :param next_technique: the consequent technique
    :return:
    """
    previous_phases = deepcopy(previous_technique['rule.mitre.tactic'])
    following_phases = deepcopy(next_technique['rule.mitre.tactic'])

    combinations = []
    for first_phase in previous_phases:
        for second_phase in following_phases:
            combinations.append((first_phase, second_phase))

    for first_phase in previous_technique['rule.mitre.tactic']:
        for second_phase in next_technique['rule.mitre.tactic']:
            if first_phase in partially_ordered_phases[second_phase]:
                combinations.remove((first_phase, second_phase))

    first_satisfactory_phases = set()
    second_satisfactory_phases = set()
    for (first_phase, second_phase) in combinations:
        first_satisfactory_phases.add(first_phase)
        second_satisfactory_phases.add(second_phase)

    remove_unsatisfactory_phases(previous_phases, first_satisfactory_phases, previous_technique)
    remove_unsatisfactory_phases(following_phases, second_satisfactory_phases, next_technique)


def remove_unsatisfactory_phases(possible_phases, satisfactory_phases, technique):
    """
    This procedure removes unsatisfactory phases from all allowed phases for a technique.
    :param possible_phases: all allowed phases for the technique
    :param satisfactory_phases: allowed phases in the context of a specific sequence
    :param technique: the mentioned technique
    :return:
    """
    list_index = 0
    length = len(possible_phases)

    while list_index < length:
        if possible_phases[list_index] not in satisfactory_phases:
            technique['rule.mitre.tactic'].remove(possible_phases[list_index])
        list_index += 1


def check_starting_tactics(tactics):
    """
    Return only tactics that can begin sequence of techniques.
    :param tactics: List of possible tactics for the first technique in the sequence
    :return:
    """
    allowed_tactics = []
    for tactic in tactics:
        if tactic in ['Reconnaissance', 'Resource Development', 'Initial Access']:
            allowed_tactics.append(tactic)
    return allowed_tactics


def is_ip_address(ip_address):
    """
    Check whether the provided string is an IPv4 or an IPv6 address.
    :param ip_address: string that may be IP address
    :return:
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def process_file_containing_techniques(technique_filename, output_dictionary):
    """
    Add to the output dictionary all technique present in a file.
    :param technique_filename: file containing alerts about techniques
    :param output_dictionary: output dictionary that will contain the techniques
    :return:
    """
    with open(technique_filename, newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"')
        first_row = next(csvreader)
        TECHNIQUE_INDEX = first_row.index('_source.rule.mitre.technique')
        AGENT_IP_INDEX = first_row.index('_source.agent.ip')
        MITRE_ID_INDEX = first_row.index('_source.rule.mitre.id')
        TIMESTAMP_INDEX = first_row.index('_source.timestamp')

        for row in csvreader:
            if row[TECHNIQUE_INDEX] != 'rule.mitre.technique' and row[TECHNIQUE_INDEX] != "-" and \
                    row[TECHNIQUE_INDEX] != '_source.rule.mitre.technique' and row[TECHNIQUE_INDEX] != ' ':
                if row[AGENT_IP_INDEX] not in output_dictionary:
                    output_dictionary[row[AGENT_IP_INDEX]] = []

                # modified version of for loop condition
                for mitre_id in json.loads(row[MITRE_ID_INDEX]):
                    output_dictionary[row[AGENT_IP_INDEX]].append({
                        "rule.mitre.technique": [NAMES_OF_TECHNIQUES[mitre_id]],
                        "rule.mitre.id": [mitre_id],
                        "rule.mitre.tactic": MAPPING_OF_TECHNIQUES[mitre_id],
                        "data.timestamp": row[TIMESTAMP_INDEX],
                        "data.src_ip": "-",
                        "data.dest_ip": "-"
                    })

    # add techniques detected by custom detection
    technique_dictionary = check_encryption_technique()
    for agent_ip in technique_dictionary:
        if agent_ip not in output_dictionary:
            output_dictionary[agent_ip] = []
        output_dictionary[agent_ip].append(technique_dictionary[agent_ip])


def process_file_containing_communication(communication_filename, output_dictionary):
    """
    Add to the output dictionary all communication entries from a file.
    :param communication_filename: file containing communication of IP addresses
    :param output_dictionary: output dictionary that will contain the communication
    :return:
    """
    with open(communication_filename, newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in csvreader:

            if row[AGENT_IP_INDEX] != 'agent.ip' and \
                    row[SRC_IP_INDEX] != " " and row[DEST_IP_INDEX] != " ":
                # technique type of event has technique specified while communication not
                if row[AGENT_IP_INDEX] not in output_dictionary:
                    output_dictionary[row[AGENT_IP_INDEX]] = []
                output_dictionary[row[AGENT_IP_INDEX]].append({
                    "rule.mitre.technique": [],
                    "rule.mitre.id": [],
                    "rule.mitre.tactic": [],
                    "data.timestamp": row[TIMESTAMP_INDEX],
                    "data.src_ip": row[SRC_IP_INDEX],
                    "data.dest_ip": row[DEST_IP_INDEX]
                })


def compress_events(output_dictionary):
    """
    This procedure removes single appearance of techniques and network communication and replaces them with
    entries containing number of the technique or communication alerts.
    :param output_dictionary: output dictionary that will contain the compressed entries
    :return:
    """
    tmp_dictionary = {}
    for ip_address in output_dictionary:
        tmp_dictionary[ip_address] = []
        current_item = None
        sequence_length = 0
        for item in output_dictionary[ip_address]:
            if current_item is None:
                current_item = item
                current_item["start_timestamp"] = item["data.timestamp"]
                current_item["end_timestamp"] = item["data.timestamp"]
                sequence_length += 1
                del current_item["data.timestamp"]
                if len(output_dictionary[ip_address]) == 1:
                    current_item["count"] = sequence_length
                    sequence_length = 0
                    tmp_dictionary[ip_address].append(current_item)
            else:
                if current_item["rule.mitre.technique"] == item["rule.mitre.technique"] and \
                        current_item["rule.mitre.id"] == item["rule.mitre.id"] and \
                        current_item["rule.mitre.tactic"] == item["rule.mitre.tactic"] and \
                        current_item["data.src_ip"] == item["data.src_ip"] and \
                        current_item["data.dest_ip"] == item["data.dest_ip"]:
                    current_item["end_timestamp"] = item["data.timestamp"]
                    sequence_length += 1
                else:
                    # create a new compression sequence
                    current_item["count"] = sequence_length
                    tmp_dictionary[ip_address].append(current_item)
                    current_item = item
                    current_item["start_timestamp"] = item["data.timestamp"]
                    current_item["end_timestamp"] = item["data.timestamp"]
                    sequence_length = 1
                    if "data.timestamp" in current_item:
                        del current_item["data.timestamp"]
        current_item["count"] = sequence_length
        tmp_dictionary[ip_address].append(current_item)
    output_dictionary = tmp_dictionary


def create_sequences(input_dictionary):
    """
    This procedure will create sequences of techniques and return them.
    :param input_dictionary: input dictionary containing techniques and communication
    :return:
    """
    sequences = {}
    for ip_address in input_dictionary:
        sequences[ip_address] = []
        for event in input_dictionary[ip_address]:
            # there is no attack path - start a new one
            if len(sequences[ip_address]) == 0:
                # the following condition compresses also communication events
                # if techniques are only needed, replace ["-"] with []
                if event["rule.mitre.id"] != ["-"]:
                    event["rule.mitre.tactic"] = check_starting_tactics(event["rule.mitre.tactic"])
                    if event["rule.mitre.tactic"]:
                        sequences[ip_address].append([{
                            "rule.mitre.id": event["rule.mitre.id"],
                            "rule.mitre.technique": event["rule.mitre.technique"],
                            "rule.mitre.tactic": event["rule.mitre.tactic"]}])

            # there are already some sequences
            else:
                for sequence in sequences[ip_address]:
                    last_index = len(sequence) - 1
                    if event["rule.mitre.id"] != ["-"]:
                        correct_phases = False
                        if sequence[last_index]["rule.mitre.id"] == event["rule.mitre.id"]:
                            continue

                        # Lateral movement is addressed during path matching.
                        # If an attack path contains the lateral movement tactic, then the matching tests a sequence of
                        # alerts from one host before the lateral movement and a sequence of alerts from the second host
                        # after the lateral movement.
                        for start_tactic in sequence[last_index]["rule.mitre.tactic"]:
                            for end_tactic in event["rule.mitre.tactic"]:
                                if end_tactic in partially_ordered_phases[start_tactic] or \
                                        end_tactic == start_tactic:
                                    correct_phases = True

                        # if the current event can be added to the sequence
                        if correct_phases:
                            sequence.append({
                                "rule.mitre.id": event["rule.mitre.id"],
                                "rule.mitre.technique": event["rule.mitre.technique"],
                                "rule.mitre.tactic": event["rule.mitre.tactic"]})

                        # if the current event cannot be added to the sequence's end
                        else:
                            # iterate back through the sequence
                            current_index = last_index - 1
                            while current_index > 0:
                                if event["rule.mitre.id"] != ["-"]:
                                    correct_inner_phases = False
                                    for start_tactic in sequence[last_index]["rule.mitre.tactic"]:
                                        for end_tactic in event["rule.mitre.tactic"]:
                                            if end_tactic in partially_ordered_phases[start_tactic] or \
                                                    end_tactic == start_tactic:
                                                correct_inner_phases = True
                                    if sequence[last_index]["rule.mitre.id"] == event["rule.mitre.id"]:
                                        correct_inner_phases = False

                                    # add the technique to the right position
                                    if correct_inner_phases:
                                        sequence.append({
                                            "rule.mitre.id": event["rule.mitre.id"],
                                            "rule.mitre.technique": event["rule.mitre.technique"],
                                            "rule.mitre.tactic": event["rule.mitre.tactic"]})
                                        break

                                    # create new sequence
                                    else:
                                        current_index -= 1
                                        # not all phases can begin kill chain
                                        if current_index == -1 and [{
                                            "rule.mitre.id": event["rule.mitre.id"],
                                            "rule.mitre.technique": event["rule.mitre.technique"],
                                            "rule.mitre.tactic": event["rule.mitre.tactic"]}] not in sequences[
                                            ip_address]:
                                            event["rule.mitre.tactic"] = check_starting_tactics(
                                                event["rule.mitre.tactic"])
                                            if event["rule.mitre.tactic"]:
                                                sequences[ip_address].append([{
                                                    "rule.mitre.id": event["rule.mitre.id"],
                                                    "rule.mitre.technique": event["rule.mitre.technique"],
                                                    "rule.mitre.tactic": event["rule.mitre.tactic"]}])
    return sequences


def process_restricted_files():
    """
    This procedure processes files obtained from SIEM with a restricted static content.
    :return:
    """
    output_dictionary = {}

    # step 1 - add all techniques to the dictionary
    # ============================================
    for technique_filename in TECHNIQUE_FILENAMES:
        process_file_containing_techniques(technique_filename, output_dictionary)

    # step 2 - add communication to the dictionary
    # ========================================================================
    for communication_filename in COMMUNICATION_FILENAMES:
        process_file_containing_communication(communication_filename, output_dictionary)

    # step 3 - sort and compress multiple appearances of the same event
    for ip_address in output_dictionary:
        output_dictionary[ip_address] = sorted(output_dictionary[ip_address], key=lambda i: i['data.timestamp'])

    compress_events(output_dictionary)

    with open("outputs/output_dictionary.json", "w") as output_file:
        json.dump(output_dictionary, output_file, indent=4)

    # step 4 - find possible attack paths
    sequences = create_sequences(output_dictionary)

    # step 5 - check sequences and their kill chain phases
    for ip_address in sequences:
        for sequence in sequences[ip_address]:
            for list_index in range(len(sequence)):
                if list_index > 0:
                    previous_index = list_index - 1
                    current_technique = sequence[list_index]
                    previous_technique = sequence[previous_index]
                    check_techniques(previous_technique, current_technique)

                if list_index < len(sequence) - 1:
                    next_index = list_index + 1
                    current_technique = sequence[list_index]
                    next_technique = sequence[next_index]
                    check_techniques(current_technique, next_technique)

    print("These valid sequences of alerts were present in the data:")
    pprint(sequences)

    # step 6 - final evaluation
    # the evaluation will contain IP, level and techniques (with attack path in data) as an indication
    print("The following output contains attack paths.")
    print("The return value contains severity levels for IP addresses.")
    return final_evaluation(sequences, CRITICAL_IPS)
