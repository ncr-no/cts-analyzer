import csv
import json

from evidence_path import SRC_IP_INDEX, DEST_IP_INDEX, AGENT_IP_INDEX, COMMUNICATION_FILENAMES

RULE_GROUPS_INDEX = 19
TARGET_USER_INDEX = 66
TECHNIQUE_FILENAMES = ['inputs/wazuh-alerts.csv', 'inputs/wazuh-archives.csv']
GOAL_IP = "10.77.77.77"  # dc


def add_countermeasures(output_lines):
    """
    Add countermeasures to the output lines
    :param output_lines: set of output lines
    :return:
    """
    output_lines.add("homoglyphDetection(no).")
    output_lines.add("urlAnalysis(no).")
    output_lines.add("senderMTAReputationAnalysis(no).")
    output_lines.add("senderReputationAnalysis(no).")
    output_lines.add("strongPasswordPolicy(no).")
    output_lines.add("multifactorAuthentication(no).")
    output_lines.add("accountLocking(no).")
    output_lines.add("softwareUpdate(no).")
    output_lines.add("userTraining(no).")
    output_lines.add("passwordPolicies(no).")
    output_lines.add("userAccountManagement(no).")
    output_lines.add("restrictRegistryPermissions(no).")


def add_plaintext_protocols(output_lines):
    """
    Add specification of some plaintext protocols to the output lines.
    :param output_lines: set of output lines
    :return:
    """
    output_lines.add("plaintextProtocol(20).")
    output_lines.add("plaintextProtocol(23).")
    output_lines.add("plaintextProtocol(80).")
    output_lines.add("plaintextProtocol(69).")
    output_lines.add("plaintextProtocol(25).")
    output_lines.add("plaintextProtocol(110).")


def add_attack_source_target(row, output_lines, goal_ip_address):
    """
    Add attack source and attack target to the output lines.
    :param row: row from CSV file
    :param output_lines: set of output lines
    :param goal_ip_address: goal IP address in an attack graph
    :return:
    """

    # the output attack graph was based on the goal
    output_lines.add(
        f"attackGoal(file(2, integrity, {goal_ip_address.replace('.', '_')}, _)).")

    output_lines.add("externalActor(vendor).")

    # vendor has access to domain controller
    output_lines.add(f"accessAllowed(vendor, 10_77_77_77, _, _).")


def add_accounts_and_os(row, output_lines, rule_groups_index=RULE_GROUPS_INDEX, agent_ip_index=AGENT_IP_INDEX,
                        target_user_index=TARGET_USER_INDEX):
    """
    Add information about accounts and Windows OS to the output lines.
    :param row: row from CSV file
    :param output_lines: set of output lines
    :return:
    """
    if row[rule_groups_index] != " " and row[agent_ip_index] != " ":
        if "windows" in json.loads(row[rule_groups_index]):
            output_lines.add(f"installed({row[agent_ip_index].replace('.', '_')}, windows).")
            if row[target_user_index] == "SYSTEM":
                output_lines.add(f"hasAccount(_, root, {row[agent_ip_index].replace('.', '_')}, windows).")
            else:
                output_lines.add(f"hasAccount(_, user, {row[agent_ip_index].replace('.', '_')}, windows).")
        elif "syslog" in json.loads(row[rule_groups_index]):
            output_lines.add(f"installed({row[agent_ip_index].replace('.', '_')}, linux).")


def add_network_access_and_services(row, output_lines, agent_ip_index=AGENT_IP_INDEX):
    """
    Add information about network access between endpoints and services to the output lines.
    :param row: row from CSV file
    :param output_lines: set of output lines
    :return:
    """

    # a version for the cyber exercise
    output_lines.add(f"networkService({row[agent_ip_index].replace('.', '_')}, "
                     f"'_', "
                     f"tcp, "
                     f"_, _).")
    output_lines.add(f"accessAllowed({'10.77.77.77'.replace('.', '_')}, "
                     f"{'10.11.1.20'.replace('.', '_')}, tcp, "
                     f"_).")
    output_lines.add(f"accessAllowed({'10.77.77.77'.replace('.', '_')}, "
                     f"{'10.11.1.10'.replace('.', '_')}, tcp, "
                     f"_).")


def add_other_network_predicates(row, ip_index, output_lines):
    """
    Add the remaining network predicates to the output lines.
    :param row: row from CSV file
    :param ip_index: index of column from the row that will be processed
    :param output_lines: set of output lines
    :return:
    """
    if '.' in row[ip_index]:
        last_dot_index = row[ip_index].rindex('.')
        network_address = row[ip_index][:last_dot_index] + ".0_24"
        output_lines.add(f"inNetwork({row[ip_index].replace('.', '_')}, "
                         f"{network_address.replace('.', '_')}).")
        output_lines.add(f"inboundTrafficFiltering({network_address.replace('.', '_')}, no).")


def convert_input(output_path, goal_ip_address="10.77.77.77"):
    """
    This procedure converts organization's description to the form that MulVAL can process.
    :param output_path: path where the MulVAL's input file will be stored
    :param goal_ip_address: specifies goal of the attack
    :return
    """

    output_lines = set()

    # default actor
    output_lines.add("externalActor(internet).")

    add_countermeasures(output_lines)
    add_plaintext_protocols(output_lines)

    for technique_filename in TECHNIQUE_FILENAMES:
        with open(technique_filename, newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=',', quotechar='"')
            first_row = next(csvreader)
            RULE_GROUPS_INDEX = first_row.index('_source.rule.groups')
            TARGET_USER_INDEX = first_row.index('_source.data.win.eventdata.targetUserName')
            AGENT_IP_INDEX = first_row.index('_source.agent.ip')
            for row in csvreader:
                if row[AGENT_IP_INDEX] != 'agent.ip' and row[AGENT_IP_INDEX] != " ":
                    add_attack_source_target(row, output_lines, goal_ip_address)
                    add_accounts_and_os(row, output_lines, rule_groups_index=RULE_GROUPS_INDEX,
                                        agent_ip_index=AGENT_IP_INDEX, target_user_index=TARGET_USER_INDEX)
                    output_lines.add(f"dataBackup({row[AGENT_IP_INDEX].replace('.', '_')}, no).")
                    output_lines.add(f"encryptedDisk({row[AGENT_IP_INDEX].replace('.', '_')}, no).")
                    add_other_network_predicates(row, AGENT_IP_INDEX, output_lines)
                    add_network_access_and_services(row, output_lines, AGENT_IP_INDEX)

    for communication_filename in COMMUNICATION_FILENAMES:
        with open(communication_filename, newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in csvreader:
                if row[AGENT_IP_INDEX] != 'agent.ip':
                    add_network_access_and_services(row, output_lines)
                    if row[SRC_IP_INDEX].startswith('10.'):
                        output_lines.add(f"dataBackup({row[SRC_IP_INDEX].replace('.', '_')}, no).")
                        output_lines.add(f"encryptedDisk({row[SRC_IP_INDEX].replace('.', '_')}, no).")
                    output_lines.add(f"dataBackup({row[DEST_IP_INDEX].replace('.', '_')}, no).")
                    output_lines.add(f"encryptedDisk({row[DEST_IP_INDEX].replace('.', '_')}, no).")

                    add_other_network_predicates(row, SRC_IP_INDEX, output_lines)
                    add_other_network_predicates(row, DEST_IP_INDEX, output_lines)

    with open(output_path, "w") as txtfile:
        for line in output_lines:
            txtfile.write(line + "\n")
