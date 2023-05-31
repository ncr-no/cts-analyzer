import csv
from evidence_path import SRC_IP_INDEX, DEST_IP_INDEX, AGENT_IP_INDEX, TECHNIQUE_FILENAMES, COMMUNICATION_FILENAMES


RULE_GROUPS_INDEX = 87
TARGET_USER_INDEX = 55


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
    # The following lines contain possible attack goals - integrity is chosen as an example
    # ============================================================================================
    # output_lines.add(f"attackGoal(system(2, confidentiality, {row[AGENT_IP_INDEX].replace('.', '_')}, _)).")
    # output_lines.add(f"attackGoal(system(2, integrity, {row[AGENT_IP_INDEX].replace('.', '_')}, _)).")
    # output_lines.add(f"attackGoal(system(2, availability, {row[AGENT_IP_INDEX].replace('.', '_')}, _)).")
    # output_lines.add(f"attackGoal(system(2, authorization, {row[AGENT_IP_INDEX].replace('.', '_')}, _)).")
    # output_lines.add(
    #     f"attackGoal(file(2, confidentiality, {row[AGENT_IP_INDEX].replace('.', '_')}, _)).")
    # output_lines.add(
    #     f"attackGoal(file(2, integrity, {row[AGENT_IP_INDEX].replace('.', '_')}, _)).")
    # output_lines.add(
    #     f"attackGoal(file(2, availability, {row[AGENT_IP_INDEX].replace('.', '_')}, _)).")
    # ============================================================================================
    # the output attack graph was based on the goal
    output_lines.add(
        f"attackGoal(file(2, integrity, {goal_ip_address.replace('.', '_')}, _)).")
    # ============================================================================================

    # MITRE CALDERA server represents the attacker, it can access agents
    output_lines.add("externalActor(10_255_1_128).")
    # for now without port, even though it uses HTTP
    output_lines.add(f"accessAllowed(10_255_1_128, {row[AGENT_IP_INDEX].replace('.', '_')}, _, _).")


def add_accounts_and_os(row, output_lines):
    """
    Add information about accounts and Windows OS to the output lines.
    :param row: row from CSV file
    :param output_lines: set of output lines
    :return:
    """
    if "windows" in row[RULE_GROUPS_INDEX].split(', '):
        output_lines.add(f"installed({row[AGENT_IP_INDEX].replace('.', '_')}, windows).")
        if row[TARGET_USER_INDEX] == "SYSTEM":
            output_lines.add(f"hasAccount(_, root, {row[AGENT_IP_INDEX].replace('.', '_')}, windows).")
        else:
            output_lines.add(f"hasAccount(_, user, {row[AGENT_IP_INDEX].replace('.', '_')}, windows).")
    elif "syslog" in row[RULE_GROUPS_INDEX].split(', '):
        output_lines.add(f"installed({row[AGENT_IP_INDEX].replace('.', '_')}, linux).")


def add_network_access_and_services(row, output_lines):
    """
    Add information about network access between endpoints and services to the output lines.
    :param row: row from CSV file
    :param output_lines: set of output lines
    :return:
    """
    if not row[SRC_IP_INDEX].startswith('10.'):
        # ==================================================================================
        # accessAllowed without ports
        output_lines.add(f"accessAllowed(internet, {row[DEST_IP_INDEX].replace('.', '_')}, "
                         f"{row[SRC_IP_INDEX - 1].lower()}, _).")
        # ==================================================================================
        # accessAllowed with ports - can cause huge number of possible attack paths
        # output_lines.add(f"accessAllowed(internet, {row[DEST_IP_INDEX].replace('.', '_')}, "
        #                  f"{row[SRC_IP_INDEX - 1].lower()}, "
        #                  f"{row[DEST_IP_INDEX + 1] if row[DEST_IP_INDEX + 1].isdigit() and int(row[DEST_IP_INDEX + 1]) < 1024 else '_'}).")
        # ==================================================================================
    else:
        # ==================================================================================
        # accessAllowed without ports
        output_lines.add(f"accessAllowed({row[SRC_IP_INDEX].replace('.', '_')}, "
                         f"{row[DEST_IP_INDEX].replace('.', '_')}, {row[SRC_IP_INDEX - 1].lower()}, "
                         f"_).")
        # ==================================================================================
        # accessAllowed with ports - can cause huge number of possible attack paths
        # output_lines.add(f"accessAllowed({row[SRC_IP_INDEX].replace('.', '_')}, "
        #                  f"{row[DEST_IP_INDEX].replace('.', '_')}, {row[SRC_IP_INDEX - 1].lower()}, "
        #                  f"{row[DEST_IP_INDEX + 1] if row[DEST_IP_INDEX + 1].isdigit() and int(row[DEST_IP_INDEX + 1]) < 1024 else '_'}).")
        # ==================================================================================

    # ======================================================================================
    # networkService without ports
    output_lines.add(f"networkService({row[DEST_IP_INDEX].replace('.', '_')}, "
                     f"{row[DEST_IP_INDEX - 1] if row[DEST_IP_INDEX - 1] != '-' else '_'}, "
                     f"{row[SRC_IP_INDEX - 1].lower()}, "
                     f"_, _).")
    # ======================================================================================
    # networkService with ports
    # output_lines.add(f"networkService({row[DEST_IP_INDEX].replace('.', '_')}, "
    #                  f"{row[DEST_IP_INDEX - 1] if row[DEST_IP_INDEX - 1] != '-' else '_'}, "
    #                  f"{row[SRC_IP_INDEX - 1].lower()}, "
    #                  f"{row[DEST_IP_INDEX + 1] if int(row[DEST_IP_INDEX + 1]) < 1024 else '_'}, _).")
    # ======================================================================================


def add_other_network_predicates(row, ip_index, output_lines):
    """
    Add the remaining network predicates to the output lines.
    :param row: row from CSV file
    :param ip_index: index of column from the row that will be processed
    :param output_lines: set of output lines
    :return:
    """
    last_dot_index = row[ip_index].rindex('.')
    network_address = row[ip_index][:last_dot_index] + ".0_24"
    output_lines.add(f"inNetwork({row[ip_index].replace('.', '_')}, "
                     f"{network_address.replace('.', '_')}).")
    output_lines.add(f"inboundTrafficFiltering({network_address.replace('.', '_')}, no).")


def convert_input(output_path, goal_ip_address="10.11.1.10"):
    """
    This procedure converts organization's description to the form that MulVAL can process.
    :param output_path: path where the MulVAL's input file will be stored
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
            for row in csvreader:
                if row[AGENT_IP_INDEX] != 'agent.ip':
                    add_attack_source_target(row, output_lines, goal_ip_address)
                    add_accounts_and_os(row, output_lines)

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
