import json

# Goals of scenarios used for the evaluation. In practice, system or application availability loss,
# file confidentiality, integrity, and availability loss can be used.
SCENARIOS_GOALS = {
    "10.12.1.10": ["attackGoal(system(2, availability, 10_12_1_10, _))."],
    "10.12.1.20": ["attackGoal(application(2, availability, 10_12_1_20, _))."],
    "10.12.2.10": ["attackGoal(system(2, availability, 10_12_2_10, _))."],
    "10.12.3.20": ["attackGoal(file(2, availability, 10_12_3_20, _))."],
    "10.12.2.20": ["attackGoal(file(2, confidentiality, 10_12_2_20, _))."]
}

ALERTS_FILENAMES = [
    "alerts/ossec-alerts-04.json",
    "alerts/ossec-alerts-05.json",
    "alerts/ossec-alerts-06.json",
    "alerts/ossec-alerts-07.json",
    "alerts/ossec-alerts-08.json",
    "alerts/ossec-alerts-09.json"]


def convert_input(output_path, use_ports=False):
    """
    This procedure converts organization's description to the form that MulVAL can process.
    :param output_path: path where the MulVAL's input file will be stored
    :param use_ports: if True the MulVAL's input file will contain transport ports
    :return
    """

    agent_ips = set()
    output_lines = set()

    # default actor
    output_lines.add("externalActor(internet).")

    add_countermeasures(output_lines)
    add_plaintext_protocols(output_lines)

    for alerts_filename in ALERTS_FILENAMES:
        with open(alerts_filename, "r", encoding="UTF-8") as json_file:
            for line in json_file:
                json_data = json.loads(line)
                if "agent" in json_data and "ip" in json_data["agent"]:
                    agent_ips.add(json_data["agent"]["ip"])

                add_attack_source_target(json_data, output_lines)

                if "groups" in json_data["rule"] and "suricata" in json_data["rule"]["groups"]:
                    add_network_access_and_services(json_data, output_lines, use_ports)
                else:
                    if "data" in json_data and "win" in json_data["data"] and "eventdata" in json_data["data"]["win"]:
                        output_lines.add(f"networkService({json_data['agent']['ip'].replace('.', '_')}, "
                                         f"{json_data['app_proto'] if 'app_proto' in json_data else '_'}, "
                                         f"_, "
                                         f"_, _).")

                add_accounts_and_os(json_data, output_lines)
                add_other_network_predicates(json_data, output_lines)

    for first_ip in agent_ips:
        for second_ip in agent_ips:
            first_octets = first_ip.split('.')
            second_octets = second_ip.split('.')
            if first_octets[:3] == second_octets[:3]:
                output_lines.add(f"accessAllowed({first_ip.replace('.', '_')}, "
                                 f"{second_ip.replace('.', '_')}, _, "
                                 f"_).")
        output_lines.add(f"vulnerableAsset({first_ip.replace('.', '_')}, _, zero_day_cve, remote, privEscalation).")
    output_lines.add(f"networkService({'10.77.77.77'.replace('.', '_')}, "
                     f"activeDirectory, "
                     f"_, "
                     f"_, _).")

    with open(output_path, "w", encoding="UTF-8") as txtfile:
        for line in output_lines:
            txtfile.write(line + "\n")


def add_network_access_and_services(json_data, output_lines, use_ports=False):
    """
    This procedure adds network access and network service predicates.
    :param json_data: dictionary based on which predicates are created
    :param output_lines: set of lines that will be written to input file
    :param use_ports: determines whether predicates contain port numbers
    :return:
    """

    src_ip = json_data["data"]["src_ip"]
    dst_ip = json_data["data"]["dest_ip"]
    transport_protocol = json_data["data"]["proto"].lower()
    dst_port = json_data["data"]["dest_port"]

    if not src_ip.startswith('10.'):
        if use_ports:
            output_lines.add(f"accessAllowed(internet, {dst_ip.replace('.', '_')}, "
                             f"{transport_protocol}, {dst_port}).")
        else:
            # accessAllowed without ports
            output_lines.add(f"accessAllowed(internet, {dst_ip.replace('.', '_')}, "
                             f"{transport_protocol}, _).")
    else:
        if use_ports:
            output_lines.add(f"accessAllowed({src_ip.replace('.', '_')}, "
                             f"{dst_ip.replace('.', '_')}, {transport_protocol}, "
                             f"{dst_port}).")
        else:
            # accessAllowed without ports
            output_lines.add(f"accessAllowed({src_ip.replace('.', '_')}, "
                             f"{dst_ip.replace('.', '_')}, {transport_protocol}, "
                             f"_).")

    if use_ports:
        output_lines.add(f"networkService({dst_ip.replace('.', '_')}, "
                         f"{json_data['app_proto'] if 'app_proto' in json_data else '_'}, "
                         f"{transport_protocol}, "
                         f"{dst_port}, _).")
    else:
        # networkService without ports
        output_lines.add(f"networkService({dst_ip.replace('.', '_')}, "
                         f"{json_data['app_proto'] if 'app_proto' in json_data else '_'}, "
                         f"{transport_protocol}, "
                         f"_, _).")


def add_accounts_and_os(json_data, output_lines):
    """
    Add information about accounts and Windows OS to the output lines.
    :param json_data: row from JSON file
    :param output_lines: set of output lines
    :return:
    """
    if "groups" in json_data["rule"] and "agent" in json_data:
        if "windows" in json_data["rule"]["groups"]:
            output_lines.add(f"installed({json_data['agent']['ip'].replace('.', '_')}, windows).")
            if "targetUserName" in json_data["data"]["win"]["eventdata"] and \
                    json_data["data"]["win"]["eventdata"]["targetUserName"] == "SYSTEM":
                output_lines.add(f"hasAccount(_, root, {json_data['agent']['ip'].replace('.', '_')}, windows).")
            else:
                output_lines.add(f"hasAccount(_, user, {json_data['agent']['ip'].replace('.', '_')}, windows).")
        elif "syslog" in json_data["rule"]["groups"] and 'ip' in json_data["agent"]:
            output_lines.add(f"installed({json_data['agent']['ip'].replace('.', '_')}, linux).")
            output_lines.add(f"hasAccount(_, root, {json_data['agent']['ip'].replace('.', '_')}, linux).")
            output_lines.add(f"hasAccount(_, user, {json_data['agent']['ip'].replace('.', '_')}, linux).")


def add_attack_source_target(line_data, output_lines):
    """
    Add attack source and attack target to the output lines.
    :param line_data
    :param output_lines: set of output lines
    :return:
    """

    if 'ip' in line_data['agent']:
        if line_data['agent']['ip'] in SCENARIOS_GOALS:
            for goal in SCENARIOS_GOALS[line_data['agent']['ip']]:
                output_lines.add(goal)

    # MITRE CALDERA server represents the attacker, it can access agents
        output_lines.add("externalActor(10_255_1_37).")
        output_lines.add(f"accessAllowed(10_255_1_37, {line_data['agent']['ip'].replace('.', '_')}, _, _).")


def add_other_network_predicates(line_data, output_lines):
    """
    Add the remaining network predicates to the output lines.
    :param row: row from CSV file
    :param ip_index: index of column from the row that will be processed
    :param output_lines: set of output lines
    :return:
    """
    if 'ip' in line_data['agent'] and '.' in line_data['agent']['ip']:
        last_dot_index = line_data['agent']['ip'].rindex('.')
        network_address = line_data['agent']['ip'][:last_dot_index] + ".0_24"
        output_lines.add(f"inNetwork({line_data['agent']['ip'].replace('.', '_')}, "
                         f"{network_address.replace('.', '_')}).")
        output_lines.add(f"inboundTrafficFiltering({network_address.replace('.', '_')}, no).")
        output_lines.add(f"dataBackup({line_data['agent']['ip'].replace('.', '_')}, no).")


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
