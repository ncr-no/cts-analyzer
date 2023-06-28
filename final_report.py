from output_postprocessing import create_and_postprocess_kcag


def check_sequence_in_path(sequence, attack_path, ip_address):
    """
    Checks if sequence appears in the path (as pattern)
    :param sequence: sequence of attack techniques from SIEM
    :param attack_path: dictionary with attack techniques from the generated attack graph, IP addresses and
    the lateral movement indication
    :param ip_address: for this IP address the search is accomplished
    :return:
    """
    sequence_index = 0
    path_index = 0
    last_successful_path_index = 0
    sequence_length = len(sequence)
    attack_path_length = len(attack_path["vertices"])
    found_sequence = []

    if ip_address.replace(".", "") in attack_path["ip_addresses"]:
        # Future work can alternatively check the lateral movement only if there was network communication
        # from the previous IP address and its timestamp. However, it would require that the communication
        # would be captured during the time window which may not hold for long-term attacks.
        if attack_path["lateral_movement"]:
            ip_index = attack_path["ip_addresses"].index(ip_address.replace(".", ""))

            # find appearance of the lateral movement
            lm_indices = [0]
            for i in range(len(attack_path["vertices"])):
                if "Lateral Movement" in attack_path["vertices"][i]["phases"]:
                    lm_indices.append(i)
            lm_indices.append(sequence_length - 1)

            # check only part of the attack path for a specific IP address
            path_index = lm_indices[ip_index]
            attack_path_length = lm_indices[ip_index + 1] + 1

        while sequence_index < sequence_length:
            if sequence[sequence_index]['rule.mitre.id'][0] == attack_path["vertices"][path_index]['attack_id']:
                last_successful_path_index = path_index
                found_sequence.append(sequence[sequence_index])
                sequence_index += 1
                path_index += 1
            else:
                path_index += 1
            if path_index == attack_path_length:
                path_index = last_successful_path_index
                sequence_index += 1
    return found_sequence


def final_evaluation(sequences, critical_ips):
    """
    This procedure creates final evaluation of the DEFCON levels for each IP address and its sequences of techniques.
    :param sequences: dictionary containing for each IP address its sequences of techniques
    :param critical_ips: list of the critical IP addresses
    :return:
    """
    evaluation = {}
    attack_paths = create_and_postprocess_kcag()

    for ip_address in sequences:
        for sequence in sequences[ip_address]:
            for attack_path in attack_paths:
                for event in check_sequence_in_path(sequence, attack_path, ip_address):
                    if ip_address not in evaluation:
                        evaluation[ip_address] = {'technique': [], 'level': 5}

                    # assign level or decrease the current level
                    if 'Reconnaissance' in event["rule.mitre.tactic"] or \
                            'Resource Development' in event["rule.mitre.tactic"]:
                        if evaluation[ip_address]['level'] > 5:
                            evaluation[ip_address]['level'] = 5
                            evaluation[ip_address]['technique'] = [event['rule.mitre.id'][0] +
                                                                   " - " + event["rule.mitre.technique"][0]]
                        elif evaluation[ip_address]['level'] == 5 and \
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]
                    if ('Initial Access' in event["rule.mitre.tactic"]) and ip_address not in critical_ips:
                        if evaluation[ip_address]['level'] > 4:
                            evaluation[ip_address]['level'] = 4
                            evaluation[ip_address]['technique'] = [event['rule.mitre.id'][0] +
                                                                   " - " + event["rule.mitre.technique"][0]]
                        elif evaluation[ip_address]['level'] == 4 and \
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]
                    if (('Initial Access' in event["rule.mitre.tactic"]) and ip_address in critical_ips) or \
                            (('Execution' in event["rule.mitre.tactic"] or
                              'Privilege Escalation' in event["rule.mitre.tactic"] or
                              'Defense Evasion' in event["rule.mitre.tactic"] or
                              'Persistence' in event["rule.mitre.tactic"] or
                              'Collection' in event["rule.mitre.tactic"] or
                              'Command and Control' in event["rule.mitre.tactic"] or
                              'Credential Access' in event["rule.mitre.tactic"]) and
                             ip_address not in critical_ips) or \
                            'Discovery' in event["rule.mitre.tactic"] or \
                            'Lateral Movement' in event["rule.mitre.tactic"]:
                        if evaluation[ip_address]['level'] > 3:
                            evaluation[ip_address]['level'] = 3
                            evaluation[ip_address]['technique'] = [event['rule.mitre.id'][0] +
                                                                   " - " + event["rule.mitre.technique"][0]]
                        elif evaluation[ip_address]['level'] == 3 and \
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]
                    if (('Exfiltration' in event["rule.mitre.tactic"] or 'Impact' in event["rule.mitre.tactic"])
                        and ip_address not in critical_ips) or \
                            (('Execution' in event["rule.mitre.tactic"] or
                              'Privilege Escalation' in event["rule.mitre.tactic"] or
                              'Credential Access' in event["rule.mitre.tactic"] or
                              'Defense Evasion' in event["rule.mitre.tactic"] or
                              'Persistence' in event["rule.mitre.tactic"] or
                              'Collection' in event["rule.mitre.tactic"] or
                              'Command and Control' in event["rule.mitre.tactic"]) and ip_address in critical_ips):
                        if evaluation[ip_address]['level'] > 2:
                            evaluation[ip_address]['level'] = 2
                            evaluation[ip_address]['technique'] = [event['rule.mitre.id'][0] +
                                                                   " - " + event["rule.mitre.technique"][0]]
                        elif evaluation[ip_address]['level'] == 2 and \
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]
                    if ('Exfiltration' in event["rule.mitre.tactic"] or 'Impact' in event["rule.mitre.tactic"]) and \
                            ip_address in critical_ips:
                        if evaluation[ip_address]['level'] > 1:
                            evaluation[ip_address]['level'] = 1
                            evaluation[ip_address]['technique'] = [event['rule.mitre.id'][0] +
                                                                   " - " + event["rule.mitre.technique"][0]]
                        elif evaluation[ip_address]['level'] == 1 and \
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]

    # Print commands for formatting the output
    print("______________________________________")
    print()
    return evaluation
