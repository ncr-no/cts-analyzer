from output_postprocessing import create_and_postprocess_kcag


def check_sequence_in_path(sequence, attack_path):
    """
    Checks if sequence appears in the path (as pattern)
    :param sequence: sequence of attack techniques from SIEM
    :param attack_path: sequence of attack techniques from the generated attack graph
    :return:
    """
    sequence_index = 0
    path_index = 0
    while sequence_index < len(sequence) and path_index < len(attack_path):
        if sequence[sequence_index]['rule.mitre.id'][0] == attack_path[path_index]['attack_id']:
            sequence_index += 1
            path_index += 1
        else:
            path_index += 1
    return sequence_index == len(sequence)


def final_evaluation(sequences, critical_ips):
    """
    This procedure create final evaluation of the DEFCON levels for each IP address and its sequences of techniques.
    :param sequences: dictionary containing for each IP address its sequences of techniques
    :param critical_ips: list of the critical IP addresses
    :return:
    """
    evaluation = {}
    attack_paths = create_and_postprocess_kcag()

    for ip_address in sequences:
        if ip_address == " ":
            continue
        evaluation[ip_address] = {'technique': None, 'level': 5}

        for sequence in sequences[ip_address]:
            for attack_path in attack_paths:
                if check_sequence_in_path(sequence, attack_path):
                    for event in sequence:

                        # assign level or decrease the current level
                        if 'Reconnaissance' in event["rule.mitre.tactic"] or \
                                'Resource Development' in event["rule.mitre.tactic"]:
                            if evaluation[ip_address]['level'] > 5:
                                evaluation[ip_address]['level'] = 5
                                evaluation[ip_address]['technique'] = event["rule.mitre.technique"]

                                
                        if ('Initial Access' in event["rule.mitre.tactic"] or
                            'Credential Access' in event["rule.mitre.tactic"]) and ip_address not in critical_ips:
                            if evaluation[ip_address]['level'] > 4:
                                evaluation[ip_address]['level'] = 4
                                evaluation[ip_address]['technique'] = event["rule.mitre.technique"]


                        if (('Initial Access' in event["rule.mitre.tactic"] or
                             'Credential Access' in event["rule.mitre.tactic"]) and ip_address in critical_ips) \
                             or \
                                (('Execution' in event["rule.mitre.tactic"] or
                                  'Privilege Escalation' in event["rule.mitre.tactic"] or
                                  'Discovery' in event["rule.mitre.tactic"] or
                                  'Defense Evasion' in event["rule.mitre.tactic"] or
                                  'Persistence' in event["rule.mitre.tactic"] or
                                  'Lateral Movement' in event["rule.mitre.tactic"] or
                                  'Collection' in event["rule.mitre.tactic"] or
                                  'Command and Control' in event["rule.mitre.tactic"]) and ip_address not in critical_ips):
                            if evaluation[ip_address]['level'] > 3:
                                evaluation[ip_address]['level'] = 3
                                evaluation[ip_address]['technique'] = event["rule.mitre.technique"]


                        if (('Exfiltration' in event["rule.mitre.tactic"] or 'Impact' in event["rule.mitre.tactic"])
                            and ip_address not in critical_ips) \
                            or \
                                (('Execution' in event["rule.mitre.tactic"] or
                                  'Privilege Escalation' in event["rule.mitre.tactic"] or
                                  'Discovery' in event["rule.mitre.tactic"] or
                                  'Defense Evasion' in event["rule.mitre.tactic"] or
                                  'Persistence' in event["rule.mitre.tactic"] or
                                  'Lateral Movement' in event["rule.mitre.tactic"] or
                                  'Collection' in event["rule.mitre.tactic"] or
                                  'Command and Control' in event["rule.mitre.tactic"]) and ip_address in critical_ips):
                            if evaluation[ip_address]['level'] > 2:
                                evaluation[ip_address]['level'] = 2
                                evaluation[ip_address]['technique'] = event["rule.mitre.technique"]


                        if ('Exfiltration' in event["rule.mitre.tactic"] or 'Impact' in event["rule.mitre.tactic"]) and \
                                ip_address in critical_ips:
                            if evaluation[ip_address]['level'] > 1:
                                evaluation[ip_address]['level'] = 1
                                evaluation[ip_address]['technique'] = event["rule.mitre.technique"]

    # Print commands for formatting the output
    print("______________________________________")
    print()
    return evaluation
