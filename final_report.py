from output_postprocessing import create_and_postprocess_kcag
from evaluation.ground_truth import MAPPING_ALERTS_PATH, MAPPING_PROCEDURES_ALERTS


def check_sequence_in_path(sequence, attack_path, ip_address, threshold=0):
    """
    Checks if sequence appears in the path (as pattern)
    :param sequence: sequence of attack techniques from SIEM
    :param attack_path: dictionary with attack techniques from the generated attack graph, IP addresses and
    the lateral movement indication
    :param ip_address: for this IP address the search is accomplished
    :param threshold: threshold value that determines success of matching, 0 means no threshold
    :return:
    """
    sequence_index = 0
    path_index = 0
    last_successful_path_index = 0
    sequence_length = len(sequence)
    attack_path_length = len(attack_path["vertices"])
    found_sequence = []

    if ip_address.replace(".", "") in attack_path["ip_addresses"]:
        if attack_path["lateral_movement"]:
            ip_index = attack_path["ip_addresses"].index(ip_address.replace(".", ""))
            lm_indices = attack_path["lm_indices"]

            # check only part of the attack path for a specific IP address
            path_index = lm_indices[ip_index + 1]
            attack_path_length = lm_indices[ip_index + 2] + 1
            last_successful_path_index = path_index

        while sequence_index < sequence_length:
            if sequence[sequence_index]['rule.mitre.id'][0] == attack_path["vertices"][path_index]['attack_id'] or \
                (sequence[sequence_index]['rule.mitre.id'][0] in list(MAPPING_PROCEDURES_ALERTS.values()) and
                 list(MAPPING_PROCEDURES_ALERTS.keys())[list(MAPPING_PROCEDURES_ALERTS.values()).index(
                     sequence[sequence_index]['rule.mitre.id'][0])] == attack_path["vertices"][path_index][
                     'attack_id']) or \
                    (sequence[sequence_index]['rule.mitre.id'][0] in MAPPING_ALERTS_PATH and
                     MAPPING_ALERTS_PATH[sequence[sequence_index]['rule.mitre.id'][0]] ==
                     attack_path["vertices"][path_index]['attack_id']):

                last_successful_path_index = path_index
                found_sequence.append(sequence[sequence_index])
                sequence_index += 1
                path_index += 1
            else:
                path_index += 1
            if path_index >= attack_path_length:
                path_index = last_successful_path_index
                sequence_index += 1

    if len(found_sequence) / len(sequence) < threshold:
        return []
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
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[
                                ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]
                    if ('Initial Access' in event["rule.mitre.tactic"]) and ip_address not in critical_ips:
                        if evaluation[ip_address]['level'] > 4:
                            evaluation[ip_address]['level'] = 4
                            evaluation[ip_address]['technique'] = [event['rule.mitre.id'][0] +
                                                                   " - " + event["rule.mitre.technique"][0]]
                        elif evaluation[ip_address]['level'] == 4 and \
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[
                                ip_address]['technique']:
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
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[
                                ip_address]['technique']:
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
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[
                                ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]
                    if ('Exfiltration' in event["rule.mitre.tactic"] or 'Impact' in event["rule.mitre.tactic"]) and \
                            ip_address in critical_ips:
                        if evaluation[ip_address]['level'] > 1:
                            evaluation[ip_address]['level'] = 1
                            evaluation[ip_address]['technique'] = [event['rule.mitre.id'][0] +
                                                                   " - " + event["rule.mitre.technique"][0]]
                        elif evaluation[ip_address]['level'] == 1 and \
                                event['rule.mitre.id'][0] + " - " + event["rule.mitre.technique"][0] not in evaluation[
                                ip_address]['technique']:
                            evaluation[ip_address]['technique'] += [event['rule.mitre.id'][0] +
                                                                    " - " + event["rule.mitre.technique"][0]]

    return evaluation
