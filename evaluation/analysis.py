import json
from datetime import datetime, timedelta
from pprint import pprint
import matplotlib.pyplot as plt
from sklearn.metrics import RocCurveDisplay
from matplotlib.transforms import Bbox
from final_report import check_sequence_in_path
from evaluation.ground_truth import (GROUND_TRUTH, MAPPING_ALERTS_PATH, MAPPING_PROCEDURES_ALERTS, TRUE_POSITIVE_IDS,
                                     SCENARIOS)
from evidence_path import process_restricted_files, TECHNIQUE_FILENAMES
from utils import CRITICAL_IPS, SEVERITY_LEVELS_MAPPING


def get_statistics(input_files):
    """
    This procedure outputs how many alerts belong to inidivudal groups - Suricata alerts, ATT&CK alerts
    and other alerts.
    :param input_files: input files from which the statistics is computed
    :return:
    """
    techniques = set()
    all_alerts = 0
    mitre_attack_alerts = 0
    suricata_alerts = 0
    for input_file in input_files:
        with open(input_file, 'r', encoding="UTF-8") as json_file:
            for line in json_file:
                all_alerts += 1
                data = json.loads(line)
                if "mitre" in data["rule"] and "id" in data["rule"]["mitre"]:
                    for mitre_id in data["rule"]["mitre"]["id"]:
                        techniques.add(mitre_id)
                    mitre_attack_alerts += 1
                elif "groups" in data["rule"] and "suricata" in data["rule"]["groups"]:
                    # Examples of Suricata messages:
                    # Suricata: Alert - ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management
                    # Suricata: Alert - SURICATA HTTP unable to match response to request
                    # Suricata: Alert - SURICATA HTTP too many warnings
                    # Suricata: Alert - SURICATA STREAM pkt seen on wrong thread
                    suricata_alerts += 1

                # Examples of other messages:
                # 'Windows logon success.'
                # 'Windows User Logoff.'
                # 'Name resolution for the name ... timed out'
                # 'Windows installer began an installation process.'
                # 'Windows installer reconfigured the product.'
                # 'SLUI.exe launched.'
                # "Summary event of the report's signatures."
                # 'Application installed ...'
                # 'Software protection service scheduled successfully.'
                # 'Service startup type was changed'
                # 'Windows System error event'
                # 'Print Spooler terminated unexpectedly'

    print(f"{techniques}, len: {len(techniques)}")
    print(f"All alerts: {all_alerts}, MITRE ATT&CK alerts: {mitre_attack_alerts}, Suricata alerts: {suricata_alerts}.")


def compute_minimum_and_maximum_length_of_scenarios(input_file="outputs/sequences_sorted.json"):
    """
    This procedure computes range of evidence paths for scenarios.
    :param input_file: input file that contains evidence paths
    :return:
    """
    min_length = 100
    max_length = 0
    count_of_sequences = 0
    count_lm_sequences = 0
    count_dictionary = {}
    with open(input_file, "r", encoding='UTF-8') as jsonfile:
        json_data = json.load(jsonfile)
        for ip_address in json_data:
            count_of_sequences += len(json_data[ip_address])
            for sequence in json_data[ip_address]:
                if len(sequence) < min_length:
                    min_length = len(sequence)
                if len(sequence) > max_length:
                    max_length = len(sequence)
                if len(sequence) not in count_dictionary:
                    count_dictionary[len(sequence)] = 0
                count_dictionary[len(sequence)] += 1
                for item in sequence:
                    if "Lateral Movement" in item["rule.mitre.tactic"]:
                        count_lm_sequences += 1
                        break
    print(f"Min and max length: {min_length}, {max_length}")
    print(f"Count of sequences: {count_of_sequences}")
    print(f"Count of lm sequences: {count_lm_sequences}")
    print(f"Counts for length of sequences: {count_dictionary}")


def get_statistics_about_evidence_paths(compressed_events_dictionary, evidence_sequences_dictionary):
    """
    This function analyzes whether all techniques from compressed events were used in evidence paths.
    Each of them has True or False in the result value indicating whether they were found.
    :param compressed_events_dictionary: path to JSON file containing the compressed events dictionary
    :param evidence_sequences_dictionary: path to JSON file containing evidence paths dictionary
    :return:
    """
    statistics = {}
    with open(compressed_events_dictionary, "r", encoding='UTF-8') as events_file:
        with open(evidence_sequences_dictionary, "r", encoding='UTF-8') as sequences_file:
            compressed_events = json.load(events_file)
            sequences = json.load(sequences_file)
            for ip_address in compressed_events:
                statistics[ip_address] = {}
                for event in compressed_events[ip_address]:
                    if not event["rule.mitre.id"]:
                        continue
                    statistics[ip_address][event["rule.mitre.id"][0]] = False
                    for sequence in sequences[ip_address]:
                        if event["rule.mitre.id"] in [i["rule.mitre.id"] for i in sequence]:
                            statistics[ip_address][event["rule.mitre.id"][0]] = True
                            break
    return statistics


def get_statistics_about_attack_paths(compressed_events_dictionary, attack_paths):
    """
    This procedure returns two dictionaries where keys are ATT&CK IDs. The first one specifies which
    IDs from Wazuh data appeared in attack paths and the second one which IDs from attack paths were
    also captured in Wazuh data.
    :param compressed_events_dictionary: JSON file with dictionary of compressed Wazuh events
    :param attack_paths: JSON file containing attack paths from KCAG.
    :return:
    """
    alerts_statistics = {}
    attack_paths_statistics = {}
    with open(compressed_events_dictionary, "r", encoding='UTF-8') as events_file:
        with open(attack_paths, "r", encoding='UTF-8') as attack_paths_file:
            compressed_events = json.load(events_file)
            attack_paths = json.load(attack_paths_file)
            for ip_address in compressed_events:
                alerts_statistics[ip_address] = {}
                for event in compressed_events[ip_address]:
                    alerts_statistics[ip_address][event["rule.mitre.id"][0]] = False
                    for attack_path in attack_paths:
                        # structure of "lm_indices" list in attack paths:
                        # [0, 1) - externalActor without IP
                        # [1, i) - first IP
                        # [j, len(attack_path) - 1] - last IP
                        if ip_address.replace('.', '') in attack_path["ip_addresses"]:
                            ip_address_index = attack_path["ip_addresses"].index(ip_address.replace('.', ''))
                            lower_lm_index = attack_path["lm_indices"][ip_address_index + 1]
                            upper_lm_index = attack_path["lm_indices"][ip_address_index + 2]

                            if event["rule.mitre.id"][0] in [
                                i["attack_id"] for i in attack_path["vertices"][lower_lm_index:upper_lm_index]] or \
                                    (event["rule.mitre.id"][0] == "T1078" and
                                     "T1078.001" in [i["attack_id"] for i in
                                                     attack_path["vertices"][lower_lm_index:upper_lm_index]]) or \
                                    (event["rule.mitre.id"][0] == "T1078" and
                                     "T1078.003" in [i["attack_id"] for i in
                                                     attack_path["vertices"][lower_lm_index:upper_lm_index]]) or \
                                    (event["rule.mitre.id"][0] in MAPPING_PROCEDURES_ALERTS and
                                     MAPPING_PROCEDURES_ALERTS[event["rule.mitre.id"][0]] in [
                                         i["attack_id"] for i in
                                         attack_path["vertices"][lower_lm_index:upper_lm_index]]):
                                alerts_statistics[ip_address][event["rule.mitre.id"][0]] = True
                                break

                        for vertex in attack_path["vertices"]:
                            if vertex["attack_id"] not in attack_paths_statistics:
                                attack_paths_statistics[vertex["attack_id"]] = False

                            if vertex["attack_id"] in [key for ip_address in alerts_statistics for key in
                                                       alerts_statistics[ip_address]] or \
                                    (vertex["attack_id"] == "T1078.001" and
                                     "T1078" in [key for ip_address in alerts_statistics for key in
                                                 alerts_statistics[ip_address]]) or \
                                    (vertex["attack_id"] == "T1078.003" and
                                     "T1078" in [key for ip_address in alerts_statistics for key in
                                                 alerts_statistics[ip_address]]) or \
                                    (vertex["attack_id"] in list(MAPPING_PROCEDURES_ALERTS.values()) and
                                     list(MAPPING_PROCEDURES_ALERTS.keys())[
                                         list(MAPPING_PROCEDURES_ALERTS.values()).index(vertex["attack_id"])] in
                                     [key for ip_address in alerts_statistics for key in
                                      alerts_statistics[ip_address]]):

                                attack_paths_statistics[vertex["attack_id"]] = True
    return alerts_statistics, attack_paths_statistics


def get_depth_of_paths(path="attack_paths.json"):
    """
    This function computes how many vertices are in attack paths.
    :param path: path to JSON file containing attack paths
    :return:
    """
    length_dictionary = {}
    with open(path, "r", encoding='UTF-8') as attack_paths_file:
        attack_paths = json.load(attack_paths_file)
    for attack_path in attack_paths:
        if len(attack_path["vertices"]) not in length_dictionary:
            length_dictionary[len(attack_path["vertices"])] = 0
        length_dictionary[len(attack_path["vertices"])] += 1

    return length_dictionary


def get_statistical_metrics(threshold, evidence_paths_filename="outputs/sequences_sorted.json",
                            attack_paths_filename="attack_paths.json"):
    """
    This function computes true positives, true negatives, false positives, and false negatives.
    :param threshold: threshold values used to classify evidence paths ranging from 0 to 1
    :param evidence_paths_filename: JSON filename containing evidence paths
    :param attack_paths_filename: JSON filename containing attack paths
    :return:
    """

    with open(evidence_paths_filename, "r", encoding='UTF-8') as output_file:
        sequences = json.load(output_file)
    with open(attack_paths_filename, "r", encoding='UTF-8') as attack_paths_file:
        attack_paths = json.load(attack_paths_file)
    results = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for ip_address in sequences:
        print(ip_address)
        for sequence in sequences[ip_address]:
            sequence_results = []
            for attack_path in attack_paths:
                found_sequence = check_sequence_in_path(sequence, attack_path, ip_address)
                if len(found_sequence) / len(sequence) >= threshold:
                    if check_sequence_in_ground_truth(sequence, GROUND_TRUTH):
                        sequence_results.append("TP")
                    else:
                        sequence_results.append("FP")
                else:
                    if found_sequence and check_sequence_in_ground_truth(sequence, GROUND_TRUTH):
                        sequence_results.append("FN")
                    else:
                        sequence_results.append("TN")
            if "TP" in sequence_results:
                results["TP"] += 1
            elif "FP" in sequence_results:
                results["FP"] += 1
            elif "FN" in sequence_results:
                results["FN"] += 1
            elif "TN" in sequence_results:
                results["TN"] += 1
            print(results)
    return results


def check_sequence_in_ground_truth(sequence, ground_truth_paths):
    """
    This function checks whether a sequence of alerts (evidence path) is in a ground truth path.
    :param sequence: evidence path
    :param ground_truth_paths: sequences of ATT&CK IDs representing the ground truth
    :return:
    """
    for path in ground_truth_paths:
        if (all([item['rule.mitre.id'][0] in path or
                (item['rule.mitre.id'][0] in list(MAPPING_PROCEDURES_ALERTS.values()) and
                 list(MAPPING_PROCEDURES_ALERTS.keys())[
                     list(MAPPING_PROCEDURES_ALERTS.values()).index(item['rule.mitre.id'][0])] in path) or
                 (item['rule.mitre.id'][0] in MAPPING_ALERTS_PATH and
                  MAPPING_ALERTS_PATH[item['rule.mitre.id'][0]] in path)
                 for item in sequence])):

            for i in range(len(sequence)):
                item = sequence[i]

                if (item['rule.mitre.id'][0] not in path and
                        (item['rule.mitre.id'][0] in list(MAPPING_PROCEDURES_ALERTS.values()) and
                         list(MAPPING_PROCEDURES_ALERTS.keys())[
                             list(MAPPING_PROCEDURES_ALERTS.values()).index(item['rule.mitre.id'][0])] in path)):
                    sequence[i]['rule.mitre.id'][0] = list(MAPPING_PROCEDURES_ALERTS.keys())[
                        list(MAPPING_PROCEDURES_ALERTS.values()).index(item['rule.mitre.id'][0])]
                elif (item['rule.mitre.id'][0] in MAPPING_ALERTS_PATH and
                      MAPPING_ALERTS_PATH[item['rule.mitre.id'][0]] in path):
                    sequence[i]['rule.mitre.id'][0] = MAPPING_ALERTS_PATH[item['rule.mitre.id'][0]]

            if all([path.index(sequence[i]['rule.mitre.id'][0]) <= path.index(
                    sequence[i+1]['rule.mitre.id'][0]) for i in range(len(sequence) - 1)]) and \
                    path.index(sequence[-1]['rule.mitre.id'][0]) <= len(sequence):
                return True

    return False


def evaluation_of_correctness_metrics(evidence_paths_filename="outputs/sequences_sorted.json",
                                      attack_paths_filename="attack_paths.json"):
    """
    This function outputs classification metrics for various thresholds of match score.
    :param evidence_paths_filename: filename for JSON containing evidence paths
    :param attack_paths_filename: filename for JSON containing attack paths
    :return:
    """
    process_restricted_files()
    sequences_count = {"true": 0, "false": 0}
    results = {"true": [], "false": []}

    with open(evidence_paths_filename, "r", encoding="UTF-8") as sequences_file:
        sequences = json.load(sequences_file)
    with open(attack_paths_filename, "r", encoding='UTF-8') as attack_paths_file:
        attack_paths = json.load(attack_paths_file)

    for ip_address in sequences:
        for sequence in sequences[ip_address]:
            found = False

            for scenario_ip in SCENARIOS:
                if scenario_ip != ip_address:
                    continue
                for scenario in SCENARIOS[scenario_ip]:
                    if all([item["rule.mitre.id"][0] in TRUE_POSITIVE_IDS for item in sequence]) and \
                            all([item["rule.mitre.id"][0] in scenario for item in sequence]) and \
                            all([scenario.index(sequence[i]['rule.mitre.id'][0]) <= scenario.index(
                                sequence[i + 1]['rule.mitre.id'][0])
                                 for i in range(len(sequence) - 1)]):
                        found = True
                    if all([item["rule.mitre.id"][0] in TRUE_POSITIVE_IDS for item in sequence[1:]]) and \
                            all([item["rule.mitre.id"][0] in scenario for item in sequence[1:]]) and \
                            all([scenario.index(sequence[i]['rule.mitre.id'][0]) <= scenario.index(
                                sequence[i + 1]['rule.mitre.id'][0])
                                 for i in range(1, len(sequence) - 1)]):
                        found = True

            if found:
                sequences_count["true"] += 1
                best_match = 0
                best_found_sequence = None
                for attack_path in attack_paths:
                    found_sequence = check_sequence_in_path(sequence, attack_path, ip_address)
                    if len(found_sequence) / len(sequence) > best_match:
                        best_match = len(found_sequence) / len(sequence)
                        best_found_sequence = found_sequence
                results["true"].append(best_match)
                if best_match < 0.9:
                    print(ip_address, sequence)
                    print(f"found_sequence: {best_found_sequence}")
            else:
                sequences_count["false"] += 1
                best_match = 0
                for attack_path in attack_paths:
                    found_sequence = check_sequence_in_path(sequence, attack_path, ip_address)
                    if len(found_sequence) / len(sequence) > best_match:
                        best_match = len(found_sequence) / len(sequence)
                results["false"].append(best_match)
    print(results)

    # Length of an evidence path is i + 1
    # We allow one missing alert in evidence path, i.e., length of i
    for i in range(1, 11):
        threshold = i / (i+1)
        iteration_results = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        for key in results:
            for value in results[key]:
                if key == "true":
                    if value >= threshold:
                        iteration_results["TP"] += 1
                    else:
                        iteration_results["FN"] += 1
                else:
                    if value >= threshold:
                        iteration_results["FP"] += 1
                    else:
                        iteration_results["TN"] += 1

        precision = iteration_results['TP'] / (iteration_results['TP'] + iteration_results['FP'])
        accuracy = ((iteration_results['TP'] + iteration_results['TN']) /
                    (iteration_results['TP'] + iteration_results['FP'] +
                     iteration_results['TN'] + iteration_results['FN']))
        recall = iteration_results['TP'] / (iteration_results['TP'] + iteration_results['FN'])
        f1_score = 2 * precision * recall / (precision + recall)
        print(f"Iteration {i}/{i+1}: {iteration_results}, precision: {precision}, accuracy:"
              f"{accuracy}, recall: {recall}, f1_score: {f1_score}")

    return sequences_count, results


def draw_roc_curve():
    """
    This procedure draws ROC curve for match scores of individual evidence paths compared with the ground truth.
    :return:
    """
    _, results = evaluation_of_correctness_metrics()
    y_true = [1] * len(results['true']) + [0] * len(results['false'])
    y_score = results['true'] + results['false']

    figure = plt.figure()
    plt.rc('font', size=14)
    axes_objects = plt.gca()
    RocCurveDisplay.from_predictions(y_true=y_true, y_pred=y_score, ax=axes_objects, name="Proposed approach")
    plt.show()
    figure.savefig("outputs/auc_jisa.pdf",
                   bbox_inches=Bbox([[0, 0], [5.898, 4.37]]),
                   pad_inches=0.1)


def get_severity_levels_for_timestamps(results_filename="outputs/results.txt"):
    """
    This procedure computes progress of computation for individual days from Wazuh data.
    :param results_filename: filename of output results
    :return:
    """
    with open(results_filename, "w", encoding="UTF-8") as txtfile:
        start_datetime = datetime.fromisoformat("2023-12-04T00:00:00.000")
        for i in range(7):
            current_datetime = (start_datetime + timedelta(days=i)).isoformat()
            txtfile.write(str(process_restricted_files(current_datetime)))
            txtfile.write('\n')
            txtfile.flush()


def get_counts_of_techniques(ip_address):
    """
    This function return how many times individual ATT&CK techniques appeared in alerts.
    :param ip_address: IP address for which the analysis is accomplished
    :return:
    """
    techniques = {}
    for filename in TECHNIQUE_FILENAMES:
        with open(filename, "r", encoding="UTF-8") as jsonfile:
            for line in jsonfile:
                line_data = json.loads(line)
                if "agent" in line_data and "ip" in line_data["agent"] and line_data["agent"]["ip"] == ip_address:
                    if "rule" in line_data and "mitre" in line_data["rule"] and "id" in line_data["rule"]["mitre"]:
                        for attack_id in line_data["rule"]["mitre"]["id"]:
                            if attack_id not in techniques:
                                techniques[attack_id] = 0
                            techniques[attack_id] += 1
    return techniques


def get_confusion_matrices(evidence_paths_filename="outputs/sequences_sorted.json",
                           attack_paths_filename="attack_paths.json", critical_ips=CRITICAL_IPS):
    """
    This function computes confusion matrices for true positives, true negatives, false positives, and false negatives
    for different threshold values. The final confusion matrices should be the sum of four partial matrices for
    true positives, true negatives, false positives, and false negatives.
    :param evidence_paths_filename: JSON filename containing evidence paths
    :param attack_paths_filename: JSON filename containing attack paths
    :param critical_ips: A list of IP addresses that are considered critical
    :return:
    """

    process_restricted_files()

    with open(evidence_paths_filename, "r", encoding="UTF-8") as sequences_file:
        sequences = json.load(sequences_file)
    with open(attack_paths_filename, "r", encoding='UTF-8') as attack_paths_file:
        attack_paths = json.load(attack_paths_file)

    # The first index of the following confusion matrix is expected value, while the second index is predicted value
    # For the purpose of detailed analysis, results are divided according to true positives (TP) and other categories
    # The confusion matrix is sum of the four partial matrices
    for i in [0] + list(range(1, 11)):
        threshold = i / (i + 1)
        five_level_confusion_matrix = {
            "TP": [[0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0]],
            "FP": [[0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0]],
            "TN": [[0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0]],
            "FN": [[0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0]]
        }

        for ip_address in sequences:
            print(ip_address)
            if ip_address in critical_ips:
                criticality = "critical"
            else:
                criticality = "noncritical"
            for sequence in sequences[ip_address]:
                found = False

                for scenario_ip in SCENARIOS:
                    if scenario_ip != ip_address:
                        continue
                    for scenario in SCENARIOS[scenario_ip]:
                        if all([item["rule.mitre.id"][0] in TRUE_POSITIVE_IDS for item in sequence]) and \
                                all([item["rule.mitre.id"][0] in scenario for item in sequence]) and \
                                all([scenario.index(sequence[i]['rule.mitre.id'][0]) <= scenario.index(
                                    sequence[i + 1]['rule.mitre.id'][0])
                                     for i in range(len(sequence) - 1)]):
                            found = True
                        if all([item["rule.mitre.id"][0] in TRUE_POSITIVE_IDS for item in sequence[1:]]) and \
                                all([item["rule.mitre.id"][0] in scenario for item in sequence[1:]]) and \
                                all([scenario.index(sequence[i]['rule.mitre.id'][0]) <= scenario.index(
                                    sequence[i + 1]['rule.mitre.id'][0])
                                     for i in range(1, len(sequence) - 1)]):
                            found = True

                if found:
                    best_match = 0
                    best_found_sequence = None
                    for attack_path in attack_paths:
                        found_sequence = check_sequence_in_path(sequence, attack_path, ip_address)
                        if len(found_sequence) / len(sequence) > best_match:
                            best_match = len(found_sequence) / len(sequence)
                            best_found_sequence = found_sequence
                    if best_match >= threshold:
                        expected_value = get_expected_severity_level_for_sequence(sequence, criticality)
                        all_severity_levels = [SEVERITY_LEVELS_MAPPING[criticality][tactic]
                                               for item in best_found_sequence
                                               for tactic in item['rule.mitre.tactic']]
                        predicted_value = min(all_severity_levels)
                        five_level_confusion_matrix["TP"][expected_value - 1][predicted_value - 1] += 1
                    else:
                        predicted_value = 5
                        expected_value = get_expected_severity_level_for_sequence(sequence, criticality)
                        five_level_confusion_matrix["FN"][expected_value - 1][predicted_value - 1] += 1
                else:
                    best_match = 0
                    best_found_sequence = None
                    for attack_path in attack_paths:
                        found_sequence = check_sequence_in_path(sequence, attack_path, ip_address)
                        if len(found_sequence) / len(sequence) > best_match:
                            best_match = len(found_sequence) / len(sequence)
                            best_found_sequence = found_sequence
                    if best_match >= threshold:
                        all_severity_levels = [SEVERITY_LEVELS_MAPPING[criticality][tactic]
                                               for item in best_found_sequence
                                               for tactic in item['rule.mitre.tactic']]
                        predicted_value = min(all_severity_levels)
                        expected_value = get_expected_severity_level_for_sequence(sequence, criticality)
                        five_level_confusion_matrix["FP"][expected_value - 1][predicted_value - 1] += 1
                    else:
                        predicted_value = 5
                        expected_value = get_expected_severity_level_for_sequence(sequence, criticality)
                        five_level_confusion_matrix["TN"][expected_value - 1][predicted_value - 1] += 1
        print(f"Threshold: {threshold}")
        pprint(five_level_confusion_matrix)
        print()


def get_expected_severity_level_for_sequence(sequence, criticality):
    """
    This function determines severity value for a sequence of attack techniques
    according to the criticality of asset that is impacted.
    :param sequence: a sequence of attack techniques
    :param criticality: criticality of asset that is impacted
    :return:
    """
    for item in reversed(sequence):
        if len(item['rule.mitre.id']) > 1:
            raise ValueError("List has more than one item.")
        if item['rule.mitre.id'][0] in TRUE_POSITIVE_IDS:
            return min([SEVERITY_LEVELS_MAPPING[criticality][item['rule.mitre.tactic'][i]]
                        for i in range(len(item['rule.mitre.tactic']))])
    return 5