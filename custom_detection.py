import json
from datetime import datetime
from utils import ALLOWED_IPS


def check_selected_techniques(technique_filename, output_dictionary, end_timestamp=None):
    """
    This procedure tests whether techniques T1105, T1496, T1489, T1556.003, T1570, T1529 were captured in data.
    :param technique_filename: filename of Wazuh data
    :param output_dictionary: dictionary with partial results of found techniques
    :param end_timestamp: log events after this timestamp are not processed
    :return:
    """
    system_reboot_start_timestamp = None

    with open(technique_filename, 'r', encoding='UTF-8') as jsonfile:
        for line in jsonfile:
            line_data = json.loads(line)

            if 'ip' not in line_data['agent']:
                continue

            if end_timestamp and end_timestamp < line_data['timestamp']:
                continue

            agent_ip = line_data['agent']['ip']
            if agent_ip not in ALLOWED_IPS:
                continue

            if agent_ip not in output_dictionary:
                output_dictionary[agent_ip] = []

            if 'rule' in line_data and 'description' in line_data['rule'] and \
                    "Application installed Product: PowerShell" in line_data['rule']['description']:
                output_dictionary[agent_ip].append({
                    "rule.mitre.technique": ["Ingress Tool Transfer"],
                    "rule.mitre.id": ["T1105"],
                    "rule.mitre.tactic": ["Command and Control"],
                    "data.timestamp": line_data['timestamp'],
                    "data.src_ip": "-",
                    "data.dest_ip": "-"
                })

            if 'data' in line_data and 'win' in line_data['data'] and "eventdata" in line_data['data']['win'] and\
                    "imagePath" in line_data['data']['win']["eventdata"] and\
                    "xmrig" in line_data['data']['win']["eventdata"]["imagePath"]:
                output_dictionary[agent_ip].append({
                    "rule.mitre.technique": ["Resource Hijacking"],
                    "rule.mitre.id": ["T1496"],
                    "rule.mitre.tactic": ["Impact"],
                    "data.timestamp": line_data['timestamp'],
                    "data.src_ip": "-",
                    "data.dest_ip": "-"
                })

            if "rule" in line_data and 'description' in line_data['rule'] and \
                    "Print Spooler terminated unexpectedly" in line_data["rule"]["description"]:
                output_dictionary[agent_ip].append({
                    "rule.mitre.technique": ["Service Stop"],
                    "rule.mitre.id": ["T1489"],
                    "rule.mitre.tactic": ["Impact"],
                    "data.timestamp": line_data['timestamp'],
                    "data.src_ip": "-",
                    "data.dest_ip": "-"
                })

            if "rule" in line_data and 'description' in line_data['rule'] and \
                    "PAM: Login session opened." in line_data["rule"]["description"]:
                output_dictionary[agent_ip].append({
                    "rule.mitre.technique": ["Pluggable Authentication Modules"],
                    "rule.mitre.id": ["T1556.003"],
                    "rule.mitre.tactic": ["Credential Access", "Defense Evasion", "Persistence"],
                    "data.timestamp": line_data['timestamp'],
                    "data.src_ip": "-",
                    "data.dest_ip": "-"
                })

            if 'data' in line_data and 'file' in line_data['data'] and \
                    "/tmp/install_agent.sh" in line_data['data']['file']:
                output_dictionary[agent_ip].append({
                    "rule.mitre.technique": ["Lateral Tool Transfer"],
                    "rule.mitre.id": ["T1570"],
                    "rule.mitre.tactic": ["Lateral Movement"],
                    "data.timestamp": line_data['timestamp'],
                    "data.src_ip": "-",
                    "data.dest_ip": "-"
                })

            if "rule" in line_data and "description" in line_data["rule"] and \
                    "Ossec agent stopped." in line_data["rule"]["description"]:
                system_reboot_start_timestamp = line_data["timestamp"]
            if "rule" in line_data and "description" in line_data["rule"] and \
                    "Ossec agent started." in line_data["rule"]["description"]:
                system_reboot_end_timestamp = line_data["timestamp"]
                if not system_reboot_start_timestamp:
                    continue
                datetime_start_timestamp = system_reboot_start_timestamp[:-2] + ":" + system_reboot_start_timestamp[-2:]
                datetime_end_timestamp = system_reboot_end_timestamp[:-2] + ":" + system_reboot_end_timestamp[-2:]
                timestamps_timedelta = datetime.fromisoformat(datetime_end_timestamp) - datetime.fromisoformat(
                    datetime_start_timestamp)
                if timestamps_timedelta.days == 0 and timestamps_timedelta.seconds < 60:
                    output_dictionary[agent_ip].append({
                        "rule.mitre.technique": ["System Shutdown/Reboot"],
                        "rule.mitre.id": ["T1529"],
                        "rule.mitre.tactic": ["Impact"],
                        "data.timestamp": system_reboot_start_timestamp,
                        "data.src_ip": "-",
                        "data.dest_ip": "-"
                    })
