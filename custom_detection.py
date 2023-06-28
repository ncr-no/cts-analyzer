import csv


def check_encryption_technique(filename="inputs/wazuh-archives.csv", prefix=r"C:\\log"):
    """
    This function provides custom detection of technique T1486 - Data Encrypted for Impact.
    :param filename: name of file containing data from wazuh-archives index
    :param prefix: name of directory for which the detection is accomplished
    :return:
    """
    output_dictionary = {}

    # Obtain indices for important columns in a CSV file.
    with open(filename, newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"')
        first_row = next(csvreader)
        eventid_id = first_row.index('_source.data.win.system.eventID')
        objectname_id = first_row.index('_source.data.win.eventdata.objectName')
        accesslist_id = first_row.index('_source.data.win.eventdata.accessList')
        accessmask_id = first_row.index('_source.data.win.eventdata.accessMask')
        archives_agent_ip_id = first_row.index('_source.agent.ip')
        archives_timestamp_id = first_row.index('_source.timestamp')

        # Search for indication that T1486 - Data Encrypted for Impact was used.
        for row in csvreader:
            if row[archives_agent_ip_id] not in output_dictionary:
                output_dictionary[row[archives_agent_ip_id]] = {4656: False, "created": False, 4663: False,
                                                                "timestamp": ""}

            # File delete is indicated by general events with IDs 4656 and 4663.
            # File create within the same location is indicated by ID 4663 with specific properties.
            # The last found timestamp is stored in the dictionary.
            if row[eventid_id] == "4656" and row[objectname_id].startswith(prefix):
                output_dictionary[row[archives_agent_ip_id]][4656] = True
                if not output_dictionary[row[archives_agent_ip_id]]["timestamp"] or \
                        output_dictionary[row[archives_agent_ip_id]]["timestamp"] < row[archives_timestamp_id]:
                    output_dictionary[row[archives_agent_ip_id]]["timestamp"] = row[archives_timestamp_id]
            elif row[eventid_id] == "4663" and row[objectname_id].startswith(prefix) and \
                    row[accesslist_id] == "%%4417" and row[accessmask_id] == "0x2":
                output_dictionary[row[archives_agent_ip_id]]["created"] = True
                if not output_dictionary[row[archives_agent_ip_id]]["timestamp"] or \
                        output_dictionary[row[archives_agent_ip_id]]["timestamp"] < row[archives_timestamp_id]:
                    output_dictionary[row[archives_agent_ip_id]]["timestamp"] = row[archives_timestamp_id]
            elif row[eventid_id] == "4663" and row[objectname_id].startswith(prefix):
                output_dictionary[row[archives_agent_ip_id]][4663] = True
                if not output_dictionary[row[archives_agent_ip_id]]["timestamp"] or \
                        output_dictionary[row[archives_agent_ip_id]]["timestamp"] < row[archives_timestamp_id]:
                    output_dictionary[row[archives_agent_ip_id]]["timestamp"] = row[archives_timestamp_id]

        # Provide output in the right format
        technique_dictionary = {}
        for agent_ip in output_dictionary:
            # All three conditions must hold to claim that T1486 was used.
            if output_dictionary[agent_ip][4656] and output_dictionary[agent_ip]["created"] and \
                    output_dictionary[agent_ip][4663]:
                technique_dictionary[agent_ip] = {
                    "rule.mitre.technique": ["Data Encrypted for Impact"],
                    "rule.mitre.id": ["T1486"],
                    "rule.mitre.tactic": ["Impact"],
                    "data.timestamp": output_dictionary[agent_ip]["timestamp"],
                    "data.src_ip": "-",
                    "data.dest_ip": "-"
                }

    return technique_dictionary
