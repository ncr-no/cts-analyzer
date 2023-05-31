# creates file: /tmp/mulval_dir/input_file.P
# file is 82 lines long
from input_convertor import convert_input
convert_input('/tmp/mulval_dir/input_file.P')


# file: /tmp/mulval_dir directory with various files
# Vertices, graphs, running_rules etc.
from generator import generate_kcag
generate_kcag()


# creates file output_dictionary.json located in `outputs` directory
from evidence_path import process_restricted_files
lev1 = process_restricted_files()

print("+++++++++++++++++++++++++++++")
print(lev1)

"""

# DEFCON
1-5, where 1 is the most severe and 5 is the least severe


+++++++++++++++++++++++++++++
{'10.11.9.133': {'technique': ['Stored Data Manipulation'], 'level': 1}, 
'10.11.1.10': {'technique': ['Stored Data Manipulation'], 'level': 1}, '10.11.2.113': 
{'technique': ['Stored Data Manipulation'], 'level': 1}, '10.11.4.174': 
{'technique': None, 'level': 5}, '10.11.4.138': 
{'technique': None, 'level': 5}, '10.11.3.10': 
{'technique': None, 'level': 5}, '10.11.4.172': 
{'technique': None, 'level': 5}}


"""