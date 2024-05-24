from shutil import copyfile
import os
from configparser import ConfigParser
import pkg_resources


def run_mulval(config_path):
    """
    This function runs MULVAL attack graph generation
    :param config_path: path to the config file
    :return:
    """
    config = ConfigParser()
    config.read(config_path)
    attack_graph = config['attack-graph']

    mulvalroot = attack_graph['mulval_root']
    xsbroot = attack_graph['xsb_root']
    mulval_dir = attack_graph['mulval_dir']
    rules_file = attack_graph['interaction_rules_file']

    os.environ['MULVALROOT'] = mulvalroot
    os.environ['XSBROOT'] = xsbroot
    path = os.environ['PATH']
    os.environ['PATH'] = f'{path}:{mulvalroot}/bin:{mulvalroot}/utils:{xsbroot}/bin:{xsbroot}/build'

    source_rules = pkg_resources.resource_filename(__name__, rules_file)
    if os.path.exists(f'{mulvalroot}/kb/rules.P'):
        os.remove(f'{mulvalroot}/kb/rules.P')
    copyfile(source_rules, f'{mulvalroot}/kb/rules.P')

    current_dir = os.getcwd()
    os.chdir(mulval_dir)

    # following command generates attack graph in pdf, -p option can be added for deep trimming
    os.system(f'graph_gen.sh input_file.P -v -r {mulvalroot}/kb/rules.P')
    #os.system(f'graph_gen.sh input_file.P -v -p -r {mulvalroot}/kb/rules.P')
    os.chdir(current_dir)
