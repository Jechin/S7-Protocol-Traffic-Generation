'''
Description: S7comm parameter function 0x05
Autor: Jechin
Usage: ./astf-sim -f ~/s7/astf/s7_ASTF_Write_Var.py --full -o ~/s7/astf/pcap/s7_ASTF_Write_Var.pcap -t config="config_Write_Var.json"
'''
from trex.astf.api import *
import sys
import argparse
import json, os

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from s7module.S7 import *


def trans_value_to_int(arg_dict):
    for key, value in arg_dict.items():
        if type(value) is list:
            for item in value:
                trans_value_to_int(item)
        elif type(value) is dict:
            trans_value_to_int(value)
        else:
            try:
                arg_dict[key] = int(value, 16)
            except ValueError:
                pass

def prepare_arg_dict(arg_dict):
    if "job" not in arg_dict.keys():
        colormsg(title_with_color='[Error]', msg='missing job', color='red')
        exit(1)
    # arg_dict = input_dict['job']
    trans_value_to_int(arg_dict)
    if len(arg_dict["job"]["param"]) != len(arg_dict["job"]["data"]):
        colormsg(title_with_color='[Error]', msg='param and data length not equal', color='red')
        exit(1)
    if 'param' in arg_dict["job"].keys():
        if type(arg_dict["job"]['param']) is not list:
            colormsg(title_with_color='[Error]', msg='param must be a list', color='red')
            exit(1)
        for item in arg_dict["job"]['param']:
            if 'transport_size' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing transport_size in param[{arg_dict["job"]["param"].index(item)}]', color='red')
                exit(1)
            if 'request_data_length' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing request_data_length in param[{arg_dict["job"]["param"].index(item)}]', color='red')
                exit(1)
            if 'db_number' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing db_number in param[{arg_dict["job"]["param"].index(item)}]', color='red')
                exit(1)
            if 'area' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing area in param[{arg_dict["job"]["param"].index(item)}]', color='red')
                exit(1)
            if 'address' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing address in param[{arg_dict["job"]["param"].index(item)}]', color='red')
                exit(1)
    else:
        colormsg(title_with_color='[Error]', msg='missing param', color='red')
        exit(1)

    if 'data' in arg_dict["job"].keys():
        if type(arg_dict["job"]['data']) is not list:
            colormsg(title_with_color='[Error]', msg='data must be a list', color='red')
            exit(1)
        for item in arg_dict["job"]['data']:
            if 'transport_size' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing transport_size in data[{arg_dict["job"]["data"].index(item)}]', color='red')
                exit(1)
            if 'data_length' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing data_length in data[{arg_dict["job"]["data"].index(item)}]', color='red')
                exit(1)
            if 'data' not in item.keys():
                colormsg(title_with_color='[Error]', msg=f'missing data in data[{arg_dict["data"].index(item)}]', color='red')
                exit(1)
    else:
        colormsg(title_with_color='[Error]', msg='missing data', color='red')
        exit(1)

    if 'item_count' not in arg_dict["job"].keys():
        arg_dict["job"]['item_count'] = len(arg_dict["job"]['param'])

    return arg_dict
            
def load_config(config_file):
    if not os.path.isabs(config_file):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
    
    if not os.path.exists(config_file):
        colormsg(title_with_color="[Error]", msg="Config file not found: {}".format(config_file), color="red")
        colormsg(title_with_color="[Warn]", msg="Use default config file: config_Write_Var.json", color="yellow")
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config_Write_Var.json")
    
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except Exception as e:
        colormsg(title_with_color="[Error]", msg="Load config file failed: {}".format(e), color="red")
        sys.exit(1)

    check_config(config)
    return config

def check_config_connect(config_connect: dict):
    if "sip" not in config_connect.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: sip", color="red")
        sys.exit(1)
    if "dip" not in config_connect.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: dip", color="red")
        sys.exit(1)

def check_config_function(config_function: dict):
    prepare_arg_dict(config_function)

def check_config(config: dict):
    if "Connect" not in config.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: Connect", color="red")
        sys.exit(1)
    check_config_connect(config["Connect"])

    if "Write_Var" not in config.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: Write_Var", color="red")
        sys.exit(1)
    check_config_function(config["Write_Var"])

class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, arg_dict):
        s7 = S7()
        [S7_connect_request, S7_connect_confirm] = s7.CR_and_CC()
        S7_Job_setup_communication = s7.Job_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()
        S7_Ack_setup_communication = s7.ACK_Data_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()
        S7_Job_write_var = s7.Job_Determine_Function(function=JobFunction.WRITE_VAR).generate_byte(
            item_count=arg_dict["Write_Var"]["job"]['item_count'], 
            param_items=arg_dict["Write_Var"]["job"]['param'], 
            data_items=arg_dict["Write_Var"]["job"]['data'])
        S7_Ack_write_var = s7.ACK_Data_Determine_Function(function=JobFunction.WRITE_VAR).generate_byte(
            item_count=len(arg_dict["Write_Var"]["job"]['data']))

        # client commands
        prog_c = ASTFProgram()
        prog_c.delay(1000)
        prog_c.send(S7_connect_request)
        prog_c.recv(len(S7_connect_confirm))
        prog_c.send(S7_Job_setup_communication)
        prog_c.recv(len(S7_Ack_setup_communication))
        prog_c.send(S7_Job_write_var)
        prog_c.recv(len(S7_Ack_write_var))
        

        prog_s = ASTFProgram()
        prog_s.accept()
        prog_s.recv(len(S7_connect_request))
        prog_s.send(S7_connect_confirm)
        prog_s.recv(len(S7_Job_setup_communication))
        prog_s.send(S7_Ack_setup_communication)
        prog_s.recv(len(S7_Job_write_var))
        prog_s.send(S7_Ack_write_var)

        assoc=ASTFAssociationRule(port=81)
        # ip generator
        # ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq")
        # ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq")
        ip_gen_c = ASTFIPGenDist(ip_range=[arg_dict["Connect"]["sip"], arg_dict["Connect"]["sip"]], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=[arg_dict["Connect"]["dip"], arg_dict["Connect"]["dip"]], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)


        # template
        temp_c = ASTFTCPClientTemplate(port=102,program=prog_c,ip_gen=ip_gen,limit=1)
        temp_s = ASTFTCPServerTemplate(program=prog_s,assoc=ASTFAssociationRule(102))  # using default association
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)

        # profile
        profile = ASTFProfile(default_ip_gen=ip_gen, templates=template)
        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        
        # parser.add_argument('--arg', type=str, default='{"param":[],"data":[]}', help='param中需要包含transport_size, request_data_length, db_number, area, address; data中需要包含transport_size, data_length, data, fill_data')
        # print(tunables)
        # print(type(tunables))
        # args = parser.parse_args(tunables)
        # print(args.arg)
        # arg_dict = parse_arg_str(args.arg)

        parser.add_argument('--config', type=str, default='config_Write_Var.json', help='path of config file')
        args = parser.parse_args(tunables)
        config = load_config(args.config)
        return self.create_profile(config)


def register():
    return Prof1()
