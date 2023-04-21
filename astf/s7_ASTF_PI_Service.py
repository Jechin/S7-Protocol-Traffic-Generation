'''
Description: 
Autor: Jechin
Usage: ./astf-sim -f ~/s7/astf/s7_ASTF_PI_Service.py --full -o ~/s7/astf/pcap/s7_ASTF_PI_Service.pcap -t config="config_PI_Service.json"
'''

from trex.astf.api import *
import sys
import argparse
import json, os

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from s7module.S7 import *

def check_config_PIService(config: dict):
    if "param_block" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'param_block' key", color="red")
        sys.exit(1)
    if "service" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'service' key", color="red")
        sys.exit(1)

def check_config_connect(config: dict):
    if "sip" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'sip' key", color="red")
        sys.exit(1)
    if "dip" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'dip' key", color="red")
        sys.exit(1)

def check_config(config: dict):
    if "Connect" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'Connect' key", color="red")
        sys.exit(1)
    check_config_connect(config["Connect"])
    if "PIService" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'PIService' key", color="red")
        sys.exit(1)
    check_config_PIService(config["PIService"])

def load_config(config_file: str) -> dict:
    if not os.path.isabs(config_file):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
    if not os.path.exists(config_file):
        colormsg(title_with_color="[Error]", msg="config file not exist", color="red")
        sys.exit(1)
    else:
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except json.decoder.JSONDecodeError:
            colormsg(title_with_color="[Error]", msg="config file format error", color="red")
            sys.exit(1)

    check_config(config)
    return config

class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, config):
        s7 = S7()
        [S7_connect_request, S7_connect_confirm] = s7.CR_and_CC()
        S7_Job_setup_communication = s7.Job_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()
        S7_Ack_setup_communication = s7.ACK_Data_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()

        S7_Job_PI_Service = s7.Job_Determine_Function(function=JobFunction.PI_SERVICE, args=config["PIService"]).generate_byte()
        S7_Ack_PI_Service = s7.ACK_Data_Determine_Function(function=JobFunction.PI_SERVICE, args=config["PIService"]).generate_byte()
        

        # client commands
        prog_c = ASTFProgram()
        prog_c.delay(1000)
        prog_c.send(S7_connect_request)
        prog_c.recv(len(S7_connect_confirm))
        prog_c.send(S7_Job_setup_communication)
        prog_c.recv(len(S7_Ack_setup_communication))

        prog_c.send(S7_Job_PI_Service)
        prog_c.recv(len(S7_Ack_PI_Service))
        
        

        prog_s = ASTFProgram()
        prog_s.accept()
        prog_s.recv(len(S7_connect_request))
        prog_s.send(S7_connect_confirm)
        prog_s.recv(len(S7_Job_setup_communication))
        prog_s.send(S7_Ack_setup_communication)

        prog_s.recv(len(S7_Job_PI_Service))
        prog_s.send(S7_Ack_PI_Service)

        
        assoc=ASTFAssociationRule(port=81)
        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=[config["Connect"]["sip"], config["Connect"]["sip"]], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=[config["Connect"]["dip"], config["Connect"]["dip"]], distribution="seq")
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

        parser.add_argument('--config', type=str, default='config_PI_Service.json', help='path of config file')
        args = parser.parse_args(tunables)
        
        config = load_config(args.config)
        return self.create_profile(config)


def register():
    return Prof1()