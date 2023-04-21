'''
Description: Before s7 communication, the client and server need to establish a connection in COPT.
Author: jechin
Usage: ./astf-sim -f ~/s7/astf/s7_ASTF_copt.py --full -o ~/s7/astf/pcap/s7_ASTF_copt.pcap -t config="config_copt.json"
'''
from trex.astf.api import *
import argparse
import os, sys, json

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from s7module.S7 import *

# # TPKT protocol header
# tpkt = b'\x03\x00\x00\x16'
# # COPT Connect request 
# copt_cr = b'\x11\xe0\x00\x00\x00\x06\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a'
# # COTP Connection Comfirm
# copt_cc = b'\x11\xd0\x00\x06\x00\x03\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02'

# S7_connect_request = tpkt + copt_cr
# S7_connect_confirm = tpkt + copt_cc

def load_config(config_file):
    if not os.path.isabs(config_file):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
    
    if not os.path.exists(config_file):
        colormsg(title_with_color="[Error]", msg="Config file not found: {}".format(config_file), color="red")
        colormsg(title_with_color="[Warn]", msg="Use default config file: config_copt.json", color="yellow")
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config_copt.json")
    
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

def check_config(config: dict):
    if "Connect" not in config.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: Connect", color="red")
        sys.exit(1)
    check_config_connect(config["Connect"])


class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, config):
        # generate s7 protocol packets
        s7 = S7()
        [S7_connect_request, S7_connect_confirm] = s7.CR_and_CC()

        # client commands
        prog_c = ASTFProgram()
        prog_c.delay(1000)
        prog_c.send(S7_connect_request)
        prog_c.recv(len(S7_connect_confirm))
        

        prog_s = ASTFProgram()
        prog_s.accept()
        prog_s.recv(len(S7_connect_request))
        prog_s.send(S7_connect_confirm)
        

        assoc=ASTFAssociationRule(port=81)
        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=[config["Connect"]["sip"], config["Connect"]["sip"]], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=[config["Connect"]["dip"], config["Connect"]["dip"]], distribution="seq")
        # ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq")
        # ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq")
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
        parser.add_argument('--config', type=str, default="config_copt.json", help='path of config file')

        args = parser.parse_args(tunables)
        
        config = load_config(args.config)

        return self.create_profile(config)


def register():
    return Prof1()