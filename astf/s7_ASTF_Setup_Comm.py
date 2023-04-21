'''
Description: S7Comm Parameter Function: 0xf0, setup communication, no additional parameter input
Autor: Jechin
Usage: ./astf-sim -f ~/s7/astf/s7_ASTF_Setup_Comm.py --full -o ~/s7/astf/pcap/s7_ASTF_Setup_Comm.pcap -t config="config_Setup_Communication.json"
'''

from trex.astf.api import *
import argparse
import os, sys, json

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from s7module.S7 import *

# def S7_HEADER(rosctr, protocol_data_unit_reference, parameter_length, data_length, reversed=0x0000, error_para=False):
#     if error_para:
#         return b'\x32' + rosctr.to_bytes(1, byteorder='big') + reversed.to_bytes(2, byteorder='big') + \
#             protocol_data_unit_reference.to_bytes(2, byteorder='big') + parameter_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big') + b'\x00\x00'
#     return b'\x32' + rosctr.to_bytes(1, byteorder='big') + reversed.to_bytes(2, byteorder='big') + \
#             protocol_data_unit_reference.to_bytes(2, byteorder='big') + parameter_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big')

# def S7_PARAMETER_JOB_0xF0(function, calling, called, pdu_length, reversed=0x00):
#     return function.to_bytes(1, byteorder='big') + reversed.to_bytes(1, byteorder='big') + calling.to_bytes(2, byteorder='big') + called.to_bytes(2, byteorder='big') + pdu_length.to_bytes(2, byteorder='big')

# # TPKT protocol header without length
# tpkt = b'\x03\x00\x00\x16'
# # COPT Connect request
# copt_cr = b'\x11\xe0\x00\x00\x00\x06\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a'
# # COTP Connection Comfirm
# copt_cc = b'\x11\xd0\x00\x06\x00\x03\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02'

# S7_connect_request = tpkt + copt_cr
# S7_connect_confirm = tpkt + copt_cc

# # S7Comm datagram with Rosctr: 0x01, job and Fuction: 0xf0, setup communication
# s7_job_f0_parameter = S7_PARAMETER_JOB_0xF0(function=0xf0, calling=1, called=1, pdu_length=480)
# s7_header = S7_HEADER(rosctr=0x01, protocol_data_unit_reference=512, parameter_length=len(s7_job_f0_parameter), data_length=0)
# s7_job_f0 = s7_header + s7_job_f0_parameter
# copt_header = b'\x02\xf0\x80'
# tpkt_header = b'\x03\x00' + (len(copt_header + s7_job_f0) + 4).to_bytes(2, byteorder='big')
# S7_job_f0 = tpkt_header + copt_header + s7_job_f0

# # S7Comm datagram with Rosctr: 0x03, ACK DATA and Fuction: 0xf0, setup communication
# s7_job_f0_ack_parameter = S7_PARAMETER_JOB_0xF0(function=0xf0, calling=1, called=1, pdu_length=240)
# s7_header = S7_HEADER(rosctr=0x03, protocol_data_unit_reference=512, parameter_length=len(s7_job_f0_ack_parameter), data_length=0, error_para=True)
# s7_job_f0_ack = s7_header + s7_job_f0_ack_parameter
# copt_header = b'\x02\xf0\x80'
# tpkt_header = b'\x03\x00' + (len(copt_header + s7_job_f0_ack) + 4).to_bytes(2, byteorder='big')
# S7_job_f0_ack = tpkt_header + copt_header + s7_job_f0_ack

def load_config(config_file):
    if not os.path.isabs(config_file):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
    
    if not os.path.exists(config_file):
        colormsg(title_with_color="[Error]", msg="Config file not found: {}".format(config_file), color="red")
        colormsg(title_with_color="[Warn]", msg="Use default config file: config_Setup_Communication.json", color="yellow")
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config_Setup_Communication.json")
    
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
    if "calling" not in config_function.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: calling", color="red")
        sys.exit(1)
    if "called" not in config_function.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: called", color="red")
        sys.exit(1)
    if "pdu_size" not in config_function.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: pdu_size", color="red")
        sys.exit(1)

def check_config(config: dict):
    if "Connect" not in config.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: Connect", color="red")
        sys.exit(1)
    check_config_connect(config["Connect"])

    if "Setup_Communication" not in config.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: Setup_Communication", color="red")
        sys.exit(1)
    check_config_function(config["Setup_Communication"])

class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, config):
        # generate s7 protocol packets
        s7 = S7()
        [S7_connect_request, S7_connect_confirm] = s7.CR_and_CC()
        S7_Job_setup_communication = s7.Job_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte(
            max_amq_calling=config["Setup_Communication"]["calling"],
            max_amq_called=config["Setup_Communication"]["called"],
            pdu_size=config["Setup_Communication"]["pdu_size"]
        )
        S7_Ack_setup_communication = s7.ACK_Data_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte(
            max_amq_calling=config["Setup_Communication"]["calling"],
            max_amq_called=config["Setup_Communication"]["called"],
            pdu_size=config["Setup_Communication"]["pdu_size"]
        )

        # client commands
        prog_c = ASTFProgram()
        prog_c.delay(1000)
        prog_c.send(S7_connect_request)
        prog_c.recv(len(S7_connect_confirm))
        # prog_c.delay(1000)
        prog_c.send(S7_Job_setup_communication)
        prog_c.recv(len(S7_Ack_setup_communication))
        # prog_c.delay(1000)
        

        prog_s = ASTFProgram()
        prog_s.accept()
        prog_s.recv(len(S7_connect_request))
        # prog_s.delay(1000)
        prog_s.send(S7_connect_confirm)
        # prog_s.delay(1000)
        prog_s.recv(len(S7_Job_setup_communication))
        # prog_s.delay(1000)
        prog_s.send(S7_Ack_setup_communication)
        # prog_s.delay(1000)
        

        assoc=ASTFAssociationRule(port=81)
        # ip generator
        # ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq")
        # ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq")
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
        parser.add_argument('--config', type=str, default="config_copt.json", help='path of config file')

        args = parser.parse_args(tunables)
        config = load_config(args.config)
        return self.create_profile(config)


def register():
    return Prof1()
