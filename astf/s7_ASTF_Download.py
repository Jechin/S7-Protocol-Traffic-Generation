'''
Description: 
Autor: Jechin
Usage: ./astf-sim -f ~/s7/astf/s7_ASTF_Download.py --full -o ~/s7/astf/pcap/s7_ASTF_Download.pcap -t config="config_Download.json"
'''
from trex.astf.api import *
import sys
import argparse
import json, os

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from s7module.S7 import *

def check_config_download(config: dict):
    if "request" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'request' key", color="red")
        sys.exit(1)
    if "filename_length" not in config["request"].keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'filename_length' key", color="red")
        sys.exit(1)
    if "filename" not in config["request"].keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'filename' key", color="red")
        sys.exit(1)
        
    if "download" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'download' key", color="red")
        sys.exit(1)
    if "download_data" not in config["download"].keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'download_data' key", color="red")
        sys.exit(1)
    if type(config["download"]["download_data"]) != list:
        colormsg(title_with_color="[Error]", msg="config file error: 'download_data' must be list", color="red")
        sys.exit(1)
    
    for item in config["download"]["download_data"]:
        if "data_length" not in item.keys():
            colormsg(title_with_color="[Error]", msg="missing 'data_length' key in download_data[{}]".format(config["download"]["download_data"].index(item)), color="red")
            sys.exit(1)
        if "data" not in item.keys():
            colormsg(title_with_color="[Error]", msg="missing 'data' key in download_data[{}]".format(config["download"]["download_data"].index(item)), color="red")
            sys.exit(1)
        if len(item["data"]) != item["data_length"]:
            item["data_length"] = len(item["data"])
            colormsg(title_with_color="[Warning]", msg="data length is not equal to data_length, data_length will be changed to {}".format(item["data_length"]), color="yellow")

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
    if "Download" not in config.keys():
        colormsg(title_with_color="[Error]", msg="config file error: no 'Download' key", color="red")
        sys.exit(1)
    check_config_download(config["Download"])

def load_config(config_file: str):
    if not os.path.isabs(config_file):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
    if not os.path.exists(config_file):
        colormsg(title_with_color="[Error]", msg="config file not exist", color="red")
        sys.exit(1)
    else:
        try:
            with open(config_file, 'r') as f:
                arg_dict = json.load(f)
        except json.decoder.JSONDecodeError:
            colormsg(title_with_color="[Error]", msg="config file format error", color="red")
            sys.exit(1)
    check_config(arg_dict)
    return arg_dict

class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, arg_dict):
        s7 = S7()
        [S7_connect_request, S7_connect_confirm] = s7.CR_and_CC()
        S7_Job_setup_communication = s7.Job_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()
        S7_Ack_setup_communication = s7.ACK_Data_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()

        job_download_obj = s7.Job_Determine_Function(function=JobFunction.DOWNLOAD_BLOCK, args=arg_dict["Download"])
        ack_download_obj = s7.ACK_Data_Determine_Function(function=JobFunction.DOWNLOAD_BLOCK, args=arg_dict["Download"])
        S7_Job_req_download = job_download_obj.generate_request_download()
        S7_Ack_req_download = ack_download_obj.generate_request_download()
        S7_Job_download = job_download_obj.generate_download()
        S7_Ack_download = ack_download_obj.generate_download()
        loop_count = len(S7_Ack_download)
        S7_Job_download_ended = job_download_obj.generate_download_ended()
        S7_Ack_download_ended = ack_download_obj.generate_download_ended()

        # client commands
        prog_c = ASTFProgram()
        prog_c.delay(1000)
        prog_c.send(S7_connect_request)
        prog_c.recv(len(S7_connect_confirm))
        prog_c.send(S7_Job_setup_communication)
        prog_c.recv(len(S7_Ack_setup_communication))

        prog_c.send(S7_Job_req_download)
        prog_c.recv(len(S7_Ack_req_download))
        for i in range(loop_count):
            prog_c.recv(len(S7_Job_download))
            prog_c.send(S7_Ack_download[i])
        prog_c.recv(len(S7_Job_download_ended))
        prog_c.send(S7_Ack_download_ended)
        
        

        prog_s = ASTFProgram()
        prog_s.accept()
        prog_s.recv(len(S7_connect_request))
        prog_s.send(S7_connect_confirm)
        prog_s.recv(len(S7_Job_setup_communication))
        prog_s.send(S7_Ack_setup_communication)

        prog_s.recv(len(S7_Job_req_download))
        prog_s.send(S7_Ack_req_download)
        for i in range(loop_count):
            prog_s.send(S7_Job_download)
            prog_s.recv(len(S7_Ack_download[i]))
        prog_s.send(S7_Job_download_ended)
        prog_s.recv(len(S7_Ack_download_ended))
        
        assoc=ASTFAssociationRule(port=81)
        # ip generator
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

        parser.add_argument('--config', type=str, default='config_Download.json', help='path of config file')
        args = parser.parse_args(tunables)
        config = load_config(args.config)
        return self.create_profile(config)


def register():
    return Prof1()
