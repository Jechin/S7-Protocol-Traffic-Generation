'''
Description: Before s7 communication, the client and server need to establish a connection in COPT.
Usage: ./astf-sim -f ~/s7/astf/test.py --full -o ~/s7/astf/pcap/test.pcap
'''
from trex.astf.api import *
import sys, os, json
import argparse

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

    trans_value_to_int(config["Write_Var"])
    trans_value_to_int(config["Read_Var"])
    return config

class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, config):
        # generate packets
        s7 = S7()
        [S7_connect_request, S7_connect_confirm] = s7.CR_and_CC()
        S7_Job_setup_communication = s7.Job_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()
        S7_Ack_setup_communication = s7.ACK_Data_Determine_Function(function=JobFunction.SETUP_COMMUNICATION).generate_byte()
        S7_Job_read_var = s7.Job_Determine_Function(function=JobFunction.READ_VAR).generate_byte(item_count=2)
        S7_Ack_read_var = s7.ACK_Data_Determine_Function(function=JobFunction.READ_VAR).generate_byte(item_count=2)
        S7_Job_write_var = s7.Job_Determine_Function(function=JobFunction.WRITE_VAR).generate_byte(item_count=2)
        S7_Ack_write_var = s7.ACK_Data_Determine_Function(function=JobFunction.WRITE_VAR).generate_byte(item_count=2)
        job_download_obj = s7.Job_Determine_Function(function=JobFunction.DOWNLOAD_BLOCK)
        ack_download_obj = s7.ACK_Data_Determine_Function(function=JobFunction.DOWNLOAD_BLOCK)
        S7_Job_req_download = job_download_obj.generate_request_download()
        S7_Ack_req_download = ack_download_obj.generate_request_download()
        S7_Job_download = job_download_obj.generate_download()
        S7_Ack_download = ack_download_obj.generate_download()
        loop_count = len(S7_Ack_download)
        S7_Job_download_ended = job_download_obj.generate_download_ended()
        S7_Ack_download_ended = ack_download_obj.generate_download_ended()
        job_upload_obj = s7.Job_Determine_Function(JobFunction.UPLOAD, args=config["Upload"])
        ack_upload_obj = s7.ACK_Data_Determine_Function(JobFunction.UPLOAD, args=config["Upload"])
        S7_Job_start_upload = job_upload_obj.generate_start_upload()
        S7_Ack_start_upload = ack_upload_obj.generate_start_upload()
        S7_Job_upload = job_upload_obj.generate_upload()
        S7_Ack_upload = ack_upload_obj.generate_upload()
        S7_Job_end_upload = job_upload_obj.generate_end_upload()
        S7_Ack_end_upload = ack_upload_obj.generate_end_upload()
        S7_Job_PI_Service = s7.Job_Determine_Function(function=JobFunction.PI_SERVICE, args=config["PIService"]).generate_byte()
        S7_Ack_PI_Service = s7.ACK_Data_Determine_Function(function=JobFunction.PI_SERVICE, args=config["PIService"]).generate_byte()
        S7_Job_Stop = s7.Job_Determine_Function(function=JobFunction.PLC_STOP, args=config["PLC_Stop"]).generate_byte()
        S7_Ack_Stop = s7.ACK_Data_Determine_Function(function=JobFunction.PLC_STOP, args=config["PLC_Stop"]).generate_byte()

        # client commands
        prog_c = ASTFProgram()
        prog_c.delay(1000)
        prog_c.send(S7_connect_request)
        prog_c.recv(len(S7_connect_confirm))
        prog_c.send(S7_Job_setup_communication)
        prog_c.recv(len(S7_Ack_setup_communication))
        prog_c.send(S7_Job_read_var)
        prog_c.recv(len(S7_Ack_read_var))
        prog_c.send(S7_Job_write_var)
        prog_c.recv(len(S7_Ack_write_var))

        prog_c.send(S7_Job_req_download)
        prog_c.recv(len(S7_Ack_req_download))
        for i in range(loop_count):
            prog_c.recv(len(S7_Job_download))
            prog_c.send(S7_Ack_download[i])
        prog_c.recv(len(S7_Job_download_ended))
        prog_c.send(S7_Ack_download_ended)
        prog_c.send(S7_Job_start_upload)
        prog_c.recv(len(S7_Ack_start_upload))
        for item in S7_Ack_upload:
            prog_c.send(S7_Job_upload)
            prog_c.recv(len(item))
        prog_c.send(S7_Job_end_upload)
        prog_c.recv(len(S7_Ack_end_upload))
        prog_c.send(S7_Job_PI_Service)
        prog_c.recv(len(S7_Ack_PI_Service))
        prog_c.send(S7_Job_Stop)
        prog_c.recv(len(S7_Ack_Stop))



        

        prog_s = ASTFProgram()
        prog_s.accept()
        prog_s.recv(len(S7_connect_request))
        prog_s.send(S7_connect_confirm)
        prog_s.recv(len(S7_Job_setup_communication))
        prog_s.send(S7_Ack_setup_communication)
        prog_s.recv(len(S7_Job_read_var))
        prog_s.send(S7_Ack_read_var)
        prog_s.recv(len(S7_Job_write_var))
        prog_s.send(S7_Ack_write_var)

        prog_s.delay(1000)
        prog_s.recv(len(S7_Job_req_download))
        prog_s.send(S7_Ack_req_download)
        for i in range(loop_count):
            prog_s.send(S7_Job_download)
            prog_s.recv(len(S7_Ack_download[i]))
        prog_s.send(S7_Job_download_ended)
        prog_s.recv(len(S7_Ack_download_ended))
        prog_s.recv(len(S7_Job_start_upload))
        prog_s.send(S7_Ack_start_upload)
        for item in S7_Ack_upload:
            prog_s.recv(len(S7_Job_upload))
            prog_s.send(item)
        prog_s.recv(len(S7_Job_end_upload))
        prog_s.send(S7_Ack_end_upload)
        prog_s.recv(len(S7_Job_PI_Service))
        prog_s.send(S7_Ack_PI_Service)
        prog_s.recv(len(S7_Job_Stop))
        prog_s.send(S7_Ack_Stop)

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
        
        parser.add_argument('--config', type=str, default='config_Everything.json', help='path of config file')
        args = parser.parse_args(tunables)
        
        config = load_config(args.config)
        return self.create_profile(config)


def register():
    return Prof1()