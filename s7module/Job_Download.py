'''
Description: 
Autor: Jechin
'''

import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from S7common import *

class Job_Download:
    def __init__(self, s7_obj, config: dict={}) -> None:
        self.reserved = 0x00
        self.s7_obj = s7_obj
        # self.copt = self.generate_copt_DT()
        self.config_parse(config)

    def config_parse(self, config: dict):
        if config == {} or config == None:
            # default
            self.filename_length = 0x09
            self.filename = "_0A00001P"
            self.download_data = [
                {
                    "data_length": 5,
                    "data": "aaaaa"
                }
            ]
            self.download_length = 5
        else:
            self.filename_length = config["request"]["filename_length"]
            self.filename = config["request"]["filename"]
            
            self.download_length = 0
            for item in config["download"]["download_data"]:
                self.download_length += item["data_length"]
            self.download_data = config["download"]["download_data"]
    
    # def generate_copt_DT(self):
    #     copt = b''
    #     copt = self.s7_obj.add_copt_header(copt, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=False)
    #     copt = self.s7_obj.add_tpkt_header(copt)
    #     return copt

    def generate_request_download(self):
        # parameter
        function = JobFunction.REQ_DOWNLOAD.value # 0x1a
        function_status = 0x00
        unknown_bytes = b'\x01\x00\x00\x00\x00\x00' # 6 bytes
        filename_length = self.filename_length
        filename = self.filename
        length_part2 = 0x0d # default 13
        unknown_char = '1'
        length_of_load_memory = "{:06}".format(self.download_length)
        length_of_MC7_code = '000400' # TODO unknown

        s7_param_bytes = function.to_bytes(1, byteorder='big') + function_status.to_bytes(1, byteorder='big') + unknown_bytes + filename_length.to_bytes(1, byteorder='big') + filename.encode() + length_part2.to_bytes(1, byteorder='big') + unknown_char.encode() + length_of_load_memory.encode() + length_of_MC7_code.encode()

        # total
        # protocol_ID = 0x32
        # rosctr = 0x01 # job
        # param_length = len(s7_param_bytes)
        # data_length = 0x00 # no data

        # s7_header_bytes = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big')

        s7comm_job_request_download = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='job')
        s7comm_job_request_download = self.s7_obj.add_copt_header(s7comm_job_request_download, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=True)
        s7comm_job_request_download = self.s7_obj.add_tpkt_header(s7comm_job_request_download)

        return s7comm_job_request_download
    
    def generate_download(self):
        # parameter
        function = JobFunction.DOWNLOAD_BLOCK.value.to_bytes(1, byteorder='big') # 0x1b
        function_status = 0x00.to_bytes(1, byteorder='big')
        unknown_bytes = b'\x01\x00\x00\x00\x00\x00' # 6 bytes
        filename_length = self.filename_length.to_bytes(1, byteorder='big')
        filename = self.filename.encode()
        s7_param_bytes = function + function_status + unknown_bytes + filename_length + filename

        # total
        # protocol_ID = 0x32
        # rosctr = 0x01 # job
        # param_length = len(s7_param_bytes)
        # data_length = 0x00 # no data

        # s7_header_bytes = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big')

        s7comm_job_download = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='job')
        s7comm_job_download = self.s7_obj.add_copt_header(s7comm_job_download, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=True)
        s7comm_job_download = self.s7_obj.add_tpkt_header(s7comm_job_download)
        
        return s7comm_job_download
    
    def generate_download_ended(self):
        # parameter
        function = JobFunction.DOWNLOAD_ENDBLOCK.value.to_bytes(1, byteorder='big') # 0x1b
        function_status = 0x00.to_bytes(1, byteorder='big')
        error_code = 0x0000.to_bytes(2, byteorder='big')
        unknown_bytes = 0x00000000.to_bytes(4, byteorder='big')
        filename_length = self.filename_length.to_bytes(1, byteorder='big')
        filename = self.filename.encode()

        s7_param_bytes = function + function_status + error_code + unknown_bytes + filename_length + filename

        # total
        # protocol_ID = 0x32.to_bytes(1, byteorder='big')
        # rosctr = 0x01.to_bytes(1, byteorder='big') # job
        # param_length = len(s7_param_bytes).to_bytes(2, byteorder='big')
        # data_length = 0x00.to_bytes(2, byteorder='big') # no data

        # s7_header_bytes = protocol_ID + rosctr + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length + data_length

        s7comm_job_download_ended = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='job')
        s7comm_job_download_ended = self.s7_obj.add_copt_header(s7comm_job_download_ended, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=True)
        s7comm_job_download_ended = self.s7_obj.add_tpkt_header(s7comm_job_download_ended)
        return s7comm_job_download_ended
    
    def generate_byte(self):
        pass