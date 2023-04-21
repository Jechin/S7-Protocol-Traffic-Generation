'''
Description: 
Autor: Jechin
'''

import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from S7common import *

class Job_PI_Service:
    def __init__(self, s7_obj, config) -> None:
        self.s7_obj = s7_obj
        self.config = config

    def generate_byte(self):
        # parameter
        function = JobFunction.PI_SERVICE.value.to_bytes(1, byteorder='big')
        function_status = 0x00fd.to_bytes(7, byteorder='big')
        if self.config["service"] != "_INSE": 
            block = self.config["param_block"].encode()
        else:
            number = self.config["param_block"]["number"].to_bytes(1, byteorder='big')
            unknown_byte = 0x00.to_bytes(1, byteorder='big')
            filename = self.config["param_block"]["filename"].encode()
            block = number + unknown_byte + filename
        block_length = len(block).to_bytes(2, byteorder='big')
        service_length = len(self.config["service"]).to_bytes(1, byteorder='big')
        service = self.config["service"].encode()

        s7_param = function + function_status + block_length + block + service_length + service

        s7_job_PI_service = self.s7_obj.add_s7_header(param=s7_param, data=b'', rosctr='job')
        s7_job_PI_service = self.s7_obj.add_copt_header(s7_job_PI_service)
        s7_job_PI_service = self.s7_obj.add_tpkt_header(s7_job_PI_service)

        return s7_job_PI_service
