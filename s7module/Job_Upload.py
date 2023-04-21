'''
Description: 
Autor: Jechin
'''

import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from S7common import *

class Job_Upload:
    def __init__(self, s7_obj, config) -> None:
        self.reserved = 0x00
        self.s7_obj = s7_obj
        self.config = config

    def generate_start_upload(self):
        # parameter
        function = JobFunction.START_UPLOAD.value.to_bytes(1, byteorder='big') # 0x1d
        function_status = 0x00.to_bytes(1, byteorder='big') # more data following: False
        unknown_bytes = 0x0000.to_bytes(2, byteorder='big')
        uploadID = self.config["Start"]["uploadID"].to_bytes(4, byteorder='big')
        filename_length = self.config["Start"]["filename_length"].to_bytes(1, byteorder='big')
        filename = self.config["Start"]["filename"].encode()

        s7_param_bytes = function + function_status + unknown_bytes + uploadID + filename_length + filename

        s7_job_start_upload = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='job')
        s7_job_start_upload = self.s7_obj.add_copt_header(s7_job_start_upload)
        s7_job_start_upload = self.s7_obj.add_tpkt_header(s7_job_start_upload)

        return s7_job_start_upload
    
    def generate_upload(self):
        # parameter
        function = JobFunction.UPLOAD.value.to_bytes(1, byteorder='big') # 0x1e
        function_status = 0x00.to_bytes(1, byteorder='big') # more data following: False
        unknown_bytes = 0x0000.to_bytes(2, byteorder='big')
        uploadID = self.config["Start"]["uploadID"].to_bytes(4, byteorder='big')

        s7_param_bytes = function + function_status + unknown_bytes + uploadID

        s7_job_upload = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='job')
        s7_job_upload = self.s7_obj.add_copt_header(s7_job_upload)
        s7_job_upload = self.s7_obj.add_tpkt_header(s7_job_upload)

        return s7_job_upload

    def generate_end_upload(self):
        # parameter
        function = JobFunction.END_UPLOAD.value.to_bytes(1, byteorder='big') # 0x1f
        function_status = 0x00.to_bytes(1, byteorder='big') # more data following: False
        errorcode = 0x0000.to_bytes(2, byteorder='big')
        uploadID = self.config["Start"]["uploadID"].to_bytes(4, byteorder='big')

        s7_param_bytes = function + function_status + errorcode + uploadID

        s7_job_end_upload = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='job')
        s7_job_end_upload = self.s7_obj.add_copt_header(s7_job_end_upload)
        s7_job_end_upload = self.s7_obj.add_tpkt_header(s7_job_end_upload)

        return s7_job_end_upload