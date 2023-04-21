'''
Description: 
Autor: Jechin
'''

import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from S7common import *

class Job_PLC_Stop:
    def __init__(self, s7_obj, config) -> None:
        self.s7_obj = s7_obj
        self.config = config

    def generate_byte(self):
        # parameter
        function = JobFunction.PLC_STOP.value.to_bytes(1, byteorder='big')
        unknown_bytes = 0x0000000000.to_bytes(5, byteorder='big')
        length = len(self.config["service"]).to_bytes(1, byteorder='big')
        service = self.config["service"].encode()

        s7_param_bytes = function + unknown_bytes + length + service

        s7_job_plc_stop = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='job')
        s7_job_plc_stop = self.s7_obj.add_copt_header(s7_job_plc_stop)
        s7_job_plc_stop = self.s7_obj.add_tpkt_header(s7_job_plc_stop)

        return s7_job_plc_stop