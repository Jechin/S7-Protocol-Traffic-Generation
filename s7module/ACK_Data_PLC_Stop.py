'''
Description: 
Autor: Jechin
'''

import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from S7common import *

class ACK_Data_PLC_Stop:
    def __init__(self, s7_obj, config) -> None:
        self.s7_obj = s7_obj
        self.config = config

    def generate_byte(self):
        # parameter
        s7_param_bytes = JobFunction.PLC_STOP.value.to_bytes(1, byteorder='big')

        s7_ack_data_plc_stop = self.s7_obj.add_s7_header(param=s7_param_bytes, data=b'', rosctr='ack_data')
        s7_ack_data_plc_stop = self.s7_obj.add_copt_header(s7_ack_data_plc_stop)
        s7_ack_data_plc_stop = self.s7_obj.add_tpkt_header(s7_ack_data_plc_stop)

        return s7_ack_data_plc_stop