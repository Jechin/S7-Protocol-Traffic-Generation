'''
Description: 
Autor: Jechin
'''

import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from S7common import *

class ACK_Data_Download:
    def __init__(self, s7_obj, config: dict={}) -> None:
        self.reserved = 0x00
        self.s7_obj = s7_obj
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

    def generate_request_download(self):
        # parameter
        s7_param_bytes = JobFunction.REQ_DOWNLOAD.value.to_bytes(1, byteorder='big')
        protocol_ID = 0x32
        rosctr = 0x03 # ACK_Data
        param_length = len(s7_param_bytes)
        data_length = 0x00 # no data
        error_class = 0x00
        error_code = 0x00

        s7_header_bytes = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big') + error_class.to_bytes(1, byteorder='big') + error_code.to_bytes(1, byteorder='big')

        self.s7_obj.protocol_data_unit_reference += 512
        self.s7_obj.protocol_data_unit_reference %= 0x10000

        s7comm_ack_request_download = s7_header_bytes + s7_param_bytes
        s7comm_ack_request_download = self.s7_obj.add_copt_header(s7comm_ack_request_download, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=True)
        s7comm_ack_request_download = self.s7_obj.add_tpkt_header(s7comm_ack_request_download)

        return s7comm_ack_request_download
    
    def generate_download(self):
        return_stream = []
        for item in self.download_data:
            # parameter
            if self.download_data.index(item) != len(self.download_data) - 1:
                function_status = 0x01 # more data following
            else:
                function_status = 0x00
            s7_param_bytes = JobFunction.DOWNLOAD_BLOCK.value.to_bytes(1, byteorder='big') + function_status.to_bytes(1, byteorder='big')

            # data
            unknown_bytes = 0x00fb
            s7_data_bytes = item["data_length"].to_bytes(2, byteorder='big') + unknown_bytes.to_bytes(2, byteorder='big') + item["data"].encode()

            protocol_ID = 0x32
            rosctr = 0x03 # ACK_Data
            param_length = len(s7_param_bytes)
            data_length = len(s7_data_bytes)
            error_class = 0x00
            error_code = 0x00

            s7_header_bytes = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big') + error_class.to_bytes(1, byteorder='big') + error_code.to_bytes(1, byteorder='big')

            self.s7_obj.protocol_data_unit_reference += 512
            self.s7_obj.protocol_data_unit_reference %= 0x10000

            s7comm_ack_download = s7_header_bytes + s7_param_bytes + s7_data_bytes
            s7comm_ack_download = self.s7_obj.add_copt_header(s7comm_ack_download, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=True)
            s7comm_ack_download = self.s7_obj.add_tpkt_header(s7comm_ack_download)

            return_stream.append(s7comm_ack_download)

        return return_stream
    
    def generate_download_ended(self):
        # parameter
        s7_param_bytes = JobFunction.DOWNLOAD_ENDBLOCK.value.to_bytes(1, byteorder='big')

        protocol_ID = 0x32.to_bytes(1, byteorder='big')
        rosctr = 0x03.to_bytes(1, byteorder='big') # ACK_Data
        param_length = len(s7_param_bytes).to_bytes(2, byteorder='big')
        data_length = 0x0000.to_bytes(2, byteorder='big') # no data
        error_class = 0x00.to_bytes(1, byteorder='big')
        error_code = 0x00.to_bytes(1, byteorder='big')

        s7_header_bytes = protocol_ID + rosctr + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length + data_length + error_class + error_code

        self.s7_obj.protocol_data_unit_reference += 512
        self.s7_obj.protocol_data_unit_reference %= 0x10000

        s7comm_ack_download_ended = s7_header_bytes + s7_param_bytes
        s7comm_ack_download_ended = self.s7_obj.add_copt_header(s7comm_ack_download_ended, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=True)
        s7comm_ack_download_ended = self.s7_obj.add_tpkt_header(s7comm_ack_download_ended)

        return s7comm_ack_download_ended
