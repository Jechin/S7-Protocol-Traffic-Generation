'''
Description: 
Autor: Jechin
'''
import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from S7common import *

class ACK_Data_Upload:
    def __init__(self, s7_obj, config: dict) -> None:
        self.reserved = 0x00
        self.s7_obj = s7_obj
        self.config = config

    def generate_start_upload(self) -> bytes:
        # parameter
        function = JobFunction.START_UPLOAD.value.to_bytes(1, byteorder='big') # 0x1e
        function_status = 0x00.to_bytes(1, byteorder='big') # more data following: False
        unknown_bytes = 0x0000.to_bytes(2, byteorder='big')
        uploadID = self.config["Start"]["uploadID"].to_bytes(4, byteorder='big')
        blocklengthstring_length = 0x07.to_bytes(1, byteorder='big')
        blocklength = "{:07}".format(self.config["Start"]["blocklength"]).encode()

        s7_param_bytes = function + function_status + unknown_bytes + uploadID + blocklengthstring_length + blocklength

        # total
        protocol_ID = 0x32.to_bytes(1, byteorder='big')
        rosctr = 0x03.to_bytes(1, byteorder='big') # ack_data
        reversed = 0x0000.to_bytes(2, byteorder='big')
        protocol_data_unit_reference = self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big')
        param_length = len(s7_param_bytes).to_bytes(2, byteorder='big')
        data_length = 0x00.to_bytes(2, byteorder='big') # no data
        error_class = 0x00.to_bytes(1, byteorder='big')
        error_code = 0x00.to_bytes(1, byteorder='big')

        s7_header_bytes = protocol_ID + rosctr + reversed + protocol_data_unit_reference + param_length + data_length + error_class + error_code

        self.s7_obj.protocol_data_unit_reference += 512
        self.s7_obj.protocol_data_unit_reference %= 0x10000

        s7_ack_data_upload = s7_header_bytes + s7_param_bytes
        s7_ack_data_upload = self.s7_obj.add_copt_header(s7_ack_data_upload)
        s7_ack_data_upload = self.s7_obj.add_tpkt_header(s7_ack_data_upload)

        return s7_ack_data_upload
    
    def generate_upload(self) -> list:
        upload_stream = []
        packet_count = len(self.config["Upload"])

        for i in range(packet_count):
            # parameter
            function = JobFunction.UPLOAD.value.to_bytes(1, byteorder='big')
            if i == packet_count - 1:
                function_status = 0x00.to_bytes(1, byteorder='big') # more data following: False
            else:
                function_status = 0x01.to_bytes(1, byteorder='big') # more data following: True
            
            s7_param_bytes = function + function_status

            # data
            length = self.config["Upload"][i]["length"].to_bytes(2, byteorder='big')
            unknown_bytes = 0x00fb.to_bytes(2, byteorder='big')
            data = self.config["Upload"][i]["data"].encode()

            s7_data_bytes = length + unknown_bytes + data

            # total
            protocol_ID = 0x32.to_bytes(1, byteorder='big')
            rosctr = 0x03.to_bytes(1, byteorder='big') # ack_data
            reversed = 0x0000.to_bytes(2, byteorder='big')
            protocol_data_unit_reference = self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big')
            param_length = len(s7_param_bytes).to_bytes(2, byteorder='big')
            data_length = len(s7_data_bytes).to_bytes(2, byteorder='big')
            error_class = 0x00.to_bytes(1, byteorder='big')
            error_code = 0x00.to_bytes(1, byteorder='big')

            s7_header_bytes = protocol_ID + rosctr + reversed + protocol_data_unit_reference + param_length + data_length + error_class + error_code

            self.s7_obj.protocol_data_unit_reference += 512
            self.s7_obj.protocol_data_unit_reference %= 0x10000

            s7_ack_data_upload = s7_header_bytes + s7_param_bytes + s7_data_bytes
            s7_ack_data_upload = self.s7_obj.add_copt_header(s7_ack_data_upload)
            s7_ack_data_upload = self.s7_obj.add_tpkt_header(s7_ack_data_upload)

            upload_stream.append(s7_ack_data_upload)

        return upload_stream 

            
    def generate_end_upload(self):
        # parameter
        param_bytes = JobFunction.END_UPLOAD.value.to_bytes(1, byteorder='big')

        s7_ack_data_end_upload = self.s7_obj.add_s7_header(param=param_bytes, data=b'', rosctr='ack_data')
        s7_ack_data_end_upload = self.s7_obj.add_copt_header(s7_ack_data_end_upload)
        s7_ack_data_end_upload = self.s7_obj.add_tpkt_header(s7_ack_data_end_upload)

        return s7_ack_data_end_upload