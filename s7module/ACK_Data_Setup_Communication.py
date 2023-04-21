'''
Description: 生成S7comm ACK Data Setup Communication数据包
Autor: Jechin
'''
import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from S7common import *

class ACK_Data_Setup_Communication:
    def __init__(self, s7_obj) -> None:
        self.function = JobFunction.SETUP_COMMUNICATION
        self.reserved = 0x00
        self.s7_obj = s7_obj

    def generate_byte(self, max_amq_calling=1, max_amq_called=1, pdu_size=480):
        """生成S7comm ACK Data Setup Communication数据包

        Args:
            max_amq_calling (int, optional): Defaults to 1. 最大调用AMQ
            max_amq_called (int, optional): Defaults to 1. 最大被调用AMQ
            pdu_size (int, optional): Defaults to 480. PDU大小
            error_class (int, optional): Defaults to 0x00. 错误类
            error_code (int, optional): Defaults to 0x00. 错误码

        Returns:
            s7comm_ack_data_setup_communication (bytes): S7comm ACK Data Setup Communication数据包
        """
        param = JobFunction.SETUP_COMMUNICATION.value.to_bytes(1, byteorder='big') + self.reserved.to_bytes(1, byteorder='big') + max_amq_calling.to_bytes(2, byteorder='big') + max_amq_called.to_bytes(2, byteorder='big') + pdu_size.to_bytes(2, byteorder='big')

        protocol_ID = 0x32
        rosctr = 0x03 # ack_data
        param_length = len(param)
        data_length = 0 # no data
        error_class=0x00
        error_code=0x00
        
        s7_header = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big') + error_class.to_bytes(1, byteorder='big') + error_code.to_bytes(1, byteorder='big')

        # 更新protocol_data_unit_reference， 每次+512
        self.s7_obj.protocol_data_unit_reference += 512
        self.s7_obj.protocol_data_unit_reference %= 0x10000

        s7comm_ack_data_setup_communication = s7_header + param
        s7comm_ack_data_setup_communication = self.s7_obj.add_copt_header(data=s7comm_ack_data_setup_communication)
        s7comm_ack_data_setup_communication = self.s7_obj.add_tpkt_header(data=s7comm_ack_data_setup_communication)
        return s7comm_ack_data_setup_communication