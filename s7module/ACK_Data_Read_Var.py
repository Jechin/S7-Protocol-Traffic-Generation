'''
Description: 生成S7comm Job Read Var数据包
Autor: Jechin
'''

import sys, os
from enum import Enum
import random

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from S7common import *

class Return_Code(Enum):
    Success = 0xff
    Hardware_error = 0x01
    Accessing_the_object_not_allowed = 0x03
    Invalid_address = 0x05
    Data_type_not_supported = 0x06
    Data_type_inconsistent = 0x07
    Object_does_not_exist  = 0x0a

class ACK_Data_Read_Var:
    def __init__(self, s7_obj) -> None:
        self.function = JobFunction.READ_VAR
        self.reserved = 0x00
        self.s7_obj = s7_obj

    def generate_byte(self, item_count=1, items_list=[]):
        """生成S7comm ACK Data Read Var数据包

        Args:
            item_count (int, optional): Defaults to 1. 读取的数据块数量
            items_list (list, optional): Defaults to []. 读取的数据块列表,当items_list不为空时,item_count无效,当items_list为空时,item_count有效,根据item_count随机生成items. list中的每个item为一个字典,包含code,transport_size,data_length,data

        Returns:
            s7comm_ack_data_read_var (bytes): S7comm ACK Data Read Var数据包
        """
        items_byte = b''
        if len(items_list) == 0:
            # 根据item_count随机生成items
            if item_count == 0:
                item_count = 1
            for i in range(item_count):
                if item_count > 1 and i == 0:
                    code = Return_Code.Success
                else:
                    code = random.choice(list(Return_Code))
                if code is Return_Code.Success:
                    # TODO 可以根据transport size在进行细分
                    transport_size = 0x04 # BYTE/WORD/DWORD
                    data_length = 0x01
                    data = 0x11
                    items_byte += code.value.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + data_length.to_bytes(2, byteorder='big') + data.to_bytes(data_length, byteorder='big')
                    if data_length % 2 == 1 and i != item_count - 1:
                        # fill data
                        items_byte += b'\x00'
                else:
                    transport_size = 0x00
                    data_length = 0x00
                    items_byte += code.value.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + data_length.to_bytes(2, byteorder='big')
        else:
            item_count = len(items_list)
            items_byte = b''
            for item in items_list:
                code = item['code']
                transport_size = item['transport_size']
                data_length = item['data_length']
                data = item['data']
                fill_data = 0x00
                items_byte += code.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + data_length.to_bytes(2, byteorder='big') + data.to_bytes(data_length, byteorder='big')
                if item is not items_list[-1]:
                    items_byte += fill_data.to_bytes(data_length%2, byteorder='big')

        s7_param = self.function.value.to_bytes(1, byteorder='big') + item_count.to_bytes(1, byteorder='big')
        s7_data = items_byte

        protocol_ID = 0x32
        rosctr = 0x03 # ACK Data
        param_length = len(s7_param)
        data_length = len(s7_data)
        error_class = 0x00
        error_code = 0x00

        s7_header = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big') + error_class.to_bytes(1, byteorder='big') + error_code.to_bytes(1, byteorder='big')

        self.s7_obj.protocol_data_unit_reference += 1
        self.s7_obj.protocol_data_unit_reference %= 0x10000

        s7comm_ack_data_read_var = s7_header + s7_param + s7_data
        s7comm_ack_data_read_var = self.s7_obj.add_copt_header(data=s7comm_ack_data_read_var)
        s7comm_ack_data_read_var = self.s7_obj.add_tpkt_header(data=s7comm_ack_data_read_var)
        return s7comm_ack_data_read_var

'''transport_size
0     NULL

3     BIT bit access, len is in bits

4     BYTE/WORD/DWORD     byte/word/dword access, len is in bits

5     INTEGER    integer access, len is in bits

6     DINTEGER  integer access, len is in bytes

7     REAL    real access, len is in bytes

9     OCTET STRING octet string, len is in bytes
'''


# sample pcap: wincc_s300_setup-alarm-read-write.pcapng