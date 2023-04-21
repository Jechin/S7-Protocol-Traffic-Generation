'''
Description: 
Autor: Jechin
'''

import os, sys
import random
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from S7common import *

class ACK_Data_Write_Var:
    return_error_code = [0x0110, 0x0111, 0x0112, 0x0113, 0x0114, 0x0115, 0x0116, 0x0117, 0x0118, 0x0119, 0x011a, 0x011b, 0x011c, 0x011d, 0x011e, 0x011f, 0x0140, 0x0141, 0x8001, 0x8003, 0x8100, 0x8104, 0x8204, 0x8205, 0x8301, 0x8302, 0x8304, 0x8305, 0x8306, 0x8307, 0x8401, 0x8402, 0x8404, 0x8405, 0x8500, 0x8503, 0x8701, 0x8702] # 不完整

    def __init__(self, s7_obj) -> None:
        self.function = JobFunction.WRITE_VAR
        self.reserved = 0x00
        self.s7_obj = s7_obj

    def generate_byte(self, item_count=1, result='success'):
        """生成S7comm Job Write Var数据包

        Args:
            item_count (int, optional): 返回的结果个数 . Defaults to 1.
            result (str, optional): 写入返回的结果. Defaults to 'success'. 当result为success时,所有item都返回成功,当result为error时,每个item返回一个随机的错误码

        Returns:
            s7comm_job_write_var (bytes): S7comm Job Write Var数据包
        """
        param_bytes = self.function.value.to_bytes(1, byteorder='big') + item_count.to_bytes(1, byteorder='big')
        data_bytes = b''
        if result == 'success':
            data_bytes += b'\xff' * item_count
        else:
            for i in range(item_count):
                data_bytes += random.choice(self.error_code).to_bytes(2, byteorder='big')
        
        protocol_ID = 0x32
        rosctr = 0x03 # ACK Data
        param_length = len(param_bytes)
        data_length = len(data_bytes)
        error_class=0x00
        error_code=0x00

        header_bytes = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big') + error_class.to_bytes(1, byteorder='big') + error_code.to_bytes(1, byteorder='big')

        self.s7_obj.protocol_data_unit_reference += 1
        self.s7_obj.protocol_data_unit_reference %= 0x10000

        s7comm_ack_data_write_val = header_bytes + param_bytes + data_bytes
        s7comm_ack_data_write_val = self.s7_obj.add_copt_header(data=s7comm_ack_data_write_val)
        s7comm_ack_data_write_val = self.s7_obj.add_tpkt_header(data=s7comm_ack_data_write_val)
        return s7comm_ack_data_write_val


