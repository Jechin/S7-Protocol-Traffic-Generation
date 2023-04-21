'''
Description: 生成S7comm ACK Data Setup Communication数据包
Autor: Jechin
'''
import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from S7common import *

class Job_Read_Var:
    def __init__(self, s7_obj) -> None:
        self.function = JobFunction.READ_VAR
        self.reserved = 0x00
        self.s7_obj = s7_obj

    def generate_byte(self, item_count=1, items_list=[]):
        """生成S7comm Job Read Var数据包

        Args:
            item_count (int, optional): Read Var 读取的item个数. Defaults to 1.
            items_list (list, optional): Defaults to []. 读取的数据块列表,当items_list不为空时,item_count无效,当items_list为空时,item_count有效,根据item_count随机生成items. list中的每个item为一个字典,包含code,transport_size,data_length,data

        Returns:
            s7comm_job_read_var (byte): S7comm Job Read Var数据包
        """
        items_byte = b''
        if len(items_list) == 0:
            # 根据item_count自动生成items
            variable_specification = 0x12
            length_of_following_address_specification= 0x0a
            syntax_id = 0x10 # S7ANY（0x10）定义了格式为Address data S7-Any pointer-like DBx.DBXx.x
            transport_size = 0x02 # BYTE 2字节
            request_data_length = 1 # 读取的数据长度
            db_number = 1 # DB块号
            area = 0x84 # DB
            address = 0x000000 # 前五位没用到，第六位到第二十一位是Byte地址，最后三位是Bit的地址

            item = variable_specification.to_bytes(1, byteorder='big') + length_of_following_address_specification.to_bytes(1, byteorder='big') + syntax_id.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + request_data_length.to_bytes(2, byteorder='big') + db_number.to_bytes(2, byteorder='big') + area.to_bytes(1, byteorder='big') + address.to_bytes(3, byteorder='big')

            if item_count == 0:
                item_count = 1
            items_byte = item * item_count
        elif len(items_list) != 0:
            variable_specification = 0x12
            length_of_following_address_specification= 0x0a
            syntax_id = 0x10 # S7ANY（0x10）定义了格式为Address data S7-Any pointer-like DBx.DBXx.x
            item_count = len(items_list)
            for item in items_list:
                try:
                    transport_size = item['transport_size']
                    request_data_length = item['request_data_length']
                    db_number = item['db_number']
                    area = item['area']
                    address = item['address']
                except:
                    colormsg(title_with_color='[ERROR]', msg_with_color='Job_Read_Var.generate_byte() items_list error', color='red')
                    colormsg(title_with_color='[Warning]', msg_with_color='random generate items', color='yellow')
                    return self.generate_byte(item_count=item_count)
                
                item = variable_specification.to_bytes(1, byteorder='big') + length_of_following_address_specification.to_bytes(1, byteorder='big') + syntax_id.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + request_data_length.to_bytes(2, byteorder='big') + db_number.to_bytes(2, byteorder='big') + area.to_bytes(1, byteorder='big') + address.to_bytes(3, byteorder='big')

                items_byte += item
        
        s7_param = self.function.value.to_bytes(1, byteorder='big') + item_count.to_bytes(1, byteorder='big') + items_byte

        protocol_ID = 0x32
        rosctr = 0x01 # job
        param_length = len(s7_param)
        data_length = 0x00 # no data

        s7_header = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big')

        s7comm_job_read_var = s7_header + s7_param
        s7comm_job_read_var = self.s7_obj.add_copt_header(data=s7comm_job_read_var, pdu_type=0xf0)
        s7comm_job_read_var = self.s7_obj.add_tpkt_header(data=s7comm_job_read_var)

        return s7comm_job_read_var


"""syntax_id
0x10        S7ANY  Address data S7-Any pointer-like DB1.DBX10.2

0x13        PBC-R_ID    R_ID for PBC

0x15        ALARM_LOCKFREE Alarm lock/free dataset

0x16        ALARM_IND      Alarm indication dataset

0x19        ALARM_ACK     Alarm acknowledge message dataset

0x1a        ALARM_QUERYREQ      Alarm query request dataset

0x1c        NOTIFY_IND      Notify indication dataset

0xa2        DRIVEESANY    seen on Drive ES Starter with routing over S7

0xb2        1200SYM      Symbolic address mode of S7-1200

0xb0        DBREAD      Kind of DB block read, seen only at an S7-400

0x82        NCK      Sinumerik NCK HMI access

"""