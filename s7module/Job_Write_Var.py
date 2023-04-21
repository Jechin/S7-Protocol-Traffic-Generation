'''
Description: 生成S7comm Job Write Var数据包
Autor: Jechin
'''
import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from S7common import *

class Job_Write_Var:
    def __init__(self, s7_obj) -> None:
        self.function = JobFunction.WRITE_VAR
        self.reserved = 0x00
        self.s7_obj = s7_obj

    def generate_byte(self, item_count=1, param_items=[], data_items=[]):
        """生成S7comm Job Write Var数据包

        Args:
            item_count (int, optional): Defaults to 1. 写入的数据块数量
            param_items (list, optional): Defaults to []. 写入的数据块参数列表, 
            data_items (list, optional): Defaults to []. 写入的数据块数据列表

        Returns:
            s7comm_job_write_var (bytes): S7comm Job Write Var数据包
        """
        if len(param_items) != 0:
            if len(param_items) != len(data_items):
                colormsg(title_with_color="[Warning]", msg="len(param_items) != len(data_items)", color="yellow")
                colormsg(title_with_color="[Warning]", msg=f"radom generate data_items with item_count={item_count}", color="yellow")
                return self.generate_byte(item_count=item_count)
            else:
                item_count = len(param_items)
                
                param_bytes = self.function.value.to_bytes(1, byteorder='big') + item_count.to_bytes(1, byteorder='big')
                variable_specification = 0x12
                length_of_following_address_specification= 0x0a
                syntax_id = 0x10 # S7ANY（0x10）定义了格式为Address data S7-Any pointer-like DBx.DBXx.x

                for item in param_items:
                    try:
                        transport_size = item['transport_size']
                        request_data_length = item['request_data_length']
                        db_number = item['db_number']
                        area = item['area']
                        address = item['address']
                    except Exception as e:
                        colormsg(title_with_color="[Warning]", msg=f"param_items error: {e}", color="yellow")
                        colormsg(title_with_color="[Warning]", msg=f"radom generate data_items with item_count={item_count}", color="yellow")
                        return self.generate_byte(item_count=item_count)
                    
                    item_bytes = variable_specification.to_bytes(1, byteorder='big') + length_of_following_address_specification.to_bytes(1, byteorder='big') + syntax_id.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + request_data_length.to_bytes(2, byteorder='big') + db_number.to_bytes(2, byteorder='big') + area.to_bytes(1, byteorder='big') + address.to_bytes(3, byteorder='big')
                    
                    param_bytes += item_bytes

                data_bytes = b''
                return_code = 0x00 # Reserved
                for item in data_items:
                    try:
                        transport_size = item['transport_size']
                        data_length = item['data_length']
                        data = item['data']
                        fill_data = 0x00
                    except Exception as e:
                        colormsg(title_with_color="[Warning]", msg=f"data_items error: {e}", color="yellow")
                        colormsg(title_with_color="[Warning]", msg=f"radom generate data_items with item_count={item_count}", color="yellow")
                        return self.generate_byte(item_count=item_count)
                    
                    if transport_size in [0x03, 0x04, 0x05]:
                        # 当transport_size为0x03, 0x04, 0x05时，data_length只能为0x01
                        data_length = 0x01
                    data_bytes += return_code.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + data_length.to_bytes(2, byteorder='big') + data.to_bytes(data_length, byteorder='big')
                    if item is not data_items[-1]:
                        data_bytes += fill_data.to_bytes(data_length%2, byteorder='big')

                protocol_ID = 0x32
                rosctr = 0x01 # job
                param_length = len(param_bytes)
                data_length = len(data_bytes)
                header_bytes = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big')

                s7comm_job_write_var = header_bytes + param_bytes + data_bytes
                s7comm_job_write_var = self.s7_obj.add_copt_header(data=s7comm_job_write_var, pdu_type=0xf0)
                s7comm_job_write_var = self.s7_obj.add_tpkt_header(data=s7comm_job_write_var)

                return s7comm_job_write_var
        else:
            # 根据item_count自动生成param_items和data_items
            if item_count == 0:
                item_count = 1
            
            param_bytes = self.function.value.to_bytes(1, byteorder='big') + item_count.to_bytes(1, byteorder='big')

            variable_specification = 0x12
            length_of_following_address_specification= 0x0a
            syntax_id = 0x10 # S7ANY（0x10）定义了格式为Address data S7-Any pointer-like DBx.DBXx.x
            transport_size = Transport_Size_in_Param.BIT.value # BIT (0x01) 1 bit
            request_data_length = 1 # 写入的数据长度
            db_number = 1 # DB块号
            area = 0x84 # DB
            address = 0x000008 # 前五位没用到，第六位到第二十一位是Byte地址，最后三位是Bit的地址
            item_bytes = variable_specification.to_bytes(1, byteorder='big') + length_of_following_address_specification.to_bytes(1, byteorder='big') + syntax_id.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + request_data_length.to_bytes(2, byteorder='big') + db_number.to_bytes(2, byteorder='big') + area.to_bytes(1, byteorder='big') + address.to_bytes(3, byteorder='big')

            param_bytes += item_bytes * item_count

            data_bytes = b''

            return_code = 0x00 # Reserved
            transport_size = Transport_Size_in_Data.BIT.value # BIT
            data_length = 1 # 写入的数据长度
            data = 0x01
            fill_data = 0x00
            data_bytes = return_code.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + data_length.to_bytes(2, byteorder='big') + data.to_bytes(data_length, byteorder='big') + fill_data.to_bytes(data_length%2 , byteorder='big')
            data_last_bytes = return_code.to_bytes(1, byteorder='big') + transport_size.to_bytes(1, byteorder='big') + data_length.to_bytes(2, byteorder='big') + data.to_bytes(data_length, byteorder='big')

            data_bytes = data_bytes * (item_count-1) + data_last_bytes

            protocol_ID = 0x32
            rosctr = 0x01 # job
            param_length = len(param_bytes)
            data_length = len(data_bytes)
            header_bytes = protocol_ID.to_bytes(1, byteorder='big') + rosctr.to_bytes(1, byteorder='big') + self.reserved.to_bytes(2, byteorder='big') + self.s7_obj.protocol_data_unit_reference.to_bytes(2, byteorder='big') + param_length.to_bytes(2, byteorder='big') + data_length.to_bytes(2, byteorder='big')

            s7comm_job_write_var = header_bytes + param_bytes + data_bytes
            s7comm_job_write_var = self.s7_obj.add_copt_header(data=s7comm_job_write_var, pdu_type=0xf0)
            s7comm_job_write_var = self.s7_obj.add_tpkt_header(data=s7comm_job_write_var)
            return s7comm_job_write_var


'''s7comm data部分中的transport_size
0 NULL

3  BIT  bit access, len is in bits, 此时对应data_length只能为1

4  BYTE/WORD/DWORD  byte/word/dword access, len is in bits, 此时对应data_length只能为1

5  INTEGER  integer access, len is in bits, 此时对应data_length只能为1

6  DINTEGER  integer access, len is in bytes

7  REAL  real access, len is in bytes

9  OCTET STRING  octet string, len is in bytes
'''