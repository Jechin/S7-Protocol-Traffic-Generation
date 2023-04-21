'''
Description: S7comm protocol message class
Autor: Jechin
'''
import sys
import os

# sys.path.append('/home/jechin/s7/s7module')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from S7common import *
from Job_Setup_Communication import *
from ACK_Data_Setup_Communication import *
from Job_Read_Var import *
from ACK_Data_Read_Var import *
from Job_Write_Var import *
from ACK_Data_Write_Var import *
from Job_Download import *
from ACK_Data_Download import *
from Job_Upload import *
from ACK_Data_Upload import *
from Job_PI_Service import *
from ACK_Data_PI_Service import *
from Job_PLC_Stop import *
from ACK_Data_PLC_Stop import *

class S7:
    connect_request_source_reference = 0x0000
    connect_requset_destination_reference = 0x0000
    connect_confirm_source_reference = 0x0000
    connect_confirm_destination_reference = 0x0000
    protocol_data_unit_reference = 512
    reserved = 0x00

    def __init__(self):
        pass
    
    def __copt_connection_paramater(self, source_tsap=0x0100, destination_tsap=0x0102, tpdu_size=0x0a):
        """生成COTP连接数据包中参数字段部分

        Args:
            source_tsap (hexadecimal, optional): Defaults to 0x0100.
            destination_tsap (hexadecimal, optional): Defaults to 0x0102.
            tpdu_size (hexadecimal, optional): Defaults to 0x0a.

        Returns:
            connection_param: COTP连接数据包中参数字段部分
        """
        param1 = b'\xc1\x02' + source_tsap.to_bytes(2, byteorder='big')
        param2 = b'\xc2\x02' + destination_tsap.to_bytes(2, byteorder='big')
        param3 = b'\xc0\x01' + tpdu_size.to_bytes(1, byteorder='big')
        return param1 + param2 + param3

    def add_s7_header(self, param, data, rosctr):
        """添加S7头

        Args:
            param (bytes): 参数字段
            data (bytes): 数据字段
            rosctr (str): ROSCTR 选择['job', 'ack', 'ack_data', 'userdata']其中之一

        Returns:
            s7 (bytes): 添加S7头后的数据
        """
        protocol_ID = 0x32.to_bytes(1, byteorder='big')
        if rosctr == 'job':
            rosctr = 0x01.to_bytes(1, byteorder='big') # job
        elif rosctr == 'ack':
            rosctr = 0x02.to_bytes(1, byteorder='big') # ack
        elif rosctr == 'ack_data':
            rosctr = 0x03.to_bytes(1, byteorder='big')
        elif rosctr == 'userdata':
            rosctr = 0x07.to_bytes(1, byteorder='big')
        reversed = 0x0000.to_bytes(2, byteorder='big')
        protocol_data_unit_reference = self.protocol_data_unit_reference.to_bytes(2, byteorder='big')
        param_length = len(param).to_bytes(2, byteorder='big')
        data_length = len(data).to_bytes(2, byteorder='big')
        error_class = 0x00.to_bytes(1, byteorder='big')
        error_code = 0x00.to_bytes(1, byteorder='big')
        
        if rosctr == 0x01.to_bytes(1, byteorder='big'):
            s7 = protocol_ID + rosctr + reversed + protocol_data_unit_reference + param_length + data_length + param + data
        elif rosctr == 0x03.to_bytes(1, byteorder='big'):
            s7 = protocol_ID + rosctr + reversed + protocol_data_unit_reference + param_length + data_length + error_class + error_code + param + data

            self.protocol_data_unit_reference += 512
            self.protocol_data_unit_reference %= 0x10000
        
        return s7

    def add_copt_header(self, data, pdu_type=0xf0, tpdu_number=0x00, last_data_unit=True):
        """添加COTP头

        Args:
            data (bytes): 数据
            pdu_type (hexadecimal, optional): Defaults to DT Data 0xf0.
            tpdu_number (hexadecimal, optional): Defaults to 0x00.
            last_data_unit (bool, optional): Defaults to True.

        Returns:
            copt (bytes): 添加COTP头后的数据
        """
        cotp_length = 2

        # 1字节的opt，第一位为1表示最后一个数据单元，后七位为tpdu_number
        opt = 0x00
        if last_data_unit:
            opt = 0x80
        opt = opt + tpdu_number

        copt = cotp_length.to_bytes(1, byteorder='big') + pdu_type.to_bytes(1, byteorder='big') + opt.to_bytes(1, byteorder='big') + data
        return copt
    
    def add_tpkt_header(self, data, tpkt_version=0x03, tpkt_reserved=0x00):
        """添加TPKT头

        Args:
            data (bytes): 数据

        Returns:
            tpkt (bytes): 添加TPKT头后的数据
        """
        tpkt_length = len(data) + 4
        tpkt = tpkt_version.to_bytes(1, byteorder='big') + tpkt_reserved.to_bytes(1, byteorder='big') + tpkt_length.to_bytes(2, byteorder='big') + data
        return tpkt

    def Connect_Request(self, source_reference=0x0006, destination_reference=0x0000, source_tsap=0xc1, destination_tsap=0xc2, tpdu_size=0x0a):
        """生成COTP连接数据包

        Args:
            source_reference (hexadecimal, optional): Defaults to 0x0006.
            destination_reference (hexadecimal, optional): Defaults to 0x0000.
            source_tsap (hexadecimal, optional): Defaults to 0x0100.
            destination_tsap (hexadecimal, optional): Defaults to 0x0102.
            tpdu_size (hexadecimal, optional): Defaults to 0x0a. 2^10=1024.

        Returns:
            connect_request (bytes): COTP连接数据包
        """
        self.connect_request_source_reference = source_reference
        self.connect_requset_destination_reference = destination_reference

        pdu_type = 0xe0
        opt = 0x00
        parameter = self.__copt_connection_paramater(source_tsap, destination_tsap, tpdu_size)
        
        copt_cr = pdu_type.to_bytes(1, byteorder='big') + destination_reference.to_bytes(2, byteorder='big') + source_reference.to_bytes(2, byteorder='big') + opt.to_bytes(1, byteorder='big') + parameter
        cotp_length = len(copt_cr)
        copt_cr = cotp_length.to_bytes(1, byteorder='big') + copt_cr

        tpkt_version = 0x03
        tpkt_reserved = self.reserved
        tpkt_length = cotp_length + 5
        tpkt = tpkt_version.to_bytes(1, byteorder='big') + tpkt_reserved.to_bytes(1, byteorder='big') + tpkt_length.to_bytes(2, byteorder='big')

        connect_request = tpkt + copt_cr
        return connect_request

    def Connect_Confirm(self, source_reference=0x0003, destination_reference=0x0006, source_tsap=0xc1, destination_tsap=0xc2, tpdu_size=0x0a):
        """生成COTP连接确认数据包

        Args:
            source_reference (hexadecimal, optional): Defaults to 0x0003.
            source_tsap (hexadecimal, optional): Defaults to 0x0100.
            destination_tsap (hexadecimal, optional): Defaults to 0x0102.
            tpdu_size (hexadecimal, optional): Defaults to 0x0a. 2^10=1024.

        Returns:
            connect_confirm (bytes): COTP连接确认数据包
        """
        self.connect_confirm_source_reference = source_reference
        self.connect_confirm_destination_reference = destination_reference
        if self.connect_request_source_reference != destination_reference:
            colormsg(title_with_color="[Warning]", msg="connect_request.source_reference != connect_confirm.destination_reference", color="yellow")

        pdu_type = 0xd0
        opt = 0x00
        parameter = self.__copt_connection_paramater(source_tsap, destination_tsap, tpdu_size)
        
        copt_cc = pdu_type.to_bytes(1, byteorder='big') + destination_reference.to_bytes(2, byteorder='big') + source_reference.to_bytes(2, byteorder='big') + opt.to_bytes(1, byteorder='big') + parameter
        cotp_length = len(copt_cc)
        copt_cc = cotp_length.to_bytes(1, byteorder='big') + copt_cc

        tpkt_version = 0x03
        tpkt_reserved = self.reserved
        tpkt_length = cotp_length + 5
        tpkt = tpkt_version.to_bytes(1, byteorder='big') + tpkt_reserved.to_bytes(1, byteorder='big') + tpkt_length.to_bytes(2, byteorder='big')

        connect_confirm = tpkt + copt_cc
        return connect_confirm
    
    def CR_and_CC(self, source_reference=0x0006, destination_reference=0x0000, source_tsap=0xc1, destination_tsap=0xc2, tpdu_size=0x0a):
        """生成COTP连接请求和连接确认数据包

        Args:
            source_reference (hexadecimal, optional): Defaults to 0x0006.
            destination_reference (hexadecimal, optional): Defaults to 0x0000.
            source_tsap (hexadecimal, optional): Defaults to 0x0100.
            destination_tsap (hexadecimal, optional): Defaults to 0x0102.
            tpdu_size (hexadecimal, optional): Defaults to 0x0a. 2^10=1024.

        Returns:
            [connect_request, connect_confirm] (list): COTP连接请求和连接确认数据包
        """
        cr = self.Connect_Request(source_reference=source_reference, destination_reference=0x0000, source_tsap=source_tsap, destination_tsap=destination_tsap, tpdu_size=tpdu_size)
        cc = self.Connect_Confirm(source_reference=destination_reference, destination_reference=source_reference, source_tsap=destination_tsap, destination_tsap=source_tsap, tpdu_size=tpdu_size)
        return [cr, cc]
    
    def Job_Determine_Function(self, function: JobFunction, args=None):
        if function == JobFunction.SETUP_COMMUNICATION:
            return Job_Setup_Communication(self)
        elif function == JobFunction.READ_VAR:
            return Job_Read_Var(self)
        elif function == JobFunction.WRITE_VAR:
            return Job_Write_Var(self)
        elif function == JobFunction.DOWNLOAD_BLOCK:
            return Job_Download(self, args)
        elif function == JobFunction.UPLOAD:
            return Job_Upload(self, args)
        elif function == JobFunction.PI_SERVICE:
            return Job_PI_Service(self, args)
        elif function == JobFunction.PLC_STOP:
            return Job_PLC_Stop(self, args)
        else:
            return None

    def ACK_Data_Determine_Function(self, function: JobFunction, args=None):
        if function == JobFunction.SETUP_COMMUNICATION:
            return ACK_Data_Setup_Communication(self)
        elif function == JobFunction.READ_VAR:
            return ACK_Data_Read_Var(self)
        elif function == JobFunction.WRITE_VAR:
            return ACK_Data_Write_Var(self)
        elif function == JobFunction.DOWNLOAD_BLOCK:
            return ACK_Data_Download(self, args)
        elif function == JobFunction.UPLOAD:
            return ACK_Data_Upload(self, args)
        elif function == JobFunction.PI_SERVICE:
            return ACK_Data_PI_Service(self, args)
        elif function == JobFunction.PLC_STOP:
            return ACK_Data_PLC_Stop(self, args)
        else:
            return None