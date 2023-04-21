'''
Description: S7 common
Autor: Jechin
'''
import sys, os
from enum import Enum

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# from S7 import *

def colormsg(title_with_color: str,  msg: str, color: str = "", debug=True):
    """打印带颜色的信息

    Args:
        title_with_color (str): 带颜色的标题
        color (str): 颜色
        msg (str): 信息
    """
    out = ""
    if color == "red":
        out = f'\033[1;31;40m{title_with_color}\033[0m {msg}'
    elif color == "green":
        out = f'\033[1;32;40m{title_with_color}\033[0m {msg}'
    elif color == "yellow":
        out = f'\033[1;31;40m{title_with_color}\033[0m {msg}'
    else:
        out = f'{title_with_color} {msg}'
    if debug:
        print(f'[{__file__} {sys._getframe().f_lineno}] {out}')
    else:
        print(f'{out}')


class JobFunction(Enum):
    SETUP_COMMUNICATION = 0xf0
    READ_VAR = 0x04
    WRITE_VAR = 0x05
    CPU_SERVICE = 0x00
    REQ_DOWNLOAD = 0x1a
    DOWNLOAD_BLOCK = 0x1b
    DOWNLOAD_ENDBLOCK = 0x1c
    START_UPLOAD = 0x1d
    UPLOAD = 0x1e
    END_UPLOAD = 0x1f
    PI_SERVICE = 0x28
    PLC_STOP = 0x29

class Transport_Size_in_Data(Enum):
    NULL = 0x00
    BIT = 0x03
    BYTE = 0x04
    WORD = 0x04
    DWORD = 0x04
    INTEGER = 0x05
    DINTEGER = 0x06
    REAL = 0x07
    OCTET_STRING = 0x09

class Transport_Size_in_Param(Enum):
    BIT = 0x01
    BYTE = 0x02
    CHAR = 0x03
    WORD = 0x04
    INT = 0x05
    DWORD = 0x06
    DINT = 0x07
    REAL = 0x08
    TOD = 0x0a
    TIME = 0x0b
    S5TIME = 0x0c
    DATE_AND_TIME = 0x0f
    COUNTER = 0x1c
    TIMER = 0x1d
    IEC_TIMER = 0x1e
    IEC_COUNTER = 0x1f
    HS_COUNTER = 0x20