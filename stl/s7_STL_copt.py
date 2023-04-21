'''
Usage: ./stl-sim -f ~/s7/stl/s7_STL_copt.py -o ~/s7/stl/pcap/s7_STL_copt.pcap -t config="config_copt.json"
'''
from trex_stl_lib.api import *
import argparse
import os, sys, json
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
from s7module.S7 import *

def load_config(config_file):
    if not os.path.isabs(config_file):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
    
    if not os.path.exists(config_file):
        colormsg(title_with_color="[Error]", msg="Config file not found: {}".format(config_file), color="red")
        colormsg(title_with_color="[Warn]", msg="Use default config file: config_copt.json", color="yellow")
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config_copt.json")
    
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except Exception as e:
        colormsg(title_with_color="[Error]", msg="Load config file failed: {}".format(e), color="red")
        sys.exit(1)

    check_config(config)
    return config

def check_config_connect(config_connect: dict):
    if "sip" not in config_connect.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: sip", color="red")
        sys.exit(1)
    if "dip" not in config_connect.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: dip", color="red")
        sys.exit(1)

def check_config(config: dict):
    if "Connect" not in config.keys():
        colormsg(title_with_color="[Error]", msg="Missing key: Connect", color="red")
        sys.exit(1)
    check_config_connect(config["Connect"])

# 1 clients MAC override the LSB of destination
class STLS1(object):

    def __init__ (self):
        self.fsize  =64; # the size of the packet 


    def create_stream (self, config):

        # Create base packet and pad it to size

        s7 = S7()
        [S7_connect_request, S7_connect_confirm] = s7.CR_and_CC()

        sip = config["Connect"]["sip"]
        dip = config["Connect"]["dip"]
        base_pkt1 = Ether()/IP(src=sip,dst=dip)/TCP(dport=102,sport=1025,flags = "S")
        base_pkt2 = Ether()/IP(src=dip,dst=sip)/TCP(dport=1025,sport=102,flags = "SA")
        base_pkt3 = Ether()/IP(src=sip,dst=dip)/TCP(dport=102,sport=1025,flags = "A")
        base_pkt4 = Ether()/IP(src=sip,dst=dip)/TCP(dport=102,sport=1025,flags = "PA")/S7_connect_request
        base_pkt5 = Ether()/IP(src=dip,dst=sip)/TCP(dport=1025,sport=102,flags = "A")
        base_pkt6 = Ether()/IP(src=dip,dst=sip)/TCP(dport=1025,sport=102,flags = "PA")/S7_connect_confirm
        base_pkt7 = Ether()/IP(src=sip,dst=dip)/TCP(dport=102,sport=1025,flags = "A")
        base_pkt8 = Ether()/IP(src=sip,dst=dip)/TCP(dport=102,sport=1025,flags = "R")



        return STLProfile( [ STLStream( isg = 10.0, # start in delay 
                                        name    ='S0',
                                        packet = STLPktBuilder(pkt = base_pkt1, vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                        mode = STLTXSingleBurst( pps = 10, total_pkts = 1),
                                        next = 'S1'), # point to next stream 

                             STLStream( self_start = False, # Stream is disabled. Will run because it is pointed from S0
                                        isg = 10.0,
                                        name    ='S1',
                                        packet  = STLPktBuilder(pkt = base_pkt2,vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                        mode    = STLTXSingleBurst( pps = 10, total_pkts = 1),
                                        next    = 'S2' ),
                             STLStream( self_start = False, # Stream is disabled. Will run because it is pointed from S0
                                        isg = 10.0,
                                        name    ='S2',
                                        packet  = STLPktBuilder(pkt = base_pkt3,vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                        mode    = STLTXSingleBurst( pps = 10, total_pkts = 1),
                                        next    = 'S3' ),
                             STLStream( self_start = False, # Stream is disabled. Will run because it is pointed from S0    
                                        isg = 10.0,
                                        name    ='S3',
                                        packet  = STLPktBuilder(pkt = base_pkt4,vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                        mode    = STLTXSingleBurst( pps = 10, total_pkts = 1),
                                        next    = 'S4' ),
                             STLStream( self_start = False, # Stream is disabled. Will run because it is pointed from S0
                                        isg = 10.0,
                                        name    ='S4',
                                        packet  = STLPktBuilder(pkt = base_pkt5,vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                        mode    = STLTXSingleBurst( pps = 10, total_pkts = 1),
                                        next    = 'S5' ),
                             STLStream( self_start = False, # Stream is disabled. Will run because it is pointed from S0
                                        isg = 10.0,
                                        name    ='S5',
                                        packet  = STLPktBuilder(pkt = base_pkt6,vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                        mode    = STLTXSingleBurst( pps = 10, total_pkts = 1),
                                        next    = 'S6' ),
                             STLStream( self_start = False, # Stream is disabled. Will run because it is pointed from S0
                                        isg = 10.0,
                                        name    ='S6',
                                        packet  = STLPktBuilder(pkt = base_pkt7,vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                        mode    = STLTXSingleBurst( pps = 10, total_pkts = 1),
                                        next    = 'S7' ),
                             STLStream(  self_start = False, # Stream is disabled. Will run because it is pointed from S1
                                         isg = 10.0, 
                                         name   ='S7',
                                         packet = STLPktBuilder(pkt = base_pkt8,vm = STLScVmRaw( [STLVmFixIpv4(offset = "IP")])),
                                         mode = STLTXSingleBurst( pps = 10, total_pkts = 1 ),
                                         action_count = 1, # loop 2 times 
                                         next    = 'S0' # back to S0 loop
                                        )
                            ]).get_streams()


    def get_streams (self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        parser.add_argument('--config', type=str, default="config_copt.json", help='path of config file')

        args = parser.parse_args(tunables)
        
        config = load_config(args.config)

        # create 1 stream 
        return self.create_stream(config) 


# dynamic load - used for trex console or simulator
def register():
    return STLS1()




