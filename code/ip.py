#! /usr/bin/python 
# -*- coding: utf-8 -*-

from protocol import *

#the upper layer protocol over ip
IPPROTO = {0 : 'IP',
    1 : 'ICMP',
    2 : 'IGMP',
    3 : 'GGP',
    6 : 'TCP',
    8 : 'EGP',
    12 : 'PUP',
    17 : 'UDP',
    22 : 'IDP', 
    29 : 'TP', 
    80 : 'EON', 
    98 : 'ENCAP', 
    255 : 'RAW', 
    256 : 'MAX'
    }
#endof IPPROTO

class Ip(Protocol):
    "a class for ip, devired from Protocol(an empty class)"
    
    def __init__(self, packet_data):
        self.packet = packet_data   #include the ip header and the data in the ip packet
        
        #please look up the structure of the IPV4 Protocol to get the detail of the fields below
        self.version = None
        self.header_len = None
        self.type_of_service = None
        self.total_len = None
        self.id = None
        self.flags_reservedbit = None
        self.flags_dont_fragment = None
        self.flags_more_fragment = None
        self.fragment_offset = None
        self.TTL = None
        self.protocol = None
        self.header_checksum = None
        self.src = None
        self.dst = None
        self.opt_paddings = None
        
        self.decode()
        
    def decode(self):
        """a method to decode the infomation in the packet_data, and fill in the fields above"""
        
        self.version = int(data_to_hex_str(self.packet[0])[2])
        self.header_len = int(data_to_hex_str(self.packet[0])[3])
        self.type_of_service = data_to_hex_str(self.packet[1:2])
        self.total_len = int(data_to_hex_str(self.packet[2:4]), 16)
        self.id = data_to_hex_str(self.packet[4:6])
        
        #parse the flags fields(reservedbit, don't fragment, more fragment)
        if ((ord(self.packet[6]) & (1 << 7)) != 0):
            self.flags_reservedbit = 1
        else:
            self.flags_reservedbit = 0
        #endof if
        
        if ((ord(self.packet[6]) & (1 << 6)) != 0):
            self.flags_dont_fragment = 1
        else:
            self.flags_dont_fragment = 0
        #endof if
        
        if ((ord(self.packet[6]) & (1 << 5)) != 0):
            self.flags_more_fragment = 1
        else:
            self.flags_more_fragment = 0
        #endof if
        
        #parse the offset field(in packet[6:7]): 00011111 & packet[6] (to filter flags) -->> get packet[6:7] in hex_str
        #tmp = str(31 & ord(self.packet[6]))
        self.fragment_offset = int(data_to_hex_str(self.packet[6:8]), 16)
        if (self.fragment_offset >= (1 << 13)):
            #take away the flags fields:  00011111 11111111 & self.fragment_offset
            self.fragment_offset = self.fragment_offset & ((1 << 13) - 1)   
        
        self.TTL = ord(self.packet[8])
        self.protocol = IPPROTO[ord(self.packet[9])]
        self.header_checksum = data_to_hex_str(self.packet[10:12])
        
        self.src = str(ord(self.packet[12])) + '.' + str(ord(self.packet[13])) + '.' + \
            str(ord(self.packet[14])) + '.' + str(ord(self.packet[15]))
        self.dst = str(ord(self.packet[16])) + '.' + str(ord(self.packet[17])) + '.' + \
            str(ord(self.packet[18])) + '.' + str(ord(self.packet[19]))
            
        if (self.header_len > 5):
            self.opt_paddings = self.packet[20 : (self.header_len * 4)]
    #endof def
    
    def print_info(self):
        """a method to print info in the packet"""
        
        print """version: %d\t header_len: %d\t tos: %s\t total_len: %d
        id: %s\t flags_reservedbit: %d\t flags_dont_fragment: %d\t flags_more_fragment: %d
        fragment_offset: %d\t TTL: %d\t protocol: %s\t
        header_checksum: %s\t
        src: %s\t dst: %s
        opt_paddings: %s""" % (
        self.version, self.header_len, self.type_of_service, self.total_len, self.id, self.flags_reservedbit, 
        self.flags_dont_fragment, self.flags_more_fragment, 
        self.fragment_offset, self.TTL, self.protocol, self.header_checksum, self.src, self.dst, repr(self.opt_paddings))
    #endof def
