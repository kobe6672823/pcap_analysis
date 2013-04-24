#! /usr/bin/python 
# -*- coding: utf-8 -*-

from protocol import *

class Tcp(Protocol):
    """a class for ip, derived from class Protocol(an empty class)"""

    def __init__(self, message_data):
        self.message = message_data #include the tcp header and the payload

        #look up the structure of the tcp protocol to get the details of fields below
        self.src_port = None
        self.dst_port = None
        self.sequence_num = None
        self.ack_num = None
        self.data_offset = None #it means the header_len, in bytes

        self.flag_urg = None
        self.flag_ack = None
        self.flag_psh = None
        self.flag_rst = None
        self.flag_syn = None
        self.flag_fin = None

        self.window_size = None
        self.checksum = None
        self.urgent_pointer = None
        self.opt_paddings = None

        self.decode()
    #endof def

    def decode(self):
        """a method to decode the info in the tcp message, and fill in the fields above"""

        self.src_port = int(data_to_hex_str(self.message[0:2]), 16)
        self.dst_port = int(data_to_hex_str(self.message[2:4]), 16)
        self.sequence_num = int(data_to_hex_str(self.message[4:8]), 16)
        self.ack_num = int(data_to_hex_str(self.message[8:12]), 16)
        self.data_offset = int(data_to_hex_str(self.message[12])[0:3], 16) * 4

        #parse the flags: bit operation
        flags = ord(self.message[13])
        if ((flags & (1 << 5)) != 0):
            self.flag_urg = 1
        else:
            self.flag_urg = 0

        if ((flags & (1 << 4)) != 0):
            self.flag_ack = 1
        else:
            self.flag_ack = 0

        if ((flags & (1 << 3)) != 0):
            self.flag_psh = 1
        else:
            self.flag_psh = 0

        if ((flags & (1 << 2)) != 0):
            self.flag_rst = 1
        else:
            self.flag_rst = 0

        if ((flags & (1 << 1)) != 0):
            self.flag_syn = 1
        else:
            self.flag_syn = 0

        if ((flags & 1) != 0):
            self.flag_fin = 1
        else:
            self.flag_fin = 0

        self.window_size = int(data_to_hex_str(self.message[14 : 16]), 16)
        self.checksum = data_to_hex_str(self.message[16 : 18])
        self.urgent_pointer = data_to_hex_str(self.message[18 : 20])

        header_len = self.data_offset
        if (header_len > 20):
            self.opt_paddings = data_to_hex_str(self.message[20 : header_len])
    #endof def

    def print_info(self):
        """a method to print the details of the fields in the tcp message"""

        print """src_port: %d\t dst_port: %d\t sequence_num: %d\t ack_num: %d
        data_offset: %d\t urg: %d\t ack: %d\t psh: %d\t rst: %d\t syn: %d\t fin: %d\t
        window_size: %d\t checksum: %s\t urgent_pointer: %s\t opt_paddings: %s""" % (
        self.src_port, self.dst_port, self.sequence_num,
        self.ack_num, self.data_offset, self.flag_urg, 
        self.flag_ack, self.flag_psh, self.flag_rst, 
        self.flag_syn, self.flag_fin, self.window_size, 
        self.checksum, self.urgent_pointer, self.opt_paddings)
