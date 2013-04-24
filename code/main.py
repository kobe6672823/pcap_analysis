#! /usr/bin/python
# -*- coding: utf-8 -*-
#main

from rd_pcap import *
from ethernet import *
from ip import *
from tcp import *
def main():
    """the main funtion"""
    
    pcap_header, packet_headers, packets = rd_pcap('../baidu_on_phone.pcap')
    for i in range(len(packets)):
        print '----------------frame: %d------------' % (i + 1)
        frame_info = Ethernet(packets[i][0:14])
        frame_info.print_info()
        
        #skip the packet that is not ip packet
        if (frame_info.type != 'IP'):
            continue
            
        print '#################   packet in the frame  ################'
        packet_info = Ip(packets[i][14:])
        packet_info.print_info()
        
        #skp the packet that is not tcp message
        if (packet_info.protocol != 'TCP'):
            continue
        
        print '@@@@@@@@@@@@@@@@@@@  tcp fields  @@@@@@@@@@@@@@@@@@@@'
        message_info = Tcp(packet_info.packet[packet_info.header_len: ])
        message_info.print_info()
        
        print
    #endof for

main()
