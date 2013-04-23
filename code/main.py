#! /usr/bin/python
# -*- coding: utf-8 -*-
#main

from rd_pcap import *
from ethernet import *

def main():
    """the main funtion"""
    
    pcap_header, packet_headers, packets = rd_pcap('../baidu_on_phone.pcap')
    for i in range(len(packets)):
        frame_info = Ethernet(packets[i][0:14])
        print "[%s\tdst:%s\tsrc:%s\ttype:%s]" % (frame_info.ether_type, frame_info.dst_addr, \
            frame_info.src_addr, frame_info.type)
    #endof for

main()
