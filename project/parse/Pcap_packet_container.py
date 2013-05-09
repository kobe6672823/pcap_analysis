#! /usr/bin/python
# -*- coding: utf-8 -*-

from rd_pcap import *
from ethernet import *
from ip import *
from tcp import *
from Pcap_packet import *
from tcp_stream_container import *
from tcp_stream import *

class Pcap_packet_container():
    """a class to contain the packets in a pcap file"""
    
    def __init__(self, file_name):
        self.pcap_file_name = file_name
        #read in the pcap_file and get the info below
        #raw_packets: the packet reads from pcap file, it hasn't been parsed, it only hases the origin hex data
        #pcap_packets: a Pcap_packet obj, it contains the data that has been parsed into layers
        #tcp_stream_container: dispatch the tcp packets in the pcap file into tcp streams, and the packets in the tcp stream 
        #                      should be http packet(at least on port is 80)
        #msg_list: the http messages list, after tcp reassemble
        self.pcap_header, \
        self.packet_headers, \
        self.raw_packets = rd_pcap(self.pcap_file_name)
        self.pcap_packets = []
        self.tcp_stream_container = Tcp_stream_container()
        self.msg_list = []
        
        self._parse()
    #endof def
    
    def _parse(self):
        """parse the data in the pcap file, get the container"""
        
        number = 1
        for raw_packet in self.raw_packets:
            pcap_packet = Pcap_packet()
            self.pcap_packets.append(pcap_packet)
            pcap_packet.pcap_num = number
            number += 1
            pcap_packet.top_layer = 1
            pcap_packet.ethernet = Ethernet(raw_packet[0:14])
            
            #skip the packet that is not ip packet
            if (pcap_packet.ethernet.type != 'IP'):
                continue
                
            pcap_packet.top_layer = 2
            pcap_packet.ip = Ip(raw_packet[14:])
            
            #skip the packet that is not tcp message
            if (pcap_packet.ip.protocol != 'TCP'):
                continue
            
            pcap_packet.top_layer = 3
            pcap_packet.tcp = Tcp(pcap_packet.ip.packet[pcap_packet.ip.header_len: ])
            
            #dispatch the tcp into tcp streams
            self._add_pkt_into_tcp_stream(pcap_packet, number)
        #endof for
    #endof def
    
    def _add_pkt_into_tcp_stream(self, pcap_packet, num):
        """a method to add a pcap_packet into a tcp stream, if it does not belong to any existing tcp stream, 
        create a new one"""
        
        #filter the packets that is not http packet
        if (pcap_packet.tcp.src_port != 80 and pcap_packet.tcp.dst_port != 80):
            return
        
        if (pcap_packet.tcp.src_port == 80):
            server_addr = pcap_packet.ip.src
            client_addr = pcap_packet.ip.dst
            client_port = pcap_packet.tcp.dst_port
        else:
            server_addr = pcap_packet.ip.dst
            client_addr = pcap_packet.ip.src
            client_port = pcap_packet.tcp.src_port
        socket_tuple = (client_addr, client_port, server_addr, 80)
        if (socket_tuple not in self.tcp_stream_container):
            self.tcp_stream_container[socket_tuple] = Tcp_stream()
        self.tcp_stream_container[socket_tuple].pcap_num_list.append(num)
            

    def print_info(self):
        """a method to print all the packets in a container to the stander output"""
        
        i = 1
        for pcap_packet in self.pcap_packets:
            print '----------------frame: %d------------' % i
            i += 1
            pcap_packet.ethernet.print_info()
            
            #skip the packet that is not ip packet
            if (pcap_packet.ethernet.type != 'IP'):
                continue
                
            print '#################   packet in the frame  ################'
            pcap_packet.ip.print_info()
            
            #skp the packet that is not tcp message
            if (pcap_packet.ip.protocol != 'TCP'):
                continue
            
            print '@@@@@@@@@@@@@@@@@@@  tcp fields  @@@@@@@@@@@@@@@@@@@@'
            pcap_packet.tcp.print_info()
            
            print
        #endof for
