#! /usr/bin/python
# -*- coding: utf-8 -*-

from rd_pcap import *
from ethernet import *
from ip import *
from tcp import *
from Pcap_packet import *
from tcp_stream_container import *
from tcp_stream import *
from message import *

#global var for tcp reassemble
_tcp_buf = None

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
        
        global _tcp_buf
        _tcp_buf = {}
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
            
            #skip the packets that is not http packet
            if (pcap_packet.tcp.src_port != 80 and pcap_packet.tcp.dst_port != 80):
                continue
            
            #dispatch the tcp into tcp streams
            self._add_pkt_into_tcp_stream(pcap_packet, pcap_packet.pcap_num)
            
            #reassemble tcp packet
            self._tcp_reassemble(pcap_packet.pcap_num, pcap_packet.ip.src, pcap_packet.ip.dst, pcap_packet.tcp)
        #endof for
    #endof def
    
    def _add_pkt_into_tcp_stream(self, pcap_packet, num):
        """a method to add a pcap_packet into a tcp stream, if it does not belong to any existing tcp stream, 
        create a new one"""
        
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

    def _tcp_reassemble(self, number, src_addr, dst_addr, tcp):
        """a method to reassemble tcp packet, and append the message after reassemble to the msg_list"""
        
        pld = tcp.message[tcp.header_len : ]
        src_socket  = (src_addr, tcp.src_port)
        dst_socket  = (dst_addr, tcp.dst_port)
        sockets     = (src_socket, dst_socket)
        
        if pld:
            if not sockets in _tcp_buf:
                _tcp_buf[sockets] = Message({
                    'pcap_num_list':    [],
                    'ts':               self.packet_headers[number]['ts'],
                    'ip_proto':         'TCP',
                    'src_addr':         src_addr,
                    'dst_addr':         dst_addr,
                    'src_port':         tcp.src_port,
                    'dst_port':         tcp.dst_port,
                    'seq':              tcp.sequence_num,
                    'ack':              tcp.ack_num,
                    'payload':          [],
                })
            _tcp_buf[sockets].pcap_num_list.append(number)
            offset = tcp.sequence_num - _tcp_buf[sockets].seq
            _tcp_buf[sockets].payload[offset:offset+len(pld)] = list(pld)
        
        #check the other side of the tcp connection, flush the complete pdu to the msg_list
        if sockets in _tcp_buf and tcp.ack_num != _tcp_buf[sockets].ack:    
            self._tcp_flush(sockets)
            del _tcp_buf[sockets]
        
    def _tcp_flush(self, sockets):
        """a method to flush the complete(after strict reassemble) pdus to the msg_list"""
        
        msg = _tcp_buf[sockets]
        msg['payload'] = ''.join(msg.payload)
        self.msg_list.append(msg)
        #TODO: need to store the msg_number into the tcp_stream????then the tcp_stream know what msgs it has
        
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
