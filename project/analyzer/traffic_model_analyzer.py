#! /usr/bin/python
# -*- coding: utf-8 -*-

from parse.Pcap_packet_container import *
from session.session_container import *

import xlwt
import os
import matplotlib.pyplot as plt 

from parse.protocol import *

class Traffic_model_analyzer():
    """a class for cal traffic over tcp, session and protocols"""
    
    def __init__(self, pcap_container, session_container):
        self.pcap_container = pcap_container
        self.session_container = session_container
        
        self.tcp_conn_duration = {}
        self.tcp_conn_all_traffic = {}
        self.tcp_conn_effective_traffic = {}    #the network traffic over tcp layer(means the sum of tcp payload length)
        
        self.session_conn_duration = []
        self.session_conn_all_traffic = []
        self.session_conn_effective_traffic = []
        
        self.udp_all_traffic = 0
        self.tcp_all_traffic = 0
        self.app_layer_all_traffic = {
            "FTP" : 0,  #port:21
            "SSH" : 0,  #port:22
            "TELNET" : 0,   #port:23
            "SMTP" : 0, #port:25
            "HTTP" : 0, #port:80
            "DNS" : 0,  #port:53
            "known":0
        }

    def cal_tcp_conn_statistics(self):
        """a method to cal all tcp connection statistics"""
        
        for sockets in self.pcap_container.tcp_stream_container.keys():
            self._cal_tcp_conn_duration(sockets)
            self._cal_tcp_conn_traffic(sockets)
    
    def cal_session_conn_statistics(self):
        """a method to cal all sessions connections statistics"""
        
        for session in self.session_container.sessions:
            self._cal_session_conn_duration(session)
            self._cal_session_conn_traffic(session)
    
    def cal_protocol_statistics(self):
        """a method to cal:
           1, all traffic in transfer layer
           2, all traffic in application layer()"""
           
        for pcap_packet in self.pcap_container.pcap_packets:
            if (pcap_packet.top_layer < 2):
                continue
            
            #cal all traffic in transfer layer
            if (pcap_packet.ip.protocol == "TCP"):
                self.tcp_all_traffic += self.pcap_container.packet_headers[pcap_packet.pcap_num-1]["cap_len"]
            elif (pcap_packet.ip.protocol == "UDP"):
                self.udp_all_traffic += self.pcap_container.packet_headers[pcap_packet.pcap_num-1]["cap_len"]
            else:
                continue    #skip the packets that is not tcp or udp packets
                
            #cal all traffic in transfer layer
            message = pcap_packet.ip.packet[pcap_packet.ip.header_len: pcap_packet.ip.header_len+4]
            src_port = int(data_to_hex_str(message[0:2]), 16)
            dst_port = int(data_to_hex_str(message[2:4]), 16)
            transfer_layer_proto = self._get_transfer_proto(src_port, dst_port)
            self.app_layer_all_traffic[transfer_layer_proto] += self.pcap_container.packet_headers[pcap_packet.pcap_num-1]["cap_len"]
    
    def _get_transfer_proto(self, src_port, dst_port):
        """a method to get transfer layer protocol according to the src_port and the dst_port"""
        
        if (src_port == 21 or dst_port == 21):
            return "FTP"
        if (src_port == 22 or dst_port == 22):
            return "SSH"
        if (src_port == 23 or dst_port == 23):
            return "TELNET"
        if (src_port == 25 or dst_port == 25):
            return "SMTP"
        if (src_port == 80 or dst_port == 80):
            return "HTTP"
        if (src_port == 53 or dst_port == 53):
            return "DNS"
        return "known"
    
    def _cal_session_conn_duration(self, session):
        """a method to cal session connection duration"""
        
        min_pcap_num = min(session.pcap_packet_list)
        max_pcap_num = max(session.pcap_packet_list)
        self.session_conn_duration.append(self.pcap_container.packet_headers[max_pcap_num]['ts'] - 
            self.pcap_container.packet_headers[min_pcap_num]['ts'])
    
    def _cal_session_conn_traffic(self, session):
        """a method to cal session connection traffic of all sessions in self.session_container.sessions"""
        
        self.session_conn_all_traffic.append(0)
        self.session_conn_effective_traffic.append(0)
        for pcap_num in session.pcap_packet_list:
            self.session_conn_all_traffic[-1] += self.pcap_container.packet_headers[pcap_num]['cap_len']
            if (self.pcap_container.pcap_packets[pcap_num].tcp != None):
                self.session_conn_effective_traffic[-1] += (len(self.pcap_container.pcap_packets[pcap_num].tcp.message) - \
                    self.pcap_container.pcap_packets[pcap_num].tcp.header_len)
    
    def _cal_tcp_conn_duration(self, sockets):
        """a method to cal tcp connection duration of all tcp streams in pcap_container.tcp_stream_container"""
        
        tcp_stream = self.pcap_container.tcp_stream_container[sockets]
        min_pcap_num = min(tcp_stream.pcap_num_list)
        max_pcap_num = max(tcp_stream.pcap_num_list)
        if (max_pcap_num >= len(self.pcap_container.packet_headers)):
            max_pcap_num = len(self.pcap_container.packet_headers) - 1
        self.tcp_conn_duration[sockets] = self.pcap_container.packet_headers[max_pcap_num]['ts'] - \
            self.pcap_container.packet_headers[min_pcap_num]['ts']
                
    def _cal_tcp_conn_traffic(self, sockets):
        """a method to cal tcp connection traffic of all tcp streams in pcap_container.tcp_stream_container"""
        
        tcp_stream = self.pcap_container.tcp_stream_container[sockets]
        self.tcp_conn_all_traffic[sockets] = 0
        self.tcp_conn_effective_traffic[sockets] = 0
        for pcap_num in tcp_stream.pcap_num_list:
            if (pcap_num >= len(self.pcap_container.packet_headers)):
                continue
            self.tcp_conn_all_traffic[sockets] += self.pcap_container.packet_headers[pcap_num]['cap_len']
            if (self.pcap_container.pcap_packets[pcap_num].tcp != None):
                self.tcp_conn_effective_traffic[sockets] += (len(self.pcap_container.pcap_packets[pcap_num].tcp.message) - \
                    self.pcap_container.pcap_packets[pcap_num].tcp.header_len)

    def export_to_xls(self):
        """a method to export the data in the analyzer to the xls file"""
        
        if (not os.path.exists("traffic_model_analyzer")):
            os.mkdir("traffic_model_analyzer")
        
        #sheet: tcp connection statistics
        wb = xlwt.Workbook()
        ws = wb.add_sheet("tcp connection statistics")
        sockets = self.tcp_conn_duration.keys()
        ws.write(1, 0, "duration")
        ws.write(2, 0, "all traffic")
        ws.write(3, 0, "effective traffic")
        cur = 1
        for socket in sockets:
            ws.write(0, cur, repr(socket))
            ws.write(1, cur, self.tcp_conn_duration[socket])
            ws.write(2, cur, self.tcp_conn_all_traffic[socket])
            ws.write(3, cur, self.tcp_conn_effective_traffic[socket])
            cur += 1

        #sheet: session connection statistics
        ws = wb.add_sheet("session connection statistics")
        ws.write(1, 0, "duration")
        ws.write(2, 0, "all traffic")
        ws.write(3, 0, "effective traffic")
        cur = 0
        for duration in self.session_conn_duration:
            ws.write(0, cur+1, "session_" + str(cur))
            ws.write(1, cur+1, self.session_conn_duration[cur])
            ws.write(2, cur+1, self.session_conn_all_traffic[cur])
            ws.write(3, cur+1, self.session_conn_effective_traffic[cur])
            cur += 1

        #sheet: protocol classified statistics
        ws = wb.add_sheet("protocol classified statistics")
        ws.write(0, 0, "tcp all traffic")
        ws.write(0, 1, "udp all traffic")
        ws.write(1, 0, self.tcp_all_traffic)
        ws.write(1, 1, self.udp_all_traffic)
        app_layer_protos = self.app_layer_all_traffic.keys()
        cur = 0
        for proto in app_layer_protos:
            ws.write(2, cur, proto)
            ws.write(3, cur, self.app_layer_all_traffic[proto])
            cur += 1
        
        xl_file_name = "traffic_model_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
            '_traffic_model_stat.xls'
        wb.save(xl_file_name)
    
    def export_to_png(self):
        """a method to export protocol classified statistics to bar chart"""

        plt.figure() 
        plt.title("protocol classified statistics")
        plt.xlabel('application layer protocols')
        plt.ylabel('traffic(in bytes)')
        
        table_headers = self.app_layer_all_traffic.keys()
        plt.xticks(range(0, len(table_headers)), table_headers, rotation=30)
        eps = 1e-7
        bar_height = [self.app_layer_all_traffic[key] + eps for key in table_headers]
        rect = plt.bar(left = range(0, len(table_headers)), height = bar_height, width = 0.3,align="center")
        self._autolabel(plt, rect)
        plt.tight_layout()
        png_file_name = "traffic_model_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
            '_protocol_classified_stat.png'
        plt.savefig(png_file_name, dpi=75)
    
    def _autolabel(self, plt, rects):
        """a method to label the height of the bar in the bar chart"""
        
        for rect in rects:
            height = int(rect.get_height())
            if (height > 0):
                plt.text(rect.get_x()+rect.get_width()/2., 1.03*height, '%s' % int(height))

    
