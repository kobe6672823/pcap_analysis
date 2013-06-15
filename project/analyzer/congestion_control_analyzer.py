#! /usr/bin/python 
# -*- coding: utf-8 -*-

from parse.Pcap_packet_container import *

import xlwt
import os
import matplotlib.pyplot as plt 

class Congestion_control_analyzer():
    """a class for analyzing congestion control"""
    
    def __init__(self, pcap_container):
        self.pcap_container = pcap_container
        self.avg_init_wnd_size = None
        self.avg_rtt = None
        self.seq_set = {}   #seq_set is a dict: sockets -> (sequence number,ack number)
        self.retransmission_prob = None
        self.retransmission_traffic = 0
        
    def analyze(self):
        """a method to cal all the congestion control statistic data"""
        
        self.__cal_avg_init_wnd_size()
        self.__cal_avg_rtt()
        self.__cal__retransmission_stat()

    def __cal_avg_init_wnd_size(self):
        """a method to cal average initial windows size"""
        
        wnd_size_sum = 0
        num = 0
        for pcap_packet in self.pcap_container.pcap_packets:
            if (pcap_packet.top_layer >= 3 and pcap_packet.tcp.flag_syn == 1):
                num += 1
                wnd_size_sum += pcap_packet.tcp.window_size
        self.avg_init_wnd_size = wnd_size_sum / num

    def __cal_avg_rtt(self):
        """a method to cal average round-trip time
        rtt = (syn_ack) - syn"""
        
        rtt_sum = 0
        num = 0
        pos = 0
        for pcap_packet in self.pcap_container.pcap_packets:
            if (pcap_packet.top_layer >= 3 and pcap_packet.tcp.flag_syn == 1 and pcap_packet.tcp.flag_ack == 0):
                start_time = self.pcap_container.packet_headers[pos]["ts"]
                end_time = self.__find_response_syn_ack_time(pos)
                if (end_time != -1):
                    num += 1
                    rtt_sum += (end_time - start_time)
            pos += 1
        self.avg_rtt = rtt_sum / num
    
    def __cal__retransmission_stat(self):
        """a method to cal retransmission probability and retransmission traffic"""
        
        tcp_pkt_num = 0
        retransmission_pkt_num = 0
        pos = 0
        for pcap_packet in self.pcap_container.pcap_packets:
            if (pcap_packet.top_layer >= 3):
                #sometimes the browser or the server will send many syn or fin packets, we skip such retransmission packets
                if (pcap_packet.tcp.flag_syn == 1 or pcap_packet.tcp.flag_fin == 1):
                    continue
                tcp_pkt_num += 1
                sockets = ((pcap_packet.ip.src, pcap_packet.tcp.src_port), (pcap_packet.ip.dst, pcap_packet.tcp.dst_port))
                if (self.seq_set.has_key(sockets)):
                    tmp_set = (pcap_packet.tcp.sequence_num, pcap_packet.tcp.ack_num)
                    if (tmp_set in self.seq_set[sockets]):
                        retransmission_pkt_num += 1
                        self.retransmission_traffic += self.pcap_container.packet_headers[pos]["cap_len"]
                    else:
                        self.seq_set[sockets].add(tmp_set)
                else:
                    self.seq_set[sockets] = set()
                    tmp_set = (pcap_packet.tcp.sequence_num, pcap_packet.tcp.ack_num)
                    self.seq_set[sockets].add(tmp_set)
            pos += 1
        self.retransmission_prob = float(retransmission_pkt_num) / float(tcp_pkt_num)
        
        
        
    def __find_response_syn_ack_time(self, pos):
        """a method to find the response of a syn tcp packet, if not exists, return -1"""
        
        cur = pos + 1
        start_packet = self.pcap_container.pcap_packets[pos]
        start_sockets = ((start_packet.ip.src, start_packet.tcp.src_port), (start_packet.ip.dst, start_packet.tcp.dst_port))
        while (cur < len(self.pcap_container.pcap_packets)):
            cur_packet = self.pcap_container.pcap_packets[cur]
            if (cur_packet.top_layer >= 3 and cur_packet.tcp.flag_syn == 1 and cur_packet.tcp.flag_ack == 1):
                cur_sockets = ((cur_packet.ip.src, cur_packet.tcp.src_port), (cur_packet.ip.dst, cur_packet.tcp.dst_port))
                if (start_sockets == cur_sockets[::-1]):
                    return self.pcap_container.packet_headers[cur]["ts"]
            cur += 1
        return -1
        
    def export_to_xls(self):
        """a method to export the data in the analyzer to the xls file"""
        
        if (not os.path.exists("congestion_control_analyzer")):
            os.mkdir("congestion_control_analyzer")
        
        wb = xlwt.Workbook()
        ws = wb.add_sheet("congestion control statistics")
        ws.write(0, 0, "avg_init_wnd_size")
        ws.write(1, 0, self.avg_init_wnd_size)
        ws.write(0, 1, "avg_rtt")
        ws.write(1, 1, self.avg_rtt)
        ws.write(0, 2, "retransmission_prob")
        ws.write(1, 2, self.retransmission_prob)
        ws.write(0, 3, "retransmission_traffic")
        ws.write(1, 3, self.retransmission_traffic)
        
        xl_file_name = "congestion_control_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
            '_congestion_control_stat.xls'
        wb.save(xl_file_name)
