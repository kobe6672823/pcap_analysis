#! /usr/bin/python 
# -*- coding: utf-8 -*-

from parse.Pcap_packet_container import *
from session.session_container import *

import xlwt
import os
import matplotlib.pyplot as plt 

class Http_service_analyzer():
    """a class for analyzing http service"""
    
    def __init__(self, session_container, pcap_container):
        self.session_container = session_container
        self.pcap_container = pcap_container
        #clear the statistics data in all sessions
        for session in self.session_container.sessions:
            session.clear_statistics()
        self.pipelining = {}    #for pipelining statistics, dist: sockets -->> [max, cnt]
        self.multipart = {} #for multipart concurrence statistics, dict: sockets -->> [max, cnt]
        self.session_tcp_concurrence = {}   #a dict for storing all sessions' tcp concurrence: session name -->> tcp concurrence
        
    def analyze(self):
        """a method to cal all the sessions' statistic data"""
        
        for session in self.session_container.sessions:
            self._cal_sp_delay(session)
            self._cal_upstream_traffic(session)
            self._cal_downstream_traffic(session)
            self._cal_distribution(session)
            self.__cal_session_tcp_concurrence(session)
        
        #pipelining statistics
        self.__cal_pipelining_concurrence()
        self.__cal_multipart_concurrence()
    
    def __is_a_syn_pkt(self, pkt):
        """a method to judge a pcap_packet is a syn packet or not"""
        
        if (pkt.top_layer < 3):
            return False
        if (pkt.tcp.src_port != 80 and pkt.tcp.flag_syn == 1 and pkt.tcp.flag_ack == 0):
            return True
        return False
    
    def __is_a_fin_pkt(self, pkt):
        """a method to judge a pcap_packet is a fin packet or not"""
        
        if (pkt.top_layer < 3):
            return False
        if (pkt.tcp.src_port != 80 and pkt.tcp.flag_fin == 1 and pkt.tcp.flag_ack == 1):
            return True
        return False
    
    def __cal_session_tcp_concurrence(self, session):
        """a method to cal all sessions' tcp concurrence"""
        
        cnt = 0
        max_concurrence = 0
        for pcap_pkt in session.pcap_packet_list:
            if (self.__is_a_syn_pkt(self.pcap_container.pcap_packets[pcap_pkt])):
                cnt += 1
            if (self.__is_a_fin_pkt(self.pcap_container.pcap_packets[pcap_pkt])):
                if (cnt > max_concurrence):
                    max_concurrence = cnt
                cnt -= 1
        try:
            host_name = self.pcap_container.http_list[session.http_list[0]].header_fields["host"]
        except:
            host_name = "unknown(no_host_field)"
        self.session_tcp_concurrence[host_name] = max_concurrence
        
    def __cal_pipelining_concurrence(self):
        """a method to cal pipelining concurrence"""
        
        pos = 0
        for http in self.pcap_container.http_list:
            if (http.http_type == HTTP_REQUEST):    #http request, pipeling Concurrence(cnt) += 1
                sockets = ((self.pcap_container.msg_list[pos]["src_addr"], self.pcap_container.msg_list[pos]["src_port"]), 
                           (self.pcap_container.msg_list[pos]["dst_addr"], self.pcap_container.msg_list[pos]["dst_port"]))
                if (not self.pipelining.has_key(sockets)):
                    self.pipelining[sockets] = [0, 0]
                self.pipelining[sockets][1] += 1
            else:
                sockets = ((self.pcap_container.msg_list[pos]["dst_addr"], self.pcap_container.msg_list[pos]["dst_port"]), 
                           (self.pcap_container.msg_list[pos]["src_addr"], self.pcap_container.msg_list[pos]["src_port"]))
                if (not self.pipelining.has_key(sockets)):
                    pos += 1
                    continue
                else:
                    if (self.pipelining[sockets][0] < self.pipelining[sockets][1]): # if the current pipeling Concurrence(cnt) > max, then max = pipeling Concurrence(cnt)
                        self.pipelining[sockets][0] = self.pipelining[sockets][1]
                    self.pipelining[sockets][1] = 0
            pos += 1
    
    #TODO: find a website that use multipart to uplaod file to test this method.....
    def __cal_multipart_concurrence(self):
        """a method to cal pipelining concurrence"""
        
        pos = 0
        for http in self.pcap_container.http_list:
            if (http.http_type == HTTP_REQUEST and http.header_fields.has_key("content-type")
                and http.header_fields["content-type"].find("multipart") != -1):    #http request and has content-type(means the client upload file to server)
                sockets = ((self.pcap_container.msg_list[pos]["src_addr"], self.pcap_container.msg_list[pos]["src_port"]), 
                           (self.pcap_container.msg_list[pos]["dst_addr"], self.pcap_container.msg_list[pos]["dst_port"]))
                if (not self.multipart.has_key(sockets)):
                    self.multipart[sockets] = [0, 0]
                self.multipart[sockets][1] += 1
            elif (http.http_type == HTTP_RESPONSE):
                sockets = ((self.pcap_container.msg_list[pos]["dst_addr"], self.pcap_container.msg_list[pos]["dst_port"]), 
                           (self.pcap_container.msg_list[pos]["src_addr"], self.pcap_container.msg_list[pos]["src_port"]))
                if (not self.multipart.has_key(sockets)):
                    pos += 1
                    continue
                else:
                    if (self.multipart[sockets][0] < self.multipart[sockets][1]): # if the current pipeling Concurrence(cnt) > max, then max = pipeling Concurrence(cnt)
                        self.multipart[sockets][0] = self.multipart[sockets][1]
                    self.multipart[sockets][1] = 0
            pos += 1
        
    def _cal_sp_delay(self, session):
        """a method to cal a session's sp_delay"""
        
        try:
            print "session %s http_list:" % self.pcap_container.http_list[session.http_list[0]].header_fields["host"]
        except:
            print "unknow host session: http_list:"
        print repr(session.http_list)
        first_http = session.http_list[0]
        last_http = session.http_list[-1]
        #a http packet consists of one or more pcap packets, "lp_in_first_http" is a http packet's last pcap packet
        lp_in_first_http = max(self.pcap_container.msg_list[first_http]["pcap_num_list"])
        lp_in_last_http = max(self.pcap_container.msg_list[last_http]["pcap_num_list"])
        begin = self.pcap_container.packet_headers[lp_in_first_http]["ts"]
        end = self.pcap_container.packet_headers[lp_in_last_http]["ts"]
        delay = end - begin
        session.sp_delay = delay
    
    def _cal_upstream_traffic(self, session):
        """a method to cal a session's upstream_traffic"""
        
        for http_pos in session.http_list:
            if (self.pcap_container.http_list[http_pos].http_type == 1):
                for num in self.pcap_container.msg_list[http_pos]["pcap_num_list"]:
                    session.upstream_traffic += self.pcap_container.packet_headers[num]["cap_len"]
    
    def _cal_downstream_traffic(self, session):
        """a method to cal a session's downstream_traffic"""
        
        for http_pos in session.http_list:
            if (self.pcap_container.http_list[http_pos].http_type == 2):
                for num in self.pcap_container.msg_list[http_pos]["pcap_num_list"]:
                    session.downstream_traffic += self.pcap_container.packet_headers[num]["cap_len"]
                    
    def _cal_distribution(self, session):
        """a method to cal a session's resource distribution"""
        
        for http_pos in session.http_list:
            if (self.pcap_container.http_list[http_pos].http_type == 2):
                http = self.pcap_container.http_list[http_pos]
                if (http.header_fields.has_key("content-type")):
                    content_type = str.lower(http.header_fields["content-type"])
                    #cal all content type's traffic and count
                    if (content_type.find("text") != -1):
                        session.resouce_distribution["text_count"] += 1
                        session.resouce_distribution["text_traffic"] += len(http.content)
                    elif (content_type.find("image") != -1):
                        session.resouce_distribution["image_count"] += 1
                        session.resouce_distribution["image_traffic"] += len(http.content)
                    elif (content_type.find("multipart") != -1):
                        session.resouce_distribution["multipart_count"] += 1
                        session.resouce_distribution["multipart_traffic"] += len(http.content)
                    elif (content_type.find("application") != -1):
                        session.resouce_distribution["application_count"] += 1
                        session.resouce_distribution["application_traffic"] += len(http.content)
                    elif (content_type.find("message") != -1):
                        session.resouce_distribution["message_count"] += 1
                        session.resouce_distribution["message_traffic"] += len(http.content)
                    elif (content_type.find("audio") != -1):
                        session.resouce_distribution["audio_count"] += 1
                        session.resouce_distribution["audio_traffic"] += len(http.content)
                    elif (content_type.find("video") != -1):
                        session.resouce_distribution["video_count"] += 1
                        session.resouce_distribution["video_traffic"] += len(http.content)
                    else:
                        session.resouce_distribution["unknown_count"] += 1
                        session.resouce_distribution["unknown_traffic"] += len(http.content)
                    #end of if

    def export_to_xls(self):
        """a method to export the data in the analyzer to the xls file"""
        
        if (not os.path.exists("http_service_analyzer")):
            os.mkdir("http_service_analyzer")
        
        wb = xlwt.Workbook()
        for session in self.session_container.sessions:
            host_name = self.pcap_container.http_list[session.http_list[0]].header_fields["host"]
            sheet_name = "session_" + host_name
            ws = wb.add_sheet(sheet_name)
            ws.write(0, 0, "sp_delay")
            ws.write(1, 0, session.sp_delay)
            ws.write(0, 1, "upstream_traffic")
            ws.write(1, 1, session.upstream_traffic)
            ws.write(0, 2, "downstream_traffic")
            ws.write(1, 2, session.downstream_traffic)
            ws.write(2, 0, "resouce_distribution")
            headers = session.resouce_distribution.keys()
            cur_col = 0
            for header in headers:
                ws.write(3, cur_col, header)
                ws.write(4, cur_col, session.resouce_distribution[header])
                cur_col += 1
        
        #export pipeling concurrence statistics
        ws = wb.add_sheet("pipeling concurrence")
        headers = self.pipelining.keys()
        cur = 0
        for header in headers:
            ws.write(0, cur, str(header))
            ws.write(1, cur, self.pipelining[header][0])
            cur += 1
        
        xl_file_name = "http_service_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
            '_http_service_stat.xls'
        wb.save(xl_file_name)
        
    def export_to_png(self):
        """a method to export statistics to bar chart"""

        #traffic statistics
        for session in self.session_container.sessions:
            plt.figure() 
            plt.title("resource distribution statistics(traffic)")
            plt.xlabel('content type')
            plt.ylabel('traffic(in bytes)')
            
            table_headers = ["text_traffic",
                "image_traffic", 
                "multipart_traffic", 
                "application_traffic", 
                "message_traffic", 
                "audio_traffic", 
                "video_traffic", 
                "unknown_traffic"]
            plt.xticks(range(0, len(table_headers)), table_headers, rotation=30)
            eps = 1e-7
            bar_height = [session.resouce_distribution[key] + eps for key in table_headers]
            rect = plt.bar(left = range(0, len(table_headers)), height = bar_height, width = 0.3,align="center")
            self._autolabel(plt, rect)
            plt.tight_layout()
            host_name = self.pcap_container.http_list[session.http_list[0]].header_fields["host"]
            png_file_name = "http_service_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
                '_session_' + host_name + '_resource_distribution_traffic_stat.png'
            plt.savefig(png_file_name, dpi=75)
        
        #number statistics
        for session in self.session_container.sessions:
            plt.figure() 
            plt.title("resource distribution statistics(number)")
            plt.xlabel('content type')
            plt.ylabel('number')
            
            table_headers = ["text_count",   
                "image_count", 
                "multipart_count", 
                "application_count", 
                "message_count", 
                "audio_count", 
                "video_count", 
                "unknown_count"]
            plt.xticks(range(0, len(table_headers)), table_headers, rotation=30)
            eps = 1e-7
            bar_height = [session.resouce_distribution[key] + eps for key in table_headers]
            rect = plt.bar(left = range(0, len(table_headers)), height = bar_height, width = 0.3,align="center")
            self._autolabel(plt, rect)
            plt.tight_layout()
            host_name = self.pcap_container.http_list[session.http_list[0]].header_fields["host"]
            png_file_name = "http_service_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
                '_session_' + host_name + '_resource_distribution_number_stat.png'
            plt.savefig(png_file_name, dpi=75)
    
    def _autolabel(self, plt, rects):
        """a method to label the height of the bar in the bar chart"""
        
        for rect in rects:
            height = int(rect.get_height())
            if (height > 0):
                plt.text(rect.get_x()+rect.get_width()/2., 1.03*height, '%s' % int(height))
