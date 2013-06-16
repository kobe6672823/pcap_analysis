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
        
    def analyze(self):
        """a method to cal all the sessions' statistic data"""
        
        for session in self.session_container.sessions:
            self._cal_sp_delay(session)
            self._cal_upstream_traffic(session)
            self._cal_downstream_traffic(session)
            self._cal_distribution(session)
            
    def _cal_sp_delay(self, session):
        """a method to cal a session's sp_delay"""
        
        print repr(session.http_list)
        first_http = session.http_list[0]
        last_http = session.http_list[-1]
        #a http packet consists of one or more pcap packets, "lp_in_first_http" is a http packet's last pcap packet
        #TODO: a tiny bug: should find out the minimum pcap_num in the pcap_num_list, in stead of the last one
        lp_in_first_http = self.pcap_container.msg_list[first_http]["pcap_num_list"][-1]
        lp_in_last_http = self.pcap_container.msg_list[last_http]["pcap_num_list"][-1]
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
        cur = 1
        for session in self.session_container.sessions:
            sheet_name = "session_" + str(cur)
            cur += 1
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
        
        xl_file_name = "http_service_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
            '_http_service_stat.xls'
        wb.save(xl_file_name)
        
    def export_to_png(self):
        """a method to export statistics to bar chart"""

        cur = 1
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
            png_file_name = "http_service_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
                '_session_' + str(cur) + '_resource_distribution_traffic_stat.png'
            plt.savefig(png_file_name, dpi=75)
            cur += 1
        
        #number statistics
        cur = 1
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
            png_file_name = "http_service_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
                '_session_' + str(cur) + '_resource_distribution_number_stat.png'
            plt.savefig(png_file_name, dpi=75)
            cur += 1
    
    def _autolabel(self, plt, rects):
        """a method to label the height of the bar in the bar chart"""
        
        for rect in rects:
            height = int(rect.get_height())
            if (height > 0):
                plt.text(rect.get_x()+rect.get_width()/2., 1.03*height, '%s' % int(height))
