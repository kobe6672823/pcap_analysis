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
        
    def analyze(self):
        """a method to cal all the sessions' statistic data"""
        
        for session in self.session_container.sessions:
            self._cal_sp_delay(session)
            self._cal_upstream_traffic(session)
            self._cal_downstream_traffic(session)
            self._cal_distribution(session)
            
    def _cal_sp_delay(self, session):
        """a method to cal a session's sp_delay"""
        
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
