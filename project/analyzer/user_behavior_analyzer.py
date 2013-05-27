#! /usr/bin/python 
# -*- coding: utf-8 -*-

from parse.Pcap_packet_container import *

import xlwt
import os
import matplotlib.pyplot as plt 

class User_behavior_analyzer():
    """a class for analyzing user behavior"""
    
    def __init__(self):
        self.browser_statistics = {
            #browser for pc(or mobile phone)
            "MSIE":0, 
            "Firefox":0, 
            "Chrome":0, 
            "Safari":0, 
            "Opera":0, 
            "TheWorld":0, 
            "baidu":0, 
            "Maxthon":0, 
            "360":0, 
            "Tencent":0, 
            
            #browser only for mobile phone
            "GoBrowser":0, 
            "IEMobile":0, 
            "UCBrowser":0, 
            "MQQBrowser":0, 
            "unknown":0
            }
        self.platform_statistics = {
            "Android":0, 
            "Linux":0, 
            "NT":0, 
            "Mac":0, 
            "Unix":0, 
            "known":0
            #TODO more detail, eg: windows 7, windows vista, etc
        }
        
    def analyze(self, pcap_container):
        """a method to get browser statistic & platform statistic"""
        
        self._clear()
        
        for http in pcap_container.http_list:
            if (http and http.http_type != None and http.http_type == HTTP_REQUEST and http.header_fields.has_key("user-agent")):
                user_agent = http.header_fields["user-agent"]
                #browser statistic
                if (user_agent.find("MSIE") != -1):
                    self.browser_statistics["MSIE"] += 1
                elif (user_agent.find("Firefox") != -1):
                    self.browser_statistics["Firefox"] += 1
                elif (user_agent.find("Chrome") != -1):
                    self.browser_statistics["Chrome"] += 1
                elif (user_agent.find("Safari") != -1):
                    self.browser_statistics["Safari"] += 1
                elif (user_agent.find("Opera") != -1):
                    self.browser_statistics["Opera"] += 1
                elif (user_agent.find("TheWorld") != -1):
                    self.browser_statistics["TheWorld"] += 1
                elif (user_agent.find("baidu") != -1):
                    self.browser_statistics["baidu"] += 1
                elif (user_agent.find("Maxthon") != -1):
                    self.browser_statistics["Maxthon"] += 1
                elif (user_agent.find("360") != -1):
                    self.browser_statistics["360"] += 1
                elif (user_agent.find("Tencent") != -1):
                    self.browser_statistics["Tencent"] += 1
                elif (user_agent.find("GoBrowser") != -1):
                    self.browser_statistics["GoBrowser"] += 1
                elif (user_agent.find("IEMobile") != -1):
                    self.browser_statistics["IEMobile"] += 1
                elif (user_agent.find("UCBrowser") != -1):
                    self.browser_statistics["UCBrowser"] += 1
                elif (user_agent.find("MQQBrowser") != -1):
                    self.browser_statistics["MQQBrowser"] += 1
                else:
                    self.browser_statistics["unknown"] += 1
                
                #platform statistic
                if (user_agent.find("Android") != -1):
                    self.platform_statistics["Android"] += 1
                elif (user_agent.find("Linux") != -1):
                    self.platform_statistics["Linux"] += 1
                elif (user_agent.find("NT") != -1):
                    self.platform_statistics["NT"] += 1
                elif (user_agent.find("Mac") != -1):
                    self.platform_statistics["Mac"] += 1
                elif (user_agent.find("Unix") != -1):
                    self.platform_statistics["Unix"] += 1
                else:
                    self.platform_statistics["unknown"] += 1
                    
    def _clear(self):
        """a method to clear the analyzer"""
        
        for key in self.browser_statistics.keys():
            self.browser_statistics[key] = 0
        for key in self.platform_statistics.keys():
            self.platform_statistics[key] = 0
    
    def export_to_xls(self, pcap_file_name):
        """a method to export the data in the analyzer to the xls file"""
        
        if (not os.path.exists("user_behavior_analyzer")):
            os.mkdir("user_behavior_analyzer")
        
        wb = xlwt.Workbook()
        ws = wb.add_sheet('browser statistics')
        table_headers = self.browser_statistics.keys()
        cur_col = 0
        for key in table_headers:
            ws.write(0, cur_col, key)
            ws.write(1, cur_col, self.browser_statistics[key])
            cur_col += 1
        
        ws = wb.add_sheet('platform statistics')
        table_headers = self.platform_statistics.keys()
        cur_col = 0
        for key in table_headers:
            if (key == 'NT'):
                ws.write(0, cur_col, 'Windows')
            else:
                ws.write(0, cur_col, key)
            ws.write(1, cur_col, self.platform_statistics[key])
            cur_col += 1
        
        xl_file_name = "user_behavior_analyzer/" + "_".join(str(pcap_file_name.split("/")[-1]).split('.')) + \
            '_user_behavior_stat.xls'
        wb.save(xl_file_name)
    
    def export_to_png(self, pcap_file_name):
        """a method to export statistics to bar chart"""

        #browser statistics
        plt.title("browser type statistics")
        plt.xlabel('browser type')
        plt.ylabel('times')
        
        table_headers = self.browser_statistics.keys()
        plt.xticks(range(0, len(table_headers)), table_headers, rotation=30)
        eps = 1e-7
        bar_height = [self.browser_statistics[key] + eps for key in table_headers]
        rect = plt.bar(left = range(0, len(table_headers)), height = bar_height, width = 0.3,align="center")
        self._autolabel(plt, rect)
        plt.tight_layout()
        png_file_name = "user_behavior_analyzer/" + "_".join(str(pcap_file_name.split("/")[-1]).split('.')) + \
            '_browser_stat.png'
        plt.savefig(png_file_name, dpi=75)
        
        #platform_statistics
        plt.figure()    #necessary! otherwise two figure will mixed some args
        plt.title("platform statistics")
        plt.xlabel('platform')
        plt.ylabel('times')
        
        table_headers = self.platform_statistics.keys()
        plt.xticks(range(0, len(table_headers)), table_headers, rotation=30)
        eps = 1e-7
        bar_height = [self.platform_statistics[key] + eps for key in table_headers]
        rect = plt.bar(left = range(0, len(table_headers)), height = bar_height, width = 0.3,align="center")
        self._autolabel(plt, rect)
        plt.tight_layout()
        png_file_name = "user_behavior_analyzer/" + "_".join(str(pcap_file_name.split("/")[-1]).split('.')) + \
            '_platform_stat.png'
        plt.savefig(png_file_name, dpi=75)
        
    def _autolabel(self, plt, rects):
        """a method to label the height of the bar in the bar chart"""
        
        for rect in rects:
            height = int(rect.get_height())
            if (height > 0):
                plt.text(rect.get_x()+rect.get_width()/2., 1.03*height, '%s' % int(height))
