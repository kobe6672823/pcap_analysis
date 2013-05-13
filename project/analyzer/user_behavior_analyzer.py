#! /usr/bin/python 
# -*- coding: utf-8 -*-

from parse.Pcap_packet_container import *

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
        
        for http in pcap_container.http_list:
            if (http and http.type == HTTP_REQUEST and http.header_fields.has_key("User-Agent")):
                user_agent = http.header_fields["User-Agent"]
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
