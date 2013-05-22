#! /usr/bin/python
# -*- coding: utf-8 -*-

from session import *

class Session_container():
    
    def __init__(self, pcap_container):
        self.pcap_container = pcap_container
        self.sessions = []
        
    def split_session(self):
        pass
