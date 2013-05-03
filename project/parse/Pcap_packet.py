#! /usr/bin/python
# -*- coding: utf-8 -*-

class Pcap_packet():
    """a class refers to the unit(packet) of the pcap file
    a unit(packet) contains: {ethernet(frame) data, ip(packet) data, tcp(message) data(if it reaches tcp layer)
    application layer data(if it reaches application layer)}"""
    
    def __init__(self):
        self.pcap_num = 0  #its sequential number in the pcap file
        self.top_layer = 0  #the toppest layer the pcap_packet reaches: 0(default), 1(ethernet), 2(ip), 3(tcp), 4(application)
        self.ethernet = None    #contain an ethernet obj
        self.ip = None  #contain an ip obj(if it has)
        self.tcp = None #contain a tcp obj(if it has)
        self.app = None #contain an app obj(if it has)
        
#TODO:to decrease the memory overhead
#in the Pcap_packet
#ethernet has its own data
#ip has its own data
#application layer has its own data
#and all these data have overlap section, it is a great awast of memory
