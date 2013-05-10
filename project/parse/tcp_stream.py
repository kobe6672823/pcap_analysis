#! /usr/bin/python 
# -*- coding: utf-8 -*-

class Tcp_stream():
    """a tcp stream include: tcp connection stablishment, http request, http response, tcp connection finish"""
    
    def __init__(self):
        #every stream has 2 attr: pcap_num_list, msg_num_list
        #pcap_num_list: the current stream has these packets(number in the pcap_packet_container)
        #msg_num_list: the current stream has these msg(msg number in the msg_list, msg_list belongs to pcap_container) 
        self.pcap_num_list = []
        self.msg_num_list = []  #not done see the TODO in the pcap_packet_container
