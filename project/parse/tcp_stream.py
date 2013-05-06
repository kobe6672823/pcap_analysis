#! /usr/bin/python 
# -*- coding: utf-8 -*-

class Tcp_stream():
    """a tcp stream include: tcp connection stablishment, http request, http response, tcp connection finish"""
    
    def __init__(self, addr1, port1, addr2, port2):
        #use socket_pair to indentify a tcp stream, socket_pair is a set, as (addr1, port1) and (addr2, port2) should not
        #be sequential
        self.socket_pair = set()
        self.socket_pair.add((addr1, port1))
        self.socket_pair.add((addr2, port2))
        self.pcap_num_list = [] #the numbers of the pcap_packets containing in the current tcp stream 
