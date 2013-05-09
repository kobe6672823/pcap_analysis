#! /usr/bin/python
# -*- coding: utf-8 -*-
#try to read in pcap file, and print the data in it 

import struct

def rd_pcap(pcap_file_name):
    """read in pcap file, 
    return: pcap_header, packet_headers, packets"""
    
    try:
        fpcap = open(pcap_file_name, 'rb')
    except IOError, e:
        print e
        exit(1)

    string_data = fpcap.read()

    #parse the pcap file
    #magic为文件识别头，pcap固定为：0xA1B2C3D4。（4个字节）
    #magor version为主版本号（2个字节）
    #minor version为次要版本号（2个字节）
    #timezone为当地的标准时间（4个字节）
    #sigflags为时间戳的精度（4个字节）
    #snaplen为最大的存储长度（4个字节）
    #linktype为链路类型（4个字节）
    pcap_header = {}
    pcap_header['magic'], pcap_header['magor_version'], pcap_header['minor_version'], \
    pcap_header['timezone'], pcap_header['sigflags'], pcap_header['snaplen'], \
    pcap_header['linktype'] = struct.unpack('4s2s2s4s4s4s4s', string_data[0 : 24])

    packet_headers = []
    packets = []
    pos = 24 #length of the pcap_header
    pcap_len = len(string_data)
    packet_num = 0
    while (pos < pcap_len):
        #parse the packet_header
        #数据包头则依次为：时间戳（秒）、时间戳（微妙）、抓包长度和实际长度，依次各占4个字节。
        packet_header = {}
        packet_header['timestamp_s'], packet_header['timestamp_ms'], packet_header['cap_len'], packet_header['len'] = \
        struct.unpack('IIII', string_data[pos : pos+16])
        packet_header['ts'] = float(str(packet_header['timestamp_s']) + '.' + str(packet_header['timestamp_ms']))
        pos += 16
        
        #get the packet data
        packet = string_data[pos : pos+packet_header['cap_len']]
        pos += packet_header['cap_len']
        packets.append(packet)
        packet_headers.append(packet_header)
        packet_num += 1
    #endof while

    fpcap.close()
    
    return (pcap_header, packet_headers, packets)
#endof def

def print_pkt(pkt_headers, pkts):
    "print the packet_headers and the packets which got from the pcap file"
    
    print "@@@@@@@@@@@@@@@@@   ready to print all the packet_headers and the packets in the pcap file   @@@@@@@@@@@@@@@@@"
    for i in range(len(pkts)):
        print "---------------this is the %dth packet_header---------------------" % (i+1)
        print "timestamp_s: %d" % packet_headers[i]["timestamp_s"]
        print "timestamp_ms: %d" % packet_headers[i]["timestamp_ms"]
        print "cap_len: %d" % packet_headers[i]["cap_len"]
        print "len: %d" % packet_headers[i]["len"]
        print  "###############this is the %dth packet_data######################" % (i+1)
        print "data: %s" % repr(packets[i])
    #endof for
    print "@@@@@@@@@@@@@@@@@    end of the print process    @@@@@@@@@@@@@@@@@@@"
#endof def

