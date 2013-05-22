#! /usr/bin/python 
# -*- coding: utf-8 -*-

from protocol import *

#a dict for ether_type
ETHERTYPE = {'0x0600':'XEROX NS IDP',
    '0x0660':'DLOG',
    '0x0661':'DLOG',
    '0x0800':'IP',
    '0x0801':'X.75',
    '0x0802':'NBS',
    '0x0803':'ECMA',
    '0x0804':'Chaosnet',
    '0x0805':'X.25',
    '0x0806':'ARP',
    '0x0808':'Frame Relay ARP',
    '0x6559':'Raw Frame Relay',
    '0x8035':'RARP',
    '0x8037':'Novell Netware IPX',
    '0x809B':'Ether Talk',
    '0x80d5':'IBM SNA Service over Ethernet',
    '0x80f3':'AARP',
    '0x8100':'EAPS',
    '0x8137':'IPX',
    '0x814c':'SNMP',
    '0x86dd':'IPv6',
    '0x880b':'PPP',
    '0x880c':'GSMP',
    '0x8847':'MPLS(unicase)',
    '0x8848':'MPLS(multicast)',
    '0x8863':'PPPoE(Discovery stage)',
    '0x8864':'PPPoE(ppp session stage)',
    '0x88bb':'LWAPP',
    '0x88cc':'LLDP',
    '0x8e88':'EAP over LAN',
    '0x9000':'Loopback',
    '0x9100':'VLAN Tag PI',
    '0x9200':'VLAN Tag PI',
    '0xffff':'Reservations'
    }
#endof ETHERTYPE

class Ethernet(Protocol):
    """a class for Ethernet, derived from class Protocol"""
    
    def __init__(self, frame_data):
        self.ether_type = None
        self.dst_addr = None
        self.src_addr = None
        self.frame = frame_data  #include the ethernet header and the data in the frame
        self.len = None #useful if ether_type is IEEE802.3 ETHERNET
        self.type = None #useful if ether_type is ETHERNET II
        self._decode()
    
    def _decode(self):
        """a method to get info from the frame_data"""
        
        #get the dst_addr string 
        addr = data_to_hex_str(self.frame[0:6])
        self.dst_addr = addr[2:4] + ':' + addr[4:6] + ':' + addr[6:8] + ':'\
            + addr[8:10] + ':' + addr[10:12] + ':' + addr[12:14]
        #get the src_addr string
        addr = data_to_hex_str(self.frame[6:12])
        self.src_addr = addr[2:4] + ':' + addr[4:6] + ':' + addr[6:8] + ':'\
            + addr[8:10] + ':' + addr[10:12] + ':' + addr[12:14]
        
        tmp = int(data_to_hex_str(self.frame[12:14]), 16)
        if (tmp <= 1500):   #means that this is a IEEE802.3 ETHERNET frame, and the frame length is tmp
            self.len = tmp
            self.ether_type = "IEEE802.3 ETHERNET"
        else:
            self.ether_type = "ETHERNET II"
            if ETHERTYPE.has_key(data_to_hex_str(self.frame[12:14])):
                self.type = ETHERTYPE[data_to_hex_str(self.frame[12:14])]
            else:
                self.type = "unknown"
        #endof if
    #endof def
    
    def print_info(self):
        """a method to print the info in the frame"""
        
        print "[%s\tdst:%s\tsrc:%s\ttype:%s]" % (self.ether_type, self.dst_addr, \
            self.src_addr, self.type)
    #endof def
    
#endof class Ethernet
