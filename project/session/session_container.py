#! /usr/bin/python
# -*- coding: utf-8 -*-

from session import *

import re
from BeautifulSoup import BeautifulSoup

def _find_init_req_pos(pcap_container, start, end):
        """a method to get init_req for a new session"""
        
        cur = start
        while (cur < end):
            if (pcap_container.http_list[cur] != None and pcap_container.http_list[cur].http_type == 1 and \
                _is_html_uri(pcap_container.http_list[cur].header_fields["uri"])):    #a http request and it requests a html page
                return cur   #has found the pos of the init_req
            cur += 1
        return -1   #no such req
   
def _is_related_response(pcap_container, req, response):
    """a method to judge the response is related to the request or not"""
    
    return pcap_container.msg_list[req]["src_addr"] == pcap_container.msg_list[response]["dst_addr"] and \
    pcap_container.msg_list[req]["src_port"] == pcap_container.msg_list[response]["dst_port"] and \
    pcap_container.msg_list[req]["dst_addr"] == pcap_container.msg_list[response]["src_addr"] and \
    pcap_container.msg_list[req]["dst_port"] == pcap_container.msg_list[response]["src_port"]
    
def _find_init_response_pos(pcap_container, start, end):
    """a method to find init_response of a new session according to the init_req_pos(start)"""
    
    init_req_pos = start
    cur = start + 1
    while (cur < end):
        if (pcap_container.http_list[cur] != None and pcap_container.http_list[cur].http_type == 2 and
            _is_related_response(pcap_container, init_req_pos, cur)):
            return cur  #has found the pos of the response related to the init_req
        cur += 1
    return -1   #no such response
    
def _extract_link(html_page):
    """a method to extract all links in a html page"""
    
    soup = BeautifulSoup(html_page)
    #find all tags that have attrs: href and src
    href_list = soup.findAll(href = True)
    src_list = soup.findAll(src = True)
    #extract links in the attr : "href" and "src"
    href_set = set([tag['href'] for tag in href_list])
    src_set = set([tag['src'] for tag in src_list])
    link_set = href_set | src_set
    
    return link_set
    
def _is_html_uri(uri):
    """a method to judge an uri is a html page or not"""
    
    pattern = '.+\.(html|htm)$'
    m = re.match(pattern, uri)
    if (m != None or uri == '/'):
        return True
    return False

class Session_container():
    
    def __init__(self):
        self.sessions = []
        
    def split_session(self, pcap_container):
        """a method to split all the pcap_packets into session"""
        
        start = 0
        end = len(pcap_container.msg_list)
        while (start < end):
            #find the init_req
            init_req = _find_init_req_pos(pcap_container, start, end)
            if (init_req == -1):
                break
            start = init_req + 1
            
            #find the init_response_pos
            init_response = _find_init_response_pos(pcap_container, init_req, end)
            if (init_response == -1):
                break
            
            #extract link from the response page  --> link_set
            if (pcap_container.http_list[init_response].decoding_content != None):
                html_src = pcap_container.http_list[init_response].decoding_content
            else:
                html_src = pcap_container.http_list[init_response].content
            link_set = _extract_link(html_src)
            
            #from the link_set, find related request(according "uri"), and get the sockets_set
            
            #init a new session
    
