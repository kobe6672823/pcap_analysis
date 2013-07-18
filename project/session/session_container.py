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
    
    try:
        soup = BeautifulSoup(html_page)
    except:
        empty_set = set()
        return empty_set
    #find all tags that have attrs: href and src
    href_list = soup.findAll(href = True)
    src_list = soup.findAll(src = True)
    #extract links in the attr : "href" and "src"
    href_set = set([tag['href'] for tag in href_list])
    src_set = set([tag['src'] for tag in src_list])
    u_link_set = href_set | src_set
    
    #transfer unicode to ascii str
    link_set = set()
    for link in u_link_set:
        link_set.add(str(link))
    return link_set
    
    #TODO: current method is using the beautiful soup to get all the href and src, but it is not complete, some links in the script
    #will miss, should use regular expression to parse the html page, and get all links
    
def _is_in_link_set(uri, link_set):
    """a method to judge if a uri in the link_set or not(test the uri is the sub string of a link in the linkset or not)"""
    
    #TODO: improve the algorithm to test a uri in the set or not, the current method is really stupid and inefficient
    for link in link_set:
        try:
            if (link.find(uri) != -1):
                return True
        except:
            return False
    return False
        
def _get_sockets_set(init_req, pcap_container, link_set):
    """a method to sockets set according to the link_set:   
    if a http's uri in the linkset, then the sockets related to this http will be added into the sockets set"""
    
    cur = 0
    sockets_set = set()
    for http in pcap_container.http_list:
        if (http != None and http.http_type == 1 and _is_in_link_set(http.header_fields["uri"], link_set) or cur == init_req):
            if (http.header_fields["uri"] == "/" and 
                http.header_fields["host"] != pcap_container.http_list[init_req].header_fields["host"]):
                cur += 1
                continue
            sockets = ((pcap_container.msg_list[cur]["src_addr"], pcap_container.msg_list[cur]["src_port"]), 
                ((pcap_container.msg_list[cur]["dst_addr"], pcap_container.msg_list[cur]["dst_port"])))
            sockets_set.add(sockets)
            sockets_set.add(sockets[::-1])  #reverse the direction   src->dst   ===>>>   dst->src
        cur += 1
    return sockets_set
    
def _is_html_uri(uri):
    """a method to judge an uri is a html page or not"""
    
    if (uri == None):
        return False
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
            sockets_set = _get_sockets_set(init_req, pcap_container, link_set)
            #init a new session
            new_session = Session(init_req, init_response, sockets_set, pcap_container)
            self.sessions.append(new_session)
        
        #test the sessions are complete or not, and output all the results, a complete session means: its req_num == response_num
        complete_session_num = 0
        for session in self.sessions:
            req_num = 0
            response_num = 0
            for msg_pos in session.http_list:
                msg = pcap_container.http_list[msg_pos]
                if msg != None:
                    if (msg.http_type == 1):
                        req_num += 1
                    elif (msg.http_type == 2):
                        response_num += 1
            if req_num == response_num:
                complete_session_num += 1
                print "complete session!"
            else:
                print "incomplete session!"
        if (len(self.sessions) == 0):
            print "no sessions!"
        else:
            print "session complete rate:" + str(float(complete_session_num) / len(self.sessions))
