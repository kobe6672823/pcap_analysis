#! /usr/bin/python 
# -*- coding: utf-8 -*-

from protocol import *
from gzip import *
from StringIO import *

#type of http
HTTP_REQUEST = 1
HTTP_RESPONSE = 2

class Http(Protocol):
    """a class for http, derived from class Protocol(an empty class)"""
    
    def __init__(self, data):
        header_len = data.index("\r\n\r\n")
        self.http_header = "".join(data[0:header_len])  #without the "\r\n\r\n"
        self.content = "".join(data[header_len+4:])
        self.decoding_content = None    #if the http content isnot encoding, this field will be None
        
        self.type = None    #HTTP_REQUEST or HTTP_RESPONSE
        
        #all fields in a http header(HTTP/1.1)
        self.header_fields = {}
        
        #only handle the HTTP/1.1
        self.header_fields["http_version"] = "HTTP/1.1"
        
        #only http response has such fields
        self.header_fields["status_code"] = 0
        self.header_fields["status"] = None
        
        #only http request has such fields
        self.header_fields["request_method"] = None
        self.header_fields["uri"] = None
        
        self._get_header_fields()
        #decode http content if necessary
        if (self.type == HTTP_RESPONSE and self.header_fields.has_key("content-encoding") and 
            self.header_fields["content-encoding"] == "gzip"):
            try:
                gf = GzipFile(fileobj=StringIO(self.content), mode="r")
                self.decoding_content = gf.read()
            except:
                self.decoding_content = gf.extrabuf
        
    def _get_header_fields(self):
        """a method to fill in the fields above"""
        
        if (self.http_header[0:6] == "HTTP/1"):
            self.type = HTTP_RESPONSE
            self.header_fields["status_code"] = int(self.http_header[9:12])
            self.header_fields["status"] = str(self.http_header[13:15])
        else:
            self.type = HTTP_REQUEST
            self.header_fields["request_method"] = str(self.http_header[0:3])
            pos = self.http_header.index(" HTTP/1.1")
            self.header_fields["uri"] = str(self.http_header[4:pos])
        
        header_lines = self.http_header.split("\r\n")
        for line in header_lines[1:]:
            line_split = line.split(": ")
            field_name = str.lower(line_split[0])
            self.header_fields[field_name] = line_split[1]
            
