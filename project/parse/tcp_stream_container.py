#! /usr/bin/python 
# -*- coding: utf-8 -*-

class Tcp_stream_container(dict):
    """a tcp stream include: tcp connection stablishment, http request, http response, tcp connection finish"""
    #use a socket_tuple to indentify a tcp stream, socket_tuple : (client_addr, client_port, server_addr, server_port)
    #note that server_port must be 80
    
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
