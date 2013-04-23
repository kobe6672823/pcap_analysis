#! /usr/bin/python 
# -*- coding: utf-8 -*-

#define base class Protocol, it is an empty class
#define a method to get hex_str

class Protocol:
    def __init__(self):
        pass
        
def data_to_hex_str(data_string):
    """a string stores data in hex, for example : \xab\x01 \x02\x11   note that: \xab\x01 is one byte
    transfer process is:   byte -->> ascii_number -->> hex_number -->> hex_string -->> get result: 0xab010211"""
    
    result = ''
    for i in range(len(data_string)):
        tmp = ord(data_string[i])
        tmp = hex(tmp)
        if (len(tmp) == 3):  #in case that tmp < 0xf, should add a 0 after x
            tmp = tmp.replace('0x', '0x0')
        tmp = tmp.replace('0x', '')   #delete the 0x
        result = result + tmp
    #endof for
    return '0x' + result
#endof def
