#! /usr/bin/python
# -*- coding: utf-8 -*-

class Message(dict):
    """Reassembled message class

    Message attributes are accessible as regular object attributes using
    dot-notation. The common available attributes are:

     * number
     * ts
     * data

    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
