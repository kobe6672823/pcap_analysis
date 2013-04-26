#! /usr/bin/python 
# -*- coding: utf-8 -*-

"""
Module implementing MainWindow.
"""

from PyQt4.QtGui import QMainWindow, QFileDialog, QTableWidgetItem, QAbstractItemView
from PyQt4.QtCore import pyqtSignature, QString

from Ui_MainWindow import Ui_MainWindow

from parse.Pcap_packet_container import *

class MainWindow(QMainWindow, Ui_MainWindow):
    """
    Class documentation goes here.
    """
    def __init__(self, parent = None):
        """
        Constructor
        """
        QMainWindow.__init__(self, parent)
        self.setupUi(self)
        self.pcap_container = None
    
    def fill_in_packet_table(self, pcap_container):
        """display info in the pcap_container to the packet_table_widget"""
        
        #set the basic preference of the table widget
        self.packet_table_widget.setRowCount(len(pcap_container.pcap_packets))
        self.packet_table_widget.setColumnCount(5)
        table_headers = ["No.", "Time", "Source", "Destination", "Protocol"]
        self.packet_table_widget.setHorizontalHeaderLabels(table_headers)
        self.packet_table_widget.verticalHeader().setVisible(False)
        self.packet_table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        
        #insert data into the table widget
        cur_num = 0
        start_time = float(str(pcap_container.packet_headers[cur_num]["timestamp_s"]) + '.' + \
            str(pcap_container.packet_headers[cur_num]["timestamp_ms"]))
        for pcap_packet in pcap_container.pcap_packets:
            
            #skip the packet that I don't need(only need tcp/ip packet)
            #if (pcap_packet.ethernet.ether_type != "ETHERNET II" or 
            #    pcap_packet.ethernet.type != "IP" or 
            #    pcap_packet.ip.protocol != "TCP"):
            #    continue
                
            #set number
            newItem = QTableWidgetItem(str(cur_num+1))
            self.packet_table_widget.setItem(cur_num, 0, newItem)
            #set Time
            cur_time = float(str(pcap_container.packet_headers[cur_num]["timestamp_s"]) + '.' + \
                str(pcap_container.packet_headers[cur_num]["timestamp_ms"])) - start_time
            cur_time = round(cur_time, 6)
            time_stamp = str(cur_time)
            newItem = QTableWidgetItem(time_stamp)
            self.packet_table_widget.setItem(cur_num, 1, newItem)
            
            #set Source
            newItem = QTableWidgetItem(pcap_packet.ip.src)
            self.packet_table_widget.setItem(cur_num, 2, newItem)
            
            #set Destination
            newItem = QTableWidgetItem(pcap_packet.ip.dst)
            self.packet_table_widget.setItem(cur_num, 3, newItem)
            
            #set Protocol
            newItem = QTableWidgetItem(pcap_packet.ip.protocol)
            self.packet_table_widget.setItem(cur_num, 4, newItem)
            
            cur_num += 1
        #endof for
        self.packet_table_widget.resizeColumnsToContents()

    @pyqtSignature("")
    def on_actionLoad_pcap_file_triggered(self):
        """
        for the user to select and load the pcap file, and analyze the basic info in the file, and display
        """
        fName = QFileDialog.getOpenFileName(None, self.trUtf8("Select a pcap file to parse"), QString(), self.trUtf8("*.pcap"), None)
        self.status_lb.setText(fName)
        
        #get pcap_container
        self.pcap_container = Pcap_packet_container(fName)
        self.pcap_container.parse()
        
        self.fill_in_packet_table(self.pcap_container)
    
    @pyqtSignature("")
    def on_actionDev_bro_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionSession_split_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionSession_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionResource_dis_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionExport_dev_bro_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionTcp_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionSession_conn_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionCong_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionExport_cong_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionExport_session_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionProto_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSignature("")
    def on_actionExport_tcp_stat_triggered(self):
        """
        Slot documentation goes here.
        """
        # TODO: not implemented yet
        raise NotImplementedError
