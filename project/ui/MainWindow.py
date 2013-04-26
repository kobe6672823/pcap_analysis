#! /usr/bin/python 
# -*- coding: utf-8 -*-

"""
Module implementing MainWindow.
"""

from PyQt4.QtGui import *
from PyQt4.QtCore import *

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
        self.connect(self.packet_table_widget, SIGNAL("itemClicked (QTableWidgetItem*)"), self.show_packet_info_tree)
    
    def show_ethernet_tree(self, pcap_packet):
        """a method to show an ethernet tree in the packet_info_tree"""
        
        ether_item = QTreeWidgetItem(self.packet_info_tree)
        item_text = pcap_packet.ethernet.ether_type
        ether_item.setText(0, item_text)
        
        ether_src_item = QTreeWidgetItem(ether_item)
        item_text = "Src: " + pcap_packet.ethernet.src_addr
        ether_src_item.setText(0, item_text)
        
        ether_dst_item = QTreeWidgetItem(ether_item)
        item_text = "Dst: " + pcap_packet.ethernet.dst_addr
        ether_dst_item.setText(0, item_text)
    #endof def
    
    def show_ip_tree(self, pcap_packet):
        """a method to show an ip tree in the packet_info_tree"""
        
        ip_item = QTreeWidgetItem(self.packet_info_tree)
        ip_item.setText(0, "Internet Protocol")
        
        ip_version_item = QTreeWidgetItem(ip_item)
        item_text = "Version: " + str(pcap_packet.ip.version)
        ip_version_item.setText(0, item_text)
        
        ip_header_len_item = QTreeWidgetItem(ip_item)
        item_text = "Header length: " + str(pcap_packet.ip.header_len) + " bytes"
        ip_header_len_item.setText(0, item_text)
        
        ip_tos_item = QTreeWidgetItem(ip_item)
        item_text = "Type of service fields: " + pcap_packet.ip.type_of_service
        ip_tos_item.setText(0, item_text)
        
        ip_total_len_item = QTreeWidgetItem(ip_item)
        item_text = "Total length: " + str(pcap_packet.ip.total_len) + " bytes"
        ip_total_len_item.setText(0, item_text)
        
        ip_id_item = QTreeWidgetItem(ip_item)
        item_text = "Identification: " + pcap_packet.ip.id
        ip_id_item.setText(0, item_text)
        
        ip_flags_item = QTreeWidgetItem(ip_item)
        item_text = "Flags"
        ip_flags_item.setText(0, item_text)
        
        ip_flags_reservedbit_item = QTreeWidgetItem(ip_flags_item)
        if (pcap_packet.ip.flags_reservedbit == 0):
            item_text = "0.. = Reserved bit: Not Set"
        else:
            item_text = "1.. = Reserved bit: Set"
        ip_flags_reservedbit_item.setText(0, item_text)
        
        ip_flags_dont_frag_item = QTreeWidgetItem(ip_flags_item)
        if (pcap_packet.ip.flags_dont_fragment == 0):
            item_text = ".0. = Don't fragment: Not Set"
        else:
            item_text = ".1. = Don't fragment: Set"
        ip_flags_dont_frag_item.setText(0, item_text)
        
        ip_flags_more_frag_item = QTreeWidgetItem(ip_flags_item)
        if (pcap_packet.ip.flags_more_fragment == 0):
            item_text = "..0 = More fragment: Not Set"
        else:
            item_text = "..1 = More fragment: Set"
        ip_flags_more_frag_item.setText(0, item_text)
        
        ip_frag_offset_item = QTreeWidgetItem(ip_item)
        item_text = "Fragment offset: " + str(pcap_packet.ip.fragment_offset)
        ip_frag_offset_item.setText(0, item_text)
        
        ip_TTL_item = QTreeWidgetItem(ip_item)
        item_text = "Time to live: " + str(pcap_packet.ip.TTL)
        ip_TTL_item.setText(0, item_text)
        
        ip_protocol_item = QTreeWidgetItem(ip_item)
        item_text = "Protocol: " + str(pcap_packet.ip.protocol)
        ip_protocol_item.setText(0, item_text)
        
        ip_header_checksum_item = QTreeWidgetItem(ip_item)
        item_text = "Header checksum: " + pcap_packet.ip.header_checksum
        ip_header_checksum_item.setText(0, item_text)
        
        ip_src_item = QTreeWidgetItem(ip_item)
        item_text = "Source: " + pcap_packet.ip.src
        ip_src_item.setText(0, item_text)
        
        ip_dst_item = QTreeWidgetItem(ip_item)
        item_text = "Destination: " + pcap_packet.ip.dst
        ip_dst_item.setText(0, item_text)
        
    #endof def
    @pyqtSignature("")
    def show_packet_info_tree(self, Item=None):
        """once user click an item in the packet table widget, 
        then show its details(the info in each layer) in a tree view"""
        if (Item==None):
            return        
        
        self.packet_info_tree.clear()
        cur_row = Item.row()
        pcap_packet = self.pcap_container.pcap_packets[cur_row]
        
        #show the info of ethernet
        if (pcap_packet.top_layer < 1):
            return
        self.show_ethernet_tree(pcap_packet)
        
        #show the info of ip
        if (pcap_packet.top_layer < 2):
            return
        self.show_ip_tree(pcap_packet)
    
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
    #endof def

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
