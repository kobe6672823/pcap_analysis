#! /usr/bin/python 
# -*- coding: utf-8 -*-

"""
Module implementing MainWindow.
"""

import os

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from Ui_MainWindow import Ui_MainWindow

from parse.Pcap_packet_container import *
from analyzer.user_behavior_analyzer import *

from User_behavior_statistic_window import User_behavior_statistic_window

import xlwt

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
        self.user_behavior_analyzer = None
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
    
    def show_tcp_tree(self, pcap_packet):
        """a method to show a tcp tree in the packet_info_tree"""
        
        tcp_item = QTreeWidgetItem(self.packet_info_tree)
        tcp_item.setText(0, "Transmission Control Protocol")
        
        tcp_src_port_item = QTreeWidgetItem(tcp_item)
        item_text = "Source port: " + str(pcap_packet.tcp.src_port)
        tcp_src_port_item.setText(0, item_text)
        
        tcp_dst_port_item = QTreeWidgetItem(tcp_item)
        item_text = "Destination port: " + str(pcap_packet.tcp.dst_port)
        tcp_dst_port_item.setText(0, item_text)
        
        tcp_seq_num_item = QTreeWidgetItem(tcp_item)
        item_text = "Sequence number: " + str(pcap_packet.tcp.sequence_num)
        tcp_seq_num_item.setText(0, item_text)
        
        tcp_ack_num_item = QTreeWidgetItem(tcp_item)
        item_text = "Acknowledgement number: " + str(pcap_packet.tcp.ack_num)
        tcp_ack_num_item.setText(0, item_text)
        
        tcp_header_len_item = QTreeWidgetItem(tcp_item)
        item_text = "Header length: " + str(pcap_packet.tcp.header_len)
        tcp_header_len_item.setText(0, item_text)
        
        tcp_flags_item = QTreeWidgetItem(tcp_item)
        item_text = "Flags: "
        tcp_flags_item.setText(0, item_text)
        
        tcp_flag_urg_item = QTreeWidgetItem(tcp_flags_item)
        if (pcap_packet.tcp.flag_urg == 0):
            item_text = "0..... = Urgent: Not set"
        else:
            item_text = "1..... = Urgent: Set"
        tcp_flag_urg_item.setText(0, item_text)
        
        tcp_flag_ack_item = QTreeWidgetItem(tcp_flags_item)
        if (pcap_packet.tcp.flag_ack == 0):
            item_text = ".0.... = Acknowledgement: Not set"
        else:
            item_text = ".1.... = Acknowledgement: Set"
        tcp_flag_ack_item.setText(0, item_text)
        
        tcp_flag_psh_item = QTreeWidgetItem(tcp_flags_item)
        if (pcap_packet.tcp.flag_psh == 0):
            item_text = "..0... = Push: Not set"
        else:
            item_text = "..1... = Push: Set"
        tcp_flag_psh_item.setText(0, item_text)
        
        tcp_flag_rst_item = QTreeWidgetItem(tcp_flags_item)
        if (pcap_packet.tcp.flag_rst == 0):
            item_text = "...0.. = Rest: Not set"
        else:
            item_text = "...1.. = Rest: Set"
        tcp_flag_rst_item.setText(0, item_text)
        
        tcp_flag_syn_item = QTreeWidgetItem(tcp_flags_item)
        if (pcap_packet.tcp.flag_syn == 0):
            item_text = "....0. = Syn: Not set"
        else:
            item_text = "....1. = Syn: Set"
        tcp_flag_syn_item.setText(0, item_text)
        
        tcp_flag_fin_item = QTreeWidgetItem(tcp_flags_item)
        if (pcap_packet.tcp.flag_fin == 0):
            item_text = ".....0 = Fin: Not set"
        else:
            item_text = ".....1 = Fin: Set"
        tcp_flag_fin_item.setText(0, item_text)
        
        tcp_window_size_item = QTreeWidgetItem(tcp_item)
        item_text = "Window size: " + str(pcap_packet.tcp.window_size)
        tcp_window_size_item.setText(0, item_text)
        
        tcp_checksum_item = QTreeWidgetItem(tcp_item)
        item_text = "Check sum: " + pcap_packet.tcp.checksum
        tcp_checksum_item.setText(0, item_text)
        
        tcp_urgent_pointer_item = QTreeWidgetItem(tcp_item)
        item_text = "Urgent pointer: " + pcap_packet.tcp.urgent_pointer
        tcp_urgent_pointer_item.setText(0, item_text)
        
        tcp_opt_paddings_item = QTreeWidgetItem(tcp_item)
        item_text = "Option and paddings: " + repr(pcap_packet.tcp.opt_paddings)
        tcp_opt_paddings_item.setText(0, item_text)
        
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
        
        #show the info of tcp
        if (pcap_packet.top_layer < 3):
            return
        self.show_tcp_tree(pcap_packet)
    
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
        
        self.fill_in_packet_table(self.pcap_container)
    
    @pyqtSignature("")
    def on_actionDev_bro_stat_triggered(self):
        """
        get and store the statistic of device and browser, and show it in a new window
        """
        
        if (self.pcap_container == None):
            warning_box = QMessageBox.warning(self, "warn", "please load a pcap file!")
            return
        
        #traverse the http_list, if not none and it is a http_request, get the user-agent to do the statistic
        self.user_behavior_analyzer = User_behavior_analyzer()
        self.user_behavior_analyzer.analyze(self.pcap_container)
        
        #show the statistic info in a new window
        wnd = User_behavior_statistic_window(self)
        wnd.file_name_lb.setText(self.pcap_container.pcap_file_name)
        
        #browser statistic
        table_headers = self.user_behavior_analyzer.browser_statistics.keys()
        wnd.bro_stat_table_widget.setColumnCount(len(table_headers))
        wnd.bro_stat_table_widget.setRowCount(1)
        wnd.bro_stat_table_widget.setHorizontalHeaderLabels(table_headers)
        wnd.bro_stat_table_widget.verticalHeader().setVisible(False)
        wnd.bro_stat_table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        wnd.bro_stat_table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        cur_col = 0
        for key in table_headers:
            newItem = QTableWidgetItem(str(self.user_behavior_analyzer.browser_statistics[key]))
            wnd.bro_stat_table_widget.setItem(0, cur_col, newItem)
            cur_col += 1
        wnd.bro_stat_table_widget.resizeColumnsToContents()
        
        #platform statistic
        table_headers = self.user_behavior_analyzer.platform_statistics.keys()
        wnd.plat_stat_table_widget.setColumnCount(len(table_headers))
        wnd.plat_stat_table_widget.setRowCount(1)
        wnd.plat_stat_table_widget.setHorizontalHeaderLabels(table_headers)
        wnd.plat_stat_table_widget.verticalHeader().setVisible(False)
        wnd.plat_stat_table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        wnd.plat_stat_table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        cur_col = 0
        for key in table_headers:
            newItem = QTableWidgetItem(str(self.user_behavior_analyzer.platform_statistics[key]))
            wnd.plat_stat_table_widget.setItem(0, cur_col, newItem)
            cur_col += 1
        wnd.plat_stat_table_widget.resizeColumnsToContents()
        wnd.show()
    
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
        export the statistic of device and browser to excel file and draw pics of the statistic
        """
        
        if (not os.path.exists("user_behavior_analyzer")):
            os.mkdir("user_behavior_analyzer")
        #export to excel
        if (self.pcap_container == None):
            warning_box = QMessageBox.warning(self, "warn", "please load a pcap file!")
            return
        if (self.user_behavior_analyzer == None):
            self.user_behavior_analyzer = User_behavior_analyzer()
            self.user_behavior_analyzer.analyze(self.pcap_container)
        
        wb = xlwt.Workbook()
        ws = wb.add_sheet('browser statistics')
        table_headers = self.user_behavior_analyzer.browser_statistics.keys()
        cur_col = 0
        for key in table_headers:
            ws.write(0, cur_col, key)
            ws.write(1, cur_col, self.user_behavior_analyzer.browser_statistics[key])
            cur_col += 1
        
        ws = wb.add_sheet('platform statistics')
        table_headers = self.user_behavior_analyzer.platform_statistics.keys()
        cur_col = 0
        for key in table_headers:
            if (key == 'NT'):
                ws.write(0, cur_col, 'Windows')
            else:
                ws.write(0, cur_col, key)
            ws.write(1, cur_col, self.user_behavior_analyzer.platform_statistics[key])
            cur_col += 1
        
        xl_file_name = "user_behavior_analyzer/" + "_".join(str(self.pcap_container.pcap_file_name.split("/")[-1]).split('.')) + \
            '_user_behavior_stat.xls'
        wb.save(xl_file_name)
        warning_box = QMessageBox.warning(self, "confirm", "export done!")
        
        
    
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
