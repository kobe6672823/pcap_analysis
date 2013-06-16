# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/hm/pcap_analysis/project/ui/MainWindow.ui'
#
# Created: Sun Jun 16 15:03:37 2013
#      by: PyQt4 UI code generator 4.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(847, 692)
        self.centralWidget = QtGui.QWidget(MainWindow)
        self.centralWidget.setObjectName(_fromUtf8("centralWidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.centralWidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.status_lb = QtGui.QLabel(self.centralWidget)
        self.status_lb.setObjectName(_fromUtf8("status_lb"))
        self.verticalLayout.addWidget(self.status_lb)
        self.packet_table_widget = QtGui.QTableWidget(self.centralWidget)
        self.packet_table_widget.setObjectName(_fromUtf8("packet_table_widget"))
        self.packet_table_widget.setColumnCount(0)
        self.packet_table_widget.setRowCount(0)
        self.verticalLayout.addWidget(self.packet_table_widget)
        self.packet_info_tree = QtGui.QTreeWidget(self.centralWidget)
        self.packet_info_tree.setObjectName(_fromUtf8("packet_info_tree"))
        self.packet_info_tree.headerItem().setText(0, _fromUtf8("1"))
        self.verticalLayout.addWidget(self.packet_info_tree)
        MainWindow.setCentralWidget(self.centralWidget)
        self.menuBar = QtGui.QMenuBar(MainWindow)
        self.menuBar.setGeometry(QtCore.QRect(0, 0, 847, 25))
        self.menuBar.setObjectName(_fromUtf8("menuBar"))
        self.menuFile = QtGui.QMenu(self.menuBar)
        self.menuFile.setObjectName(_fromUtf8("menuFile"))
        self.menuDevice_browser_info = QtGui.QMenu(self.menuBar)
        self.menuDevice_browser_info.setObjectName(_fromUtf8("menuDevice_browser_info"))
        self.menuSession = QtGui.QMenu(self.menuBar)
        self.menuSession.setObjectName(_fromUtf8("menuSession"))
        self.menuTcp = QtGui.QMenu(self.menuBar)
        self.menuTcp.setObjectName(_fromUtf8("menuTcp"))
        self.menuConguestion_control = QtGui.QMenu(self.menuBar)
        self.menuConguestion_control.setObjectName(_fromUtf8("menuConguestion_control"))
        MainWindow.setMenuBar(self.menuBar)
        self.actionLoad_pcap_file = QtGui.QAction(MainWindow)
        self.actionLoad_pcap_file.setObjectName(_fromUtf8("actionLoad_pcap_file"))
        self.actionDev_bro_stat = QtGui.QAction(MainWindow)
        self.actionDev_bro_stat.setObjectName(_fromUtf8("actionDev_bro_stat"))
        self.actionSession_split = QtGui.QAction(MainWindow)
        self.actionSession_split.setObjectName(_fromUtf8("actionSession_split"))
        self.actionSession_stat = QtGui.QAction(MainWindow)
        self.actionSession_stat.setObjectName(_fromUtf8("actionSession_stat"))
        self.actionResource_dis = QtGui.QAction(MainWindow)
        self.actionResource_dis.setObjectName(_fromUtf8("actionResource_dis"))
        self.actionExport_dev_bro_stat = QtGui.QAction(MainWindow)
        self.actionExport_dev_bro_stat.setObjectName(_fromUtf8("actionExport_dev_bro_stat"))
        self.actionTcp_stat = QtGui.QAction(MainWindow)
        self.actionTcp_stat.setObjectName(_fromUtf8("actionTcp_stat"))
        self.actionSession_conn_stat = QtGui.QAction(MainWindow)
        self.actionSession_conn_stat.setObjectName(_fromUtf8("actionSession_conn_stat"))
        self.actionCong_stat = QtGui.QAction(MainWindow)
        self.actionCong_stat.setObjectName(_fromUtf8("actionCong_stat"))
        self.actionExport_cong_stat = QtGui.QAction(MainWindow)
        self.actionExport_cong_stat.setObjectName(_fromUtf8("actionExport_cong_stat"))
        self.actionExport_session_stat = QtGui.QAction(MainWindow)
        self.actionExport_session_stat.setObjectName(_fromUtf8("actionExport_session_stat"))
        self.actionProto_stat = QtGui.QAction(MainWindow)
        self.actionProto_stat.setObjectName(_fromUtf8("actionProto_stat"))
        self.actionExport_tcp_stat = QtGui.QAction(MainWindow)
        self.actionExport_tcp_stat.setObjectName(_fromUtf8("actionExport_tcp_stat"))
        self.menuFile.addAction(self.actionLoad_pcap_file)
        self.menuDevice_browser_info.addAction(self.actionDev_bro_stat)
        self.menuDevice_browser_info.addAction(self.actionExport_dev_bro_stat)
        self.menuSession.addAction(self.actionSession_split)
        self.menuSession.addAction(self.actionSession_stat)
        self.menuSession.addAction(self.actionExport_session_stat)
        self.menuTcp.addAction(self.actionTcp_stat)
        self.menuTcp.addAction(self.actionSession_conn_stat)
        self.menuTcp.addAction(self.actionProto_stat)
        self.menuTcp.addAction(self.actionExport_tcp_stat)
        self.menuConguestion_control.addAction(self.actionCong_stat)
        self.menuConguestion_control.addAction(self.actionExport_cong_stat)
        self.menuBar.addAction(self.menuFile.menuAction())
        self.menuBar.addAction(self.menuDevice_browser_info.menuAction())
        self.menuBar.addAction(self.menuSession.menuAction())
        self.menuBar.addAction(self.menuTcp.menuAction())
        self.menuBar.addAction(self.menuConguestion_control.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow", None))
        self.status_lb.setText(_translate("MainWindow", "please load pcap file", None))
        self.menuFile.setTitle(_translate("MainWindow", "File", None))
        self.menuDevice_browser_info.setTitle(_translate("MainWindow", "device/browser info", None))
        self.menuSession.setTitle(_translate("MainWindow", "session", None))
        self.menuTcp.setTitle(_translate("MainWindow", "tcp", None))
        self.menuConguestion_control.setTitle(_translate("MainWindow", "congestion_control", None))
        self.actionLoad_pcap_file.setText(_translate("MainWindow", "load pcap file", None))
        self.actionDev_bro_stat.setText(_translate("MainWindow", "info statistic", None))
        self.actionSession_split.setText(_translate("MainWindow", "session split", None))
        self.actionSession_stat.setText(_translate("MainWindow", "session statistic", None))
        self.actionResource_dis.setText(_translate("MainWindow", "session resource distribution", None))
        self.actionExport_dev_bro_stat.setText(_translate("MainWindow", "export statistic", None))
        self.actionTcp_stat.setText(_translate("MainWindow", "tcp conn statistic", None))
        self.actionSession_conn_stat.setText(_translate("MainWindow", "session tcp conn statistic", None))
        self.actionCong_stat.setText(_translate("MainWindow", "congestion_control statistic", None))
        self.actionExport_cong_stat.setText(_translate("MainWindow", "export statistic", None))
        self.actionExport_session_stat.setText(_translate("MainWindow", "export statistic", None))
        self.actionProto_stat.setText(_translate("MainWindow", "protocol classified statistic", None))
        self.actionExport_tcp_stat.setText(_translate("MainWindow", "export statistic", None))


if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

