# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/hm/pcap_analysis/project/ui/User_behavior_statistic_window.ui'
#
# Created: Mon May 13 17:16:07 2013
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
        MainWindow.resize(718, 305)
        self.centralWidget = QtGui.QWidget(MainWindow)
        self.centralWidget.setObjectName(_fromUtf8("centralWidget"))
        self.bro_stat_table_widget = QtGui.QTableWidget(self.centralWidget)
        self.bro_stat_table_widget.setGeometry(QtCore.QRect(21, 67, 669, 71))
        self.bro_stat_table_widget.setObjectName(_fromUtf8("bro_stat_table_widget"))
        self.bro_stat_table_widget.setColumnCount(0)
        self.bro_stat_table_widget.setRowCount(0)
        self.label_3 = QtGui.QLabel(self.centralWidget)
        self.label_3.setGeometry(QtCore.QRect(21, 44, 111, 17))
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.label_4 = QtGui.QLabel(self.centralWidget)
        self.label_4.setGeometry(QtCore.QRect(21, 165, 114, 17))
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.plat_stat_table_widget = QtGui.QTableWidget(self.centralWidget)
        self.plat_stat_table_widget.setGeometry(QtCore.QRect(21, 188, 669, 51))
        self.plat_stat_table_widget.setObjectName(_fromUtf8("plat_stat_table_widget"))
        self.plat_stat_table_widget.setColumnCount(0)
        self.plat_stat_table_widget.setRowCount(0)
        self.label = QtGui.QLabel(self.centralWidget)
        self.label.setGeometry(QtCore.QRect(22, 21, 81, 17))
        self.label.setScaledContents(True)
        self.label.setObjectName(_fromUtf8("label"))
        self.file_name_lb = QtGui.QLabel(self.centralWidget)
        self.file_name_lb.setGeometry(QtCore.QRect(113, 21, 571, 20))
        self.file_name_lb.setScaledContents(True)
        self.file_name_lb.setObjectName(_fromUtf8("file_name_lb"))
        MainWindow.setCentralWidget(self.centralWidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow", None))
        self.label_3.setText(_translate("MainWindow", "browser statistic", None))
        self.label_4.setText(_translate("MainWindow", "platform statistic", None))
        self.label.setText(_translate("MainWindow", "file_name:", None))
        self.file_name_lb.setText(_translate("MainWindow", "TextLabel", None))


if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

