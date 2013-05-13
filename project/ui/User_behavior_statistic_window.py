# -*- coding: utf-8 -*-

"""
Module implementing User_behavior_statistic_window.
"""

from PyQt4.QtGui import QMainWindow
from PyQt4.QtCore import pyqtSignature

from Ui_User_behavior_statistic_window import Ui_MainWindow

class User_behavior_statistic_window(QMainWindow, Ui_MainWindow):
    """
    Class documentation goes here.
    """
    def __init__(self, parent = None):
        """
        Constructor
        """
        QMainWindow.__init__(self, parent)
        self.setupUi(self)
