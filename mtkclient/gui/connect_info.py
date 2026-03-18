from PySide6.QtWidgets import QWidget
from mtkclient.gui.connect_info_ui import Ui_ConnectInfoForm


class ConnectInfoWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_ConnectInfoForm()
        self.ui.setupUi(self)
