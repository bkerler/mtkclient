#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler, G.Kreileman 2021.
# Licensed under GPLv3 License
import sys
import time
import threading
import logging
import ctypes
from unittest import mock
from functools import partial
from PySide6.QtCore import Qt, QVariantAnimation, Signal, QObject, QSize, QTranslator, QLocale, QLibraryInfo, \
    Slot, QCoreApplication
from PySide6.QtGui import QTextOption, QPixmap, QTransform, QIcon
from PySide6.QtWidgets import QMainWindow, QApplication, QWidget, QCheckBox, QVBoxLayout, QHBoxLayout, QLineEdit, \
    QPushButton, QDialog, QListWidgetItem, QListWidget

from mtkclient.Library.mtk_class import Mtk
from mtkclient.Library.DA.mtk_da_handler import DaHandler
from mtkclient.Library.Partitions.gpt import GptSettings
from mtkclient.Library.mtk_main import Main
from mtkclient.config.mtk_config import MtkConfig

from mtkclient.gui.readFlashPartitions import ReadFlashWindow
from mtkclient.gui.writeFlashPartitions import WriteFlashWindow
from mtkclient.gui.eraseFlashPartitions import EraseFlashWindow
from mtkclient.gui.toolsMenu import generateKeysMenu, UnlockMenu
from mtkclient.gui.toolkit import asyncThread, trap_exc_during_debug, convert_size, CheckBox, FDialog, TimeEstim
from mtkclient.config.payloads import PathConfig
from mtkclient.gui.main_gui import Ui_MainWindow
import os
import serial.tools.list_ports


lock = threading.Lock()

os.environ['QT_MAC_WANTS_LAYER'] = '1'  # This fixes a bug in pyside2 on MacOS Big Sur
# TO do Move all GUI modifications to signals!
# install exception hook: without this, uncaught exception would cause application to exit
sys.excepthook = trap_exc_during_debug

# Initiate MTK classes
variables = mock.Mock()
variables.cmd = "stage"
variables.debugmode = True
path = PathConfig()
# if sys.platform.startswith('darwin'):
#    config.ptype = "kamakiri" #Temp for Mac testing
MtkTool = Main(variables)

guiState = "welcome"
phoneInfo = {"chipset": "", "bootMode": "", "daInit": False, "cdcInit": False}

class SerialPortDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Serial Port")
        self.resize(400, 300)

        self.selected_port = ""

        self.init_ui()
        self.refresh_ports()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # List of serial ports
        self.port_list = QListWidget()
        self.port_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.port_list)

        # Buttons
        button_layout = QHBoxLayout()

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_ports)
        button_layout.addWidget(self.refresh_button)

        button_layout.addStretch()

        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)

        # Enable OK button only when a port is selected
        self.port_list.itemSelectionChanged.connect(self.update_ok_button)
        self.ok_button.setDefault(True)

    def refresh_ports(self):
        self.port_list.clear()
        ports = serial.tools.list_ports.comports()

        if not ports:
            item = QListWidgetItem("No serial ports found")
            item.setFlags(Qt.ItemFlag.NoItemFlags)  # Make it unselectable
            self.port_list.addItem(item)
            self.ok_button.setEnabled(False)
            return

        for port in sorted(ports, key=lambda x: x.device):
            # Show device name and description
            display_text = f"{port.device}"
            if port.description and port.description != "n/a":
                display_text += f" - {port.description}"
            if port.manufacturer:
                display_text += f" ({port.manufacturer})"

            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, port.device)  # Store actual device path
            self.port_list.addItem(item)

        # Select first port by default if available
        if self.port_list.count() > 0:
            self.port_list.setCurrentRow(0)

        self.update_ok_button()

    def update_ok_button(self):
        has_selection = self.port_list.currentItem() is not None and \
                        self.port_list.currentItem().data(Qt.ItemDataRole.UserRole) is not None
        self.ok_button.setEnabled(has_selection)

    def accept(self):
        current_item = self.port_list.currentItem()
        if current_item and current_item.data(Qt.ItemDataRole.UserRole):
            self.selected_port = current_item.data(Qt.ItemDataRole.UserRole)
        super().accept()

    def reject(self):
        self.selected_port = ""
        super().reject()

    @staticmethod
    def get_serial_port(parent=None):
        """
        Static method to show the dialog and return the selected port.
        Returns:
            str: Selected port (e.g., '/dev/ttyUSB0' or 'COM3'), or '' if cancelled/no selection
        """
        dialog = SerialPortDialog(parent)
        result = dialog.exec()
        return dialog.selected_port if result == QDialog.DialogCode.Accepted else ""

class DeviceHandler(QObject):
    sendToLogSignal = Signal(str)
    update_status_text = Signal(str)
    sendToProgressSignal = Signal(int)
    da_handler = None

    def __init__(self, parent, preloader: str = None, loader: str = None, loglevel=logging.INFO, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        config = MtkConfig(loglevel=logging.INFO, gui=self.sendToLogSignal, guiprogress=self.sendToProgressSignal,
                           update_status_text=self.update_status_text)
        config.gpt_settings = GptSettings(gpt_num_part_entries='0', gpt_part_entry_size='0',
                                          gpt_part_entry_start_lba='0')  # This actually sets the right GPT settings..
        config.reconnect = True
        config.uartloglevel = 2
        self.loglevel = logging.DEBUG
        config.loader = loader
        config.preloader = preloader
        config.write_preloader_to_file = False
        self.da_handler = DaHandler(Mtk(config=config, loglevel=logging.INFO), loglevel)


def getDevInfo(self, parameters):
    # loglevel = parameters[0]
    phone_info = parameters[1]
    _devhandler = parameters[2]

    mtk_class = _devhandler.da_handler.mtk
    da_handler = _devhandler.da_handler
    try:
        if not mtk_class.port.cdc.connect():
            mtk_class.preloader.init()
        else:
            phone_info['cdcInit'] = True
    except Exception:
        phone_info['cantConnect'] = True
    phone_info['chipset'] = (str(mtk_class.config.chipconfig.name) +
                             " (" + str(mtk_class.config.chipconfig.description) + ")")
    self.sendUpdateSignal.emit()
    mtk_class = da_handler.configure_da(mtk_class)
    if mtk_class:
        phone_info['daInit'] = True
        phone_info['chipset'] = (str(mtk_class.config.chipconfig.name) +
                                 " (" + str(mtk_class.config.chipconfig.description) + ")")
        if mtk_class.config.is_brom:
            phone_info['bootMode'] = "Bootrom mode"
        elif mtk_class.config.chipconfig.damode:
            phone_info['bootMode'] = "DA mode"
        else:
            phone_info['bootMode'] = "Preloader mode"
        self.sendUpdateSignal.emit()
    else:
        phone_info['cantConnect'] = True
        self.sendUpdateSignal.emit()


def load_translations(application):
    # Load application translations and the QT base translations for the current locale
    locale = QLocale.system()
    translator = QTranslator(application)
    directory = os.path.dirname(__file__)
    lang = f'mtkclient/gui/i18n/{locale.name()}'
    if locale.name() == "en_NL":
        lang = lang.replace("en_NL", "nl_NL")
    # lang = 'mtkclient/gui/i18n/fr_FR'
    # lang = 'mtkclient/gui/i18n/de_DE'
    # lang = 'mtkclient/gui/i18n/en_GB'
    # lang = 'mtkclient/gui/i18n/es_ES'
    if translator.load(lang, directory):
        application.installTranslator(translator)

    translations_path = QLibraryInfo.path(QLibraryInfo.TranslationsPath)
    base_translator = QTranslator(application)
    if base_translator.load(locale, "qtbase", "_", translations_path):
        application.installTranslator(base_translator)


class MainWindow(QMainWindow):
    def __init__(self, thread, app, devhandler:DeviceHandler, loglevel=logging.INFO):
        super(MainWindow, self).__init__()
        self.loglevel = loglevel
        self.app = app
        self.readpartitionCheckboxes = None
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.fdialog = FDialog(self)
        self.initpixmap()
        self.Status = {}
        self.timeEst = TimeEstim()
        self.timeEstTotal = TimeEstim()
        self.ui.logBox.setWordWrapMode(QTextOption.NoWrap)
        self.ui.menubar.setEnabled(False)
        self.ui.tabWidget.setHidden(True)
        self.ui.partProgress.setHidden(True)
        self.ui.fullProgress.setHidden(True)
        self.ui.readDumpGPTCheckbox.setChecked(True)
        self.ui.connectInfo.setMinimumSize(200, 500)
        self.ui.connectInfo.setMaximumSize(9900, 500)
        self.ui.showdebugbtn.clicked.connect(self.showDebugInfo)
        self.ui.consettingsbtn.clicked.connect(self.selectDaLoader)
        self.ui.consettings2btn.clicked.connect(self.selectPreloader)
        self.ui.iotcheck.clicked.connect(self.selectIoT)
        self.ui.serialportbtn.clicked.connect(self.openserialportdialog)
        self.thread = thread
        self.devhandler = devhandler
        self.readflash = None
        self.daloader = ""
        self.preloader = ""
        self.write_preloader_to_file = False

    def openserialportdialog(self):
        port = SerialPortDialog.get_serial_port()
        if port != "":
            self.devhandler.da_handler.mtk.serialportname = port

    def selectIoT(self):
        self.devhandler.da_handler.mtk.config.iot = self.ui.iotcheck.isChecked()

    def selectDaLoader(self):
        fname = self.fdialog.open("MTKAllInOneDA.bin")
        if fname is not None:
            if os.path.exists(fname):
                self.daloader = fname
                self.devhandler.da_handler.mtk.config.loader = fname
                self.devhandler.da_handler.mtk.daloader.daconfig.dasetup={}
                self.devhandler.da_handler.mtk.daloader.daconfig.parse_da_loader(fname, self.devhandler.da_handler.mtk.daloader.daconfig.dasetup)

    def selectPreloader(self):
        fname = self.fdialog.open("preloader.bin")
        if fname is not None:
            if os.path.exists(fname):
                self.preloader = fname
                self.devhandler.da_handler.mtk.config.preloader_filename = fname
                self.devhandler.da_handler.mtk.config.preloader = open(fname,'rb').read()

    def showDebugInfo(self):
        self.ui.connectInfo.setHidden(True)
        self.ui.tabWidget.setCurrentWidget(self.ui.debugtab)
        self.ui.tabWidget.setHidden(False)

    @Slot()
    def updateState(self):
        lock.acquire()
        done_bytes = 0
        curpart_bytes = (
            self.Status)[f"currentPartitionSize{'Done' if 'currentPartitionSizeDone' in self.Status else ''}"]

        if "allPartitions" in self.Status:
            for partition in self.Status["allPartitions"]:
                if self.Status["allPartitions"][partition]['done'] and partition != self.Status["currentPartition"]:
                    done_bytes = done_bytes + self.Status["allPartitions"][partition]['size']
            done_bytes = curpart_bytes + done_bytes
            total_bytes = self.Status["totalsize"]
            full_percentage_done = int((done_bytes / total_bytes) * 100)
            self.ui.fullProgress.setValue(full_percentage_done)
            timeinfototal = self.timeEstTotal.update(full_percentage_done, 100)
            self.ui.fullProgressText.setText(f"<table width='100%'><tr><td><b>Total:</b> " +
                                             f"{convert_size(done_bytes)} / {convert_size(total_bytes)}" +
                                             f"</td><td align='right'>{timeinfototal}" +
                                             f"{QCoreApplication.translate('main', ' left')}" +
                                             f"</td></tr></table>")
        else:
            part_bytes = self.Status["currentPartitionSize"]
            done_bytes = self.Status["currentPartitionSizeDone"]
            full_percentage_done = int((done_bytes / part_bytes) * 100)
            self.ui.fullProgress.setValue(full_percentage_done)
            timeinfototal = self.timeEstTotal.update(full_percentage_done, 100)
            self.ui.fullProgressText.setText("<table width='100%'><tr><td><b>Total:</b> " +
                                             convert_size(done_bytes) + " / " + convert_size(part_bytes) +
                                             "</td><td align='right'>" +
                                             timeinfototal + QCoreApplication.translate("main",
                                                                                        " left") + "</td></tr></table>")

        if "currentPartitionSize" in self.Status:
            part_bytes = self.Status["currentPartitionSize"]
            part_done = (curpart_bytes / part_bytes) * 100
            self.ui.partProgress.setValue(part_done)
            timeinfo = self.timeEst.update(curpart_bytes, part_bytes)
            txt = ("<table width='100%'><tr><td><b>Current partition:</b> " + self.Status["currentPartition"] +
                   " (" + convert_size(curpart_bytes) + " / " + convert_size(part_bytes) +
                   ") </td><td align='right'>" +
                   timeinfo + QCoreApplication.translate("main", " left") + "</td></tr></table>")
            self.ui.partProgressText.setText(txt)

        lock.release()

    def updateStateAsync(self, toolkit, parameters):
        while not self.Status["done"]:
            # print(self.dumpStatus)
            time.sleep(0.1)
        print("DONE")
        self.ui.readpreloaderbtn.setEnabled(True)
        self.ui.readpartitionsbtn.setEnabled(True)
        self.ui.readboot2btn.setEnabled(True)
        self.ui.readrpmbbtn.setEnabled(True)
        self.ui.readflashbtn.setEnabled(True)

        self.ui.writepartbtn.setEnabled(True)
        self.ui.writeflashbtn.setEnabled(True)
        self.ui.writeboot2btn.setEnabled(True)
        self.ui.writepreloaderbtn.setEnabled(True)
        self.ui.writerpmbbtn.setEnabled(True)

        self.ui.erasepartitionsbtn.setEnabled(True)
        self.ui.eraseboot2btn.setEnabled(True)
        self.ui.erasepreloaderbtn.setEnabled(True)
        self.ui.eraserpmbbtn.setEnabled(True)

    @Slot(int)
    def updateProgress(self, progress):
        try:
            self.Status["currentPartitionSizeDone"] = progress
            self.updateState()
        except Exception:
            pass

    def setdevhandler(self, devhandler):
        self.devhandler = devhandler
        devhandler.sendToProgressSignal.connect(self.updateProgress)
        devhandler.update_status_text.connect(self.update_status_text)

    def initread(self):
        self.readflash = ReadFlashWindow(self.ui, self, self.devhandler.da_handler, self.sendToLog)
        self.thread.sendUpdateSignal.connect(self.updateGui)
        self.readflash.enableButtonsSignal.connect(self.enablebuttons)
        self.readflash.disableButtonsSignal.connect(self.disablebuttons)
        self.ui.readpartitionsbtn.clicked.connect(self.readflash.dumpPartition)
        self.ui.readselectallcheckbox.clicked.connect(self.readflash.selectAll)
        self.ui.readpreloaderbtn.clicked.connect(lambda: self.readflash.dumpFlash("boot1"))
        self.ui.readflashbtn.clicked.connect(lambda: self.readflash.dumpFlash("user"))
        self.ui.readrpmbbtn.clicked.connect(lambda: self.readflash.dumpFlash("rpmb"))
        self.ui.readboot2btn.clicked.connect(lambda: self.readflash.dumpFlash("boot2"))

    def initkeys(self):
        self.genkeys = generateKeysMenu(self.ui, self, self.devhandler.da_handler, self.sendToLog)
        self.ui.generatekeybtn.clicked.connect(self.genkeys.generateKeys)
        self.genkeys.enableButtonsSignal.connect(self.enablebuttons)
        self.genkeys.disableButtonsSignal.connect(self.disablebuttons)

    def initunlock(self):
        self.unlock = UnlockMenu(self.ui, self, self.devhandler.da_handler, self.sendToLog)
        self.ui.unlockbutton.clicked.connect(lambda: self.unlock.unlock("unlock"))
        self.ui.lockbutton.clicked.connect(lambda: self.unlock.unlock("lock"))
        self.unlock.enableButtonsSignal.connect(self.enablebuttons)
        self.unlock.disableButtonsSignal.connect(self.disablebuttons)

    def initerase(self):
        self.eraseflash = EraseFlashWindow(self.ui, self, self.devhandler.da_handler, self.sendToLog)
        self.eraseflash.enableButtonsSignal.connect(self.enablebuttons)
        self.eraseflash.disableButtonsSignal.connect(self.disablebuttons)
        self.ui.eraseselectallpartitionscheckbox.clicked.connect(self.eraseflash.selectAll)
        self.ui.erasepartitionsbtn.clicked.connect(self.eraseflash.erasePartition)
        self.ui.eraserpmbbtn.clicked.connect(lambda: self.eraseflash.eraseFlash("rpmb"))
        self.ui.erasepreloaderbtn.clicked.connect(lambda: self.eraseflash.eraseFlash("boot1"))
        self.ui.eraseboot2btn.clicked.connect(lambda: self.eraseflash.eraseFlash("boot2"))

    def initwrite(self):
        self.writeflash = WriteFlashWindow(self.ui, self, self.devhandler.da_handler, self.sendToLog)
        self.writeflash.enableButtonsSignal.connect(self.enablebuttons)
        self.writeflash.disableButtonsSignal.connect(self.disablebuttons)
        self.ui.writeselectfromdir.clicked.connect(self.writeflash.selectFiles)
        self.ui.writeflashbtn.clicked.connect(lambda: self.writeflash.writeFlash("user"))
        self.ui.writepartbtn.clicked.connect(self.writeflash.writePartition)
        self.ui.writeboot2btn.clicked.connect(lambda: self.writeflash.writeFlash("boot2"))
        self.ui.writepreloaderbtn.clicked.connect(lambda: self.writeflash.writeFlash("boot1"))
        self.ui.writerpmbbtn.clicked.connect(lambda: self.writeflash.writeFlash("rpmb"))

    @Slot(str)
    def update_status_text(self, text):
        self.ui.phoneDebugInfoTextbox.setText(text)

    @Slot()
    def disablebuttons(self):
        self.ui.readpreloaderbtn.setEnabled(False)
        self.ui.readpartitionsbtn.setEnabled(False)
        self.ui.readboot2btn.setEnabled(False)
        self.ui.readrpmbbtn.setEnabled(False)
        self.ui.readflashbtn.setEnabled(False)

        self.ui.writeflashbtn.setEnabled(False)
        self.ui.writepartbtn.setEnabled(False)
        self.ui.writepreloaderbtn.setEnabled(False)
        self.ui.writeboot2btn.setEnabled(False)
        self.ui.writerpmbbtn.setEnabled(False)

        self.ui.eraseboot2btn.setEnabled(False)
        self.ui.erasepreloaderbtn.setEnabled(False)
        self.ui.eraserpmbbtn.setEnabled(False)

        self.ui.generatekeybtn.setEnabled(False)
        self.ui.unlockbutton.setEnabled(False)
        self.ui.lockbutton.setEnabled(False)

    @Slot()
    def enablebuttons(self):
        self.ui.readpreloaderbtn.setEnabled(True)
        self.ui.readpartitionsbtn.setEnabled(True)
        self.ui.readboot2btn.setEnabled(True)
        self.ui.readrpmbbtn.setEnabled(True)
        self.ui.readflashbtn.setEnabled(True)

        self.ui.writeflashbtn.setEnabled(True)
        self.ui.writepartbtn.setEnabled(True)
        self.ui.writepreloaderbtn.setEnabled(True)
        self.ui.writeboot2btn.setEnabled(True)
        self.ui.writerpmbbtn.setEnabled(True)

        self.ui.eraseboot2btn.setEnabled(True)
        self.ui.erasepreloaderbtn.setEnabled(True)
        self.ui.eraserpmbbtn.setEnabled(True)

        self.ui.generatekeybtn.setEnabled(True)
        self.ui.unlockbutton.setEnabled(True)
        self.ui.lockbutton.setEnabled(True)
        self.ui.partProgress.setValue(100)
        self.ui.fullProgress.setValue(100)
        self.ui.fullProgressText.setText("")
        self.ui.partProgressText.setText(self.tr("Done."))
        self.Status = {}

    def getpartitions(self):
        data, guid_gpt = self.devhandler.da_handler.mtk.daloader.get_gpt()
        self.ui.readtitle.setText(QCoreApplication.translate("main",
                                                             "Error reading gpt" if guid_gpt is None
                                                             else "Select partitions to dump"))
        readpartition_list_widget_v_box = QVBoxLayout()
        readpartition_list_widget = QWidget(self)
        readpartition_list_widget.setLayout(readpartition_list_widget_v_box)
        self.ui.readpartitionList.setWidget(readpartition_list_widget)
        self.ui.readpartitionList.setWidgetResizable(True)
        # self.ui.readpartitionList.setGeometry(10,40,380,320)
        self.ui.readpartitionList.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.ui.readpartitionList.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.readpartitionCheckboxes = {}
        for partition in guid_gpt.partentries:
            self.readpartitionCheckboxes[partition.name] = {}
            self.readpartitionCheckboxes[partition.name]['size'] = (partition.sectors * guid_gpt.sectorsize)
            self.readpartitionCheckboxes[partition.name]['box'] = QCheckBox()
            self.readpartitionCheckboxes[partition.name]['box'].setText(
                partition.name + " (" + convert_size(partition.sectors * guid_gpt.sectorsize) + ")")
            readpartition_list_widget_v_box.addWidget(self.readpartitionCheckboxes[partition.name]['box'])

        writepartition_list_widget_v_box = QVBoxLayout()
        writepartition_list_widget = QWidget(self)
        writepartition_list_widget.setLayout(writepartition_list_widget_v_box)
        self.ui.writepartitionList.setWidget(writepartition_list_widget)
        self.ui.writepartitionList.setWidgetResizable(True)
        # self.ui.writepartitionList.setGeometry(10,40,380,320)
        self.ui.writepartitionList.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.ui.writepartitionList.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.writepartitionCheckboxes = {}
        for partition in guid_gpt.partentries:
            self.writepartitionCheckboxes[partition.name] = {}
            self.writepartitionCheckboxes[partition.name]['size'] = (partition.sectors * guid_gpt.sectorsize)
            vb = QVBoxLayout()
            qc = CheckBox()
            qc.setReadOnly(True)
            qc.setText(partition.name + " (" + convert_size(partition.sectors * guid_gpt.sectorsize) + ")")
            hc = QHBoxLayout()
            ll = QLineEdit()
            lb = QPushButton(QCoreApplication.translate("main", "Set"))
            lb.clicked.connect(partial(self.selectWriteFile, partition.name, qc, ll))
            hc.addWidget(ll)
            hc.addWidget(lb)
            vb.addWidget(qc)
            vb.addLayout(hc)
            ll.setDisabled(True)
            self.writepartitionCheckboxes[partition.name]['box'] = [qc, ll, lb]
            writepartition_list_widget_v_box.addLayout(vb)

        erasepartition_list_widget_v_box = QVBoxLayout()
        erasepartition_list_widget = QWidget(self)
        erasepartition_list_widget.setLayout(erasepartition_list_widget_v_box)
        self.ui.erasepartitionList.setWidget(erasepartition_list_widget)
        self.ui.erasepartitionList.setWidgetResizable(True)
        # self.ui.erasepartitionList.setGeometry(10,40,380,320)
        self.ui.erasepartitionList.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.ui.erasepartitionList.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.erasepartitionCheckboxes = {}
        for partition in guid_gpt.partentries:
            self.erasepartitionCheckboxes[partition.name] = {}
            self.erasepartitionCheckboxes[partition.name]['size'] = (partition.sectors * guid_gpt.sectorsize)
            self.erasepartitionCheckboxes[partition.name]['box'] = QCheckBox()
            self.erasepartitionCheckboxes[partition.name]['box'].setText(
                partition.name + " (" + convert_size(partition.sectors * guid_gpt.sectorsize) + ")")
            erasepartition_list_widget_v_box.addWidget(self.erasepartitionCheckboxes[partition.name]['box'])

    def selectWriteFile(self, partition, checkbox, lineedit):
        fname = self.fdialog.open(partition + ".bin")
        if fname is None:
            checkbox.setChecked(False)
            lineedit.setText("")
            lineedit.setDisabled(True)
            return ""
        checkbox.setChecked(True)
        lineedit.setText(fname)
        lineedit.setDisabled(False)
        return fname

    def sendToLog(self, info):
        self.ui.logBox.appendPlainText(time.strftime("[%H:%M:%S", time.localtime()) + "]: " + info)
        self.ui.logBox.verticalScrollBar().setValue(self.ui.logBox.verticalScrollBar().maximum())

    def sendToProgress(self, progress):
        return

    def updateGui(self):
        phoneInfo['chipset'] = phoneInfo['chipset'].replace("()", "")
        if phoneInfo['cdcInit'] and phoneInfo['bootMode'] == "":
            self.ui.phoneInfoTextbox.setText(
                QCoreApplication.translate("main", "Phone detected:\nReading model info..."))
        else:
            self.ui.phoneInfoTextbox.setText(QCoreApplication.translate("main",
                                                                        "Phone detected:\n" + phoneInfo[
                                                                            'chipset'] + "\n" + phoneInfo['bootMode']))
        # Disabled due to graphical steps. Maybe this should come back somewhere else.
        # self.ui.status.setText(QCoreApplication.translate("main","Device detected, please wait.\n" +
        #   "This can take a while..."))
        if phoneInfo['daInit']:
            # self.ui.status.setText(QCoreApplication.translate("main","Device connected :)"))
            self.ui.menubar.setEnabled(True)
            self.pixmap = QPixmap(path.get_images_path("phone_connected.png"))
            self.ui.phoneDebugInfoTextbox.setText("")
            self.ui.pic.setPixmap(self.pixmap)
            self.spinnerAnim.stop()
            self.ui.spinner_pic.setHidden(True)
            self.ui.connectInfo.setHidden(True)
            self.ui.partProgress.setHidden(False)
            self.ui.fullProgress.setHidden(False)
            self.initread()
            self.initkeys()
            self.initunlock()
            self.initerase()
            self.initwrite()
            self.getpartitions()
            self.ui.tabWidget.setCurrentIndex(0)
            self.ui.tabWidget.update()
            self.ui.tabWidget.setHidden(False)

        else:
            if 'cantConnect' in phoneInfo:
                self.ui.phoneInfoTextbox.setText(
                    QCoreApplication.translate("main", "Error initialising. Did you install the drivers?"))
            self.spinnerAnim.start()
            self.ui.spinner_pic.setHidden(False)

    def spinnerAnimRot(self, angle):
        # trans = QTransform()
        # dimension = self.pixmap.width() / math.sqrt(2)
        new_pixmap = self.pixmap.transformed(QTransform().rotate(angle), Qt.SmoothTransformation)
        xoffset = (new_pixmap.width() - self.pixmap.width()) // 2
        yoffset = (new_pixmap.height() - self.pixmap.height()) // 2
        rotated = new_pixmap.copy(xoffset, yoffset, self.pixmap.width(), self.pixmap.height())
        self.ui.spinner_pic.setPixmap(rotated)

    def initpixmap(self):
        # phone spinner
        self.pixmap = QPixmap(path.get_images_path("phone_loading.png")).scaled(96, 96, Qt.KeepAspectRatio,
                                                                                Qt.SmoothTransformation)
        self.pixmap.setDevicePixelRatio(2)
        self.ui.spinner_pic.setPixmap(self.pixmap)
        self.ui.spinner_pic.show()

        nfpixmap = QPixmap(path.get_images_path("phone_notfound.png"))
        self.ui.pic.setPixmap(nfpixmap)

        logo = QPixmap(path.get_images_path("logo_256.png"))
        self.ui.logoPic.setPixmap(logo)

        init_steps = QPixmap(path.get_images_path("initsteps.png"))
        self.ui.initStepsImage.setPixmap(init_steps)

        self.spinnerAnim = QVariantAnimation()
        self.spinnerAnim.setDuration(3000)
        self.spinnerAnim.setStartValue(0)
        self.spinnerAnim.setEndValue(360)
        self.spinnerAnim.setLoopCount(-1)
        self.spinnerAnim.valueChanged.connect(self.spinnerAnimRot)

        self.ui.spinner_pic.setHidden(True)


def main():
    # Enable nice 4K Scaling
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"

    # Init the app window
    app = QApplication(sys.argv)
    load_translations(app)

    loglevel = logging.INFO
    devhandler = DeviceHandler(parent=app, preloader=None, loader=None, loglevel=loglevel)
    thread = asyncThread(parent=app, n=0, function=getDevInfo, parameters=[loglevel, phoneInfo, devhandler])
    win = MainWindow(thread,app, devhandler, loglevel)

    icon = QIcon()
    icon.addFile(path.get_images_path('logo_32.png'), QSize(32, 32))
    icon.addFile(path.get_images_path('logo_64.png'), QSize(64, 64))
    icon.addFile(path.get_images_path('logo_256.png'), QSize(256, 256))
    icon.addFile(path.get_images_path('logo_512.png'), QSize(512, 512))
    app.setWindowIcon(icon)
    win.setWindowIcon(icon)
    if sys.platform.startswith('win'):
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('MTKTools.Gui')
    dpiMultiplier = win.logicalDpiX()
    if dpiMultiplier == 72:
        dpiMultiplier = 2
    else:
        dpiMultiplier = 1
    addTopMargin = 20
    if sys.platform.startswith('darwin'):  # MacOS has the toolbar in the top bar insted of in the app...
        addTopMargin = 0
    win.setWindowTitle("MTKClient - Version 2.1.3")
    # lay = QVBoxLayout(self)

    win.show()
    # win.setFixedSize(746, 400 + addTopMargin)

    # Device setup
    devhandler.sendToLogSignal.connect(win.sendToLog)
    # Get the device info

    thread.sendToLogSignal.connect(win.sendToLog)
    thread.sendUpdateSignal.connect(win.updateGui)
    thread.sendToProgressSignal.connect(win.sendToProgress)
    thread.start()
    win.setdevhandler(devhandler)

    # Run loop the app
    app.exec()
    # Prevent thread from not being closed and call error end codes
    thread.terminate()
    thread.wait()


if __name__ == '__main__':
    main()
