import sys

from unittest import mock
from PySide6.QtCore import QObject, Signal
from mtkclient.gui.toolkit import FDialog
from mtkclient.gui.toolkit import trap_exc_during_debug, asyncThread

sys.excepthook = trap_exc_during_debug


class EraseFlashWindow(QObject):
    enableButtonsSignal = Signal()
    disableButtonsSignal = Signal()

    def __init__(self, ui, parent, da_handler, sendToLog):  # def __init__(self, *args, **kwargs):
        super(EraseFlashWindow, self).__init__(parent)
        self.mtkClass = da_handler.mtk
        self.parent = parent
        self.sendToLog = sendToLog
        self.fdialog = FDialog(parent)
        self.da_handler = da_handler
        self.ui = ui

    def erasePartDone(self):
        self.sendToLogSignal.emit("erase done!")

    def selectAll(self):
        if self.ui.eraseselectallpartitionscheckbox.isChecked():
            for partition in self.parent.erasepartitionCheckboxes:
                self.parent.erasepartitionCheckboxes[partition]['box'].setChecked(True)
        else:
            for partition in self.parent.erasepartitionCheckboxes:
                self.parent.erasepartitionCheckboxes[partition]['box'].setChecked(False)

    def erasePartition(self):
        self.parent.Status["rpmb"] = False
        self.ui.erasepartitionsbtn.setEnabled(False)
        thread = asyncThread(parent=self.parent, n=0, function=self.erasePartitionAsync, parameters=[])
        thread.sendToLogSignal.connect(self.sendToLog)
        thread.update_status_text.connect(self.parent.update_status_text)
        thread.sendUpdateSignal.connect(self.parent.updateState)
        thread.sendToProgressSignal.connect(self.parent.updateProgress)
        thread.start()

    def eraseFlash(self, parttype):
        self.parent.Status["rpmb"] = False
        if parttype == "user":
            self.flashsize = self.mtkClass.daloader.daconfig.storage.flashsize
        elif parttype == "rpmb":
            self.parent.Status["rpmb"] = True
            if self.mtkClass.daloader.daconfig.storage.flashtype == "ufs":
                self.flashsize = self.mtkClass.daloader.daconfig.storage.ufs.lu1_size
            else:
                self.flashsize = self.mtkClass.daloader.daconfig.storage.emmc.rpmb_size
        elif parttype == "boot1":
            if self.mtkClass.daloader.daconfig.storage.flashtype == "ufs":
                self.flashsize = self.mtkClass.daloader.daconfig.storage.ufs.lu1_size
            else:
                self.flashsize = self.mtkClass.daloader.daconfig.storage.emmc.boot1size
        elif parttype == "boot2":
            if self.mtkClass.daloader.daconfig.storage.flashtype == "ufs":
                self.flashsize = self.mtkClass.daloader.daconfig.storage.ufs.lu2_size
            else:
                self.flashsize = self.mtkClass.daloader.daconfig.storage.emmc.boot2size
        self.parttype = parttype
        self.parent.Status["totalsize"] = self.flashsize
        self.parent.Status["currentPartitionSize"] = self.flashsize
        self.parent.Status["currentPartition"] = parttype
        self.parent.disablebuttons()
        thread = asyncThread(parent=self, n=0, function=self.eraseFlashAsync, parameters=[parttype])
        thread.sendToLogSignal.connect(self.sendToLog)
        thread.sendUpdateSignal.connect(self.parent.updateState)
        thread.start()

    def eraseFlashAsync(self, toolkit, parameters):
        self.parent.timeEst.init()
        self.sendToLogSignal = toolkit.sendToLogSignal
        self.parent.Status["done"] = False
        thread = asyncThread(self.parent.parent(), 0, self.parent.updateStateAsync, [])
        thread.sendUpdateSignal.connect(self.parent.updateState)
        thread.update_status_text.connect(self.parent.update_status_text)
        thread.sendToProgressSignal.connect(self.parent.updateProgress)
        thread.start()
        self.disableButtonsSignal.emit()
        variables = mock.Mock()
        variables.parttype = None
        self.parent.Status["writeFile"] = variables.filename
        self.parent.Status["currentPartitionSize"] = self.flashsize
        self.parent.Status["currentPartition"] = variables.parttype
        self.da_handler.close = self.erasePartDone  # Ignore the normally used sys.exit
        if "rpmb" in parameters:
            self.mtkClass.daloader.read_rpmb(variables.filename)
        else:
            if "boot1" in parameters:
                variables.parttype = "boot1"
            elif "boot2" in parameters:
                variables.parttype = "boot2"
            else:
                variables.parttype = "user"
            self.da_handler.handle_da_cmds(self.mtkClass, "ef", variables)
        self.parent.Status["done"] = True
        thread.wait()
        self.enableButtonsSignal.emit()

    def erasePartitionAsync(self, toolkit, parameters):
        self.parent.timeEst.init()
        self.parent.timeEstTotal.init()
        self.sendToLogSignal = toolkit.sendToLogSignal
        toolkit.sendToLogSignal.emit("test")
        self.parent.Status["done"] = False
        thread = asyncThread(self.parent.parent(), 0, self.parent.updateStateAsync, [])
        thread.sendUpdateSignal.connect(self.parent.updateState)
        thread.sendToProgressSignal.connect(self.parent.updateProgress)
        thread.start()
        self.disableButtonsSignal.emit()
        # calculate total bytes
        self.parent.Status["allPartitions"] = {}
        totalsize = 0
        for partition in self.parent.erasepartitionCheckboxes:
            if self.parent.erasepartitionCheckboxes[partition]['box'].isChecked():
                totalsize += self.parent.erasepartitionCheckboxes[partition]['size']
        self.parent.Status["totalsize"] = totalsize
        for partition in self.parent.erasepartitionCheckboxes:
            if self.parent.erasepartitionCheckboxes[partition]['box'].isChecked():
                self.parent.Status["allPartitions"][partition] = {
                    "size": self.parent.erasepartitionCheckboxes[partition]['size'],
                    "done": False}
        for partition in self.parent.erasepartitionCheckboxes:
            if self.parent.erasepartitionCheckboxes[partition]['box'].isChecked():
                variables = mock.Mock()
                variables.partitionname = partition
                variables.parttype = None
                self.parent.Status["currentPartitionSize"] = self.parent.erasepartitionCheckboxes[partition]['size']
                self.parent.Status["currentPartition"] = partition
                self.da_handler.close = self.erasePartDone  # Ignore the normally used sys.exit
                self.da_handler.handle_da_cmds(self.mtkClass, "e", variables)
                self.parent.Status["allPartitions"][partition]['done'] = True
                # MtkTool.cmd_stage(mtkClass, None, None, None, False)
        self.parent.Status["done"] = True
        thread.wait()
        self.enableButtonsSignal.emit()
