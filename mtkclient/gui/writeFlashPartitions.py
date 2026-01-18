import os
import sys
from unittest import mock
from PySide6.QtCore import QObject, Signal
from mtkclient.gui.toolkit import trap_exc_during_debug, asyncThread, FDialog

sys.excepthook = trap_exc_during_debug


class WriteFlashWindow(QObject):
    enableButtonsSignal = Signal()
    disableButtonsSignal = Signal()

    def __init__(self, ui, parent, da_handler, sendToLog):  # def __init__(self, *args, **kwargs):
        super(WriteFlashWindow, self).__init__(parent)
        self.mtkClass = da_handler.mtk
        self.parent = parent
        self.sendToLog = sendToLog
        self.fdialog = FDialog(parent)
        self.da_handler = da_handler
        self.ui = ui

    def writePartDone(self):
        self.sendToLogSignal.emit("write done!")

    def selectFiles(self):
        self.folder = self.fdialog.opendir(self.tr("Select input directory"))
        if self.folder:
            for partition in self.parent.writepartitionCheckboxes:
                checkbox, lineedit, button = self.parent.writepartitionCheckboxes[partition]['box']
                for root, dirs, files in os.walk(self.folder):
                    for file in files:
                        if file in [partition + ".bin", partition + ".img"]:
                            lineedit.setText(os.path.join(root, file))
                            lineedit.setDisabled(False)
                            checkbox.setChecked(True)
                            break
                    break

    def writePartition(self):
        self.disableButtonsSignal.emit()
        self.parent.Status["rpmb"] = False
        thread = asyncThread(parent=self, n=0, function=self.writePartitionAsync, parameters=[])
        thread.sendToLogSignal.connect(self.sendToLog)
        thread.sendUpdateSignal.connect(self.parent.updateState)
        thread.sendToProgressSignal.connect(self.parent.updateProgress)
        thread.start()

    def openFile(self, partition, checkbox, lineedit):
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

    def writePartitionAsync(self, toolkit, parameters):
        self.parent.timeEst.init()
        self.parent.timeEstTotal.init()
        self.sendToLogSignal = toolkit.sendToLogSignal
        toolkit.sendToLogSignal.emit("test")
        # partitionname = args.partitionname
        # parttype = args.parttype
        # filename = args.filename
        # print(self.partitionCheckboxes)
        self.parent.Status["done"] = False
        thread = asyncThread(self.parent.parent(), 0, self.parent.updateStateAsync, [])
        thread.sendUpdateSignal.connect(self.parent.updateState)
        thread.sendToProgressSignal.connect(self.parent.updateProgress)
        thread.start()
        self.disableButtonsSignal.emit()
        # calculate total bytes
        self.parent.Status["allPartitions"] = {}
        totalsize = 0
        for partition in self.parent.writepartitionCheckboxes:
            checkbox, lineedit, button = self.parent.writepartitionCheckboxes[partition]['box']
            if checkbox.isChecked():
                totalsize += min(self.parent.writepartitionCheckboxes[partition]['size'],
                                 os.stat(lineedit.text()).st_size)
        self.parent.Status["totalsize"] = totalsize

        for partition in self.parent.writepartitionCheckboxes:
            checkbox, lineedit, button = self.parent.writepartitionCheckboxes[partition]['box']
            if checkbox.isChecked():
                size = min(self.parent.writepartitionCheckboxes[partition]['size'], os.stat(lineedit.text()).st_size)
                self.parent.Status["allPartitions"][partition] = {"size": size,
                                                                  "done": False}
        for partition in self.parent.writepartitionCheckboxes:
            checkbox, lineedit, button = self.parent.writepartitionCheckboxes[partition]['box']
            if checkbox.isChecked():
                variables = mock.Mock()
                variables.partitionname = partition
                variables.filename = lineedit.text()
                variables.parttype = "user"
                size = min(self.parent.writepartitionCheckboxes[partition]['size'], os.stat(variables.filename).st_size)
                self.parent.Status["currentPartitionSize"] = size
                self.parent.Status["currentPartition"] = partition
                self.parent.Status["currentPartitionFile"] = variables.filename
                self.da_handler.close = self.writePartDone  # Ignore the normally used sys.exit
                self.da_handler.handle_da_cmds(self.mtkClass, "w", variables)
                self.parent.Status["allPartitions"][partition]['done'] = True
                # MtkTool.cmd_stage(mtkClass, None, None, None, False)
        self.parent.Status["done"] = True
        thread.wait()
        self.enableButtonsSignal.emit()

    def writeFlash(self, parttype):
        self.writeFile = self.fdialog.open(parttype + ".bin")
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
        self.disableButtonsSignal.emit()
        if self.writeFile:
            thread = asyncThread(parent=self, n=0, function=self.writeFlashAsync, parameters=[parttype])
            thread.sendToLogSignal.connect(self.sendToLog)
            thread.sendUpdateSignal.connect(self.parent.updateState)
            thread.start()
        else:
            self.enableButtonsSignal.emit()

    def writeFlashAsync(self, toolkit, parameters):
        self.parent.timeEst.init()
        self.sendToLogSignal = toolkit.sendToLogSignal
        self.parent.Status["done"] = False
        thread = asyncThread(self.parent.parent(), 0, self.parent.updateStateAsync, [])
        thread.sendUpdateSignal.connect(self.parent.updateState)
        thread.sendToProgressSignal.connect(self.parent.updateProgress)
        thread.start()
        variables = mock.Mock()
        variables.filename = self.writeFile
        variables.parttype = None
        self.parent.Status["writeFile"] = variables.filename
        self.parent.Status["currentPartitionSize"] = os.stat(variables.filename).st_size
        self.parent.Status["currentPartition"] = variables.parttype
        self.da_handler.close = self.writePartDone  # Ignore the normally used sys.exit
        if "rpmb" in parameters:
            self.mtkClass.daloader.write_rpmb(variables.filename)
        else:
            if "boot1" in parameters:
                variables.parttype = "boot1"
            elif "boot2" in parameters:
                variables.parttype = "boot2"
            else:
                variables.parttype = "user"
            self.da_handler.handle_da_cmds(self.mtkClass, "wf", variables)
        self.parent.Status["done"] = True
        thread.wait()
        self.enableButtonsSignal.emit()
