import math
import os
import sys
import time
import datetime as dt
from PySide6.QtCore import Signal, QThread, Slot, Property
from PySide6.QtWidgets import QFileDialog, QCheckBox
from traceback import print_exception
from mtkclient.config.payloads import PathConfig


class TimeEstim:
    @staticmethod
    def calcProcessTime(starttime, cur_iter, max_iter):
        telapsed = time.time() - starttime
        if telapsed > 0 and cur_iter > 0:
            testimated = (telapsed / cur_iter) * max_iter
            finishtime = starttime + testimated
            finishtime = dt.datetime.fromtimestamp(finishtime).strftime("%H:%M:%S")  # in time
            return int(telapsed), int(testimated - telapsed), finishtime
        else:
            return 0, 0, ""

    def init(self):
        self.prog = 0
        self.start = time.time()
        self.progtime = time.time()
        self.progpos = 0

    def update(self, pos, total):
        t0 = time.time()
        telapsed, lefttime, finishtime = self.calcProcessTime(self.start, pos, total)
        hinfo = ""
        if lefttime > 0:
            sec = lefttime
            if sec > 60:
                minutes = sec // 60
                sec = sec % 60
                if minutes > 60:
                    h = minutes // 24
                    minutes = minutes % 24
                    hinfo = "%02dh:%02dm:%02ds" % (h, minutes, sec)
                else:
                    hinfo = "%02dm:%02ds" % (minutes, sec)
            else:
                hinfo = "%02ds" % sec

        self.prog = pos
        self.progpos = pos
        self.progtime = t0
        return hinfo


class CheckBox(QCheckBox):
    def __init__(self, *args):
        super(CheckBox, self).__init__(*args)
        self._readOnly = False

    def isReadOnly(self):
        return self._readOnly

    def mousePressEvent(self, event):
        if self.isReadOnly():
            event.accept()
        else:
            super(CheckBox, self).mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self.isReadOnly():
            event.accept()
        else:
            super(CheckBox, self).mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self.isReadOnly():
            event.accept()
        else:
            super(CheckBox, self).mouseReleaseEvent(event)

    def keyPressEvent(self, event):
        if self.isReadOnly():
            event.accept()
        else:
            super(CheckBox, self).keyPressEvent(event)

    @Slot(bool)
    def setReadOnly(self, state):
        self._readOnly = state

    readOnly = Property(bool, isReadOnly, setReadOnly)


def convert_size(size_bytes):
    if size_bytes <= 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"


class asyncThread(QThread):
    sendToLogSignal = Signal(str)
    sendUpdateSignal = Signal()
    sendToProgressSignal = Signal(int)
    update_status_text = Signal(str)

    def __init__(self, parent, n, function, parameters):
        super(asyncThread, self).__init__(parent)
        # self.n = n
        self.parameters = parameters
        self.function = function

    def run(self):
        self.function(self, self.parameters)


class FDialog:
    def __init__(self, parent):
        pc = PathConfig()
        self.parent = parent
        self.fdialog = QFileDialog(parent)
        self.lastpath = os.path.dirname(os.path.dirname(pc.scriptpath))
        self.fdialog.setDirectory(self.lastpath)

    def save(self, filename=""):
        fname = os.path.join(self.lastpath, filename)
        self.fdialog.setDirectory(self.lastpath)
        self.fdialog.selectFile(fname)
        ret = self.fdialog.getSaveFileName(self.parent, self.parent.tr("Select output file"), fname,
                                           "Binary dump (*.bin)")
        if ret:
            fname = ret[0]
            if fname != "":
                self.lastpath = os.path.dirname(fname)
                return fname
        return None

    def open(self, filename=""):
        fname = os.path.join(self.lastpath, filename)
        self.fdialog.setDirectory(self.lastpath)
        self.fdialog.selectFile(fname)
        ret = self.fdialog.getOpenFileName(self.parent, self.parent.tr("Select input file"),
                                           fname, "Binary dump (*.bin)")
        if ret:
            if isinstance(ret, tuple):
                fname = os.path.normpath(ret[0])  # fixes backslash problem on windows
                if ret[0] != "":
                    self.lastpath = os.path.dirname(fname)
                    return fname
        return None

    def opendir(self, caption):
        options = QFileDialog.Options()
        if sys.platform.startswith('freebsd') or sys.platform.startswith('linux'):
            options |= QFileDialog.DontUseNativeDialog
            options |= QFileDialog.DontUseCustomDirectoryIcons
        fname = os.path.join(self.lastpath)
        self.fdialog.setDirectory(self.lastpath)
        fdir = self.fdialog.getExistingDirectory(self.parent, self.parent.tr(caption), fname, options=options)
        fdir = os.path.normpath(fdir)  # fixes backslash problem on windows
        if fdir != "" and fdir != ".":
            self.lastpath = fdir
            return fdir
        return None


def trap_exc_during_debug(type_, value, traceback):
    print(print_exception(type_, value, traceback), flush=True)
    # sendToLog("Error: "+str(value))
    # when app raises uncaught exception, print info
    # print("OH NO")
    # print(args)
    # print(traceback.print_tb(exc_traceback))
    # print(traceback.format_exc())
