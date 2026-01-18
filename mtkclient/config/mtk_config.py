import os
import logging
from mtkclient.Library.gui_utils import LogBase
from mtkclient.config.brom_config import Chipconfig, DAmodes, hwconfig

try:
    from PySide6.QtCore import QObject
except ImportError:
    class QObject:
        def tr(self, arg):
            return
    pass


class MtkConfig(metaclass=LogBase):
    def __init__(self, loglevel=logging.INFO, gui=None, guiprogress=None, update_status_text=None):
        self.peek = None
        self.gui = gui
        self.loglevel = loglevel
        self.guiprogress = guiprogress
        self.update_status_text = update_status_text
        self.pid = -1
        self.cid = None
        self.vid = -1
        self.var1 = 0xA
        self.auth = None
        self.cert = None
        self.is_brom = False
        self.skipwdt = False
        self.interface = -1
        self.readsocid = False
        self.enforcecrash = False
        self.debugmode = False
        self.preloader = None
        self.write_preloader_to_file = False
        self.preloader_filename = None
        self.payloadfile = None
        self.loader = None
        self.iot = False
        self.internal_flash = True
        self.gpt_file = None
        self.tr = QObject().tr
        self.ptype = "kamakiri2"
        self.generatekeys = None
        self.daconfig = None
        self.bmtflag = None
        self.bmtblockcount = None
        self.bmtpartsize = None
        self.packetsizeread = 0x400
        self.flashinfo = None
        self.readsize = 0
        self.sparesize = 16
        self.plcap = None
        self.blver = -2
        self.gcpu = None
        self.pagesize = 512
        self.SECTOR_SIZE_IN_BYTES = 4096  # fixme
        self.baudrate = 115200
        self.cpu = ""
        self.hwcode = None
        self.meid = None
        self.socid = None
        self.target_config = None
        self.chipconfig = Chipconfig()
        self.gpt_settings = None
        self.hwparam = None
        self.hwparam_path = "."
        self.sram = None
        self.dram = None
        self.otp = None
        self.stock = False
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)
        self.reconnect = True
        self.uartloglevel = 2
        self.hwver = 0xca00
        self.swver = 0

    def set_peek(self, peek):
        self.peek = peek

    def set_da_config(self, daconfig):
        self.daconfig = daconfig

    def set_gui_status(self, status):
        if self.update_status_text is not None:
            self.update_status_text.emit(status)

    def get_hwcode(self):
        if self.hwcode is None:
            if self.peek is not None:
                self.hwcode = self.peek(0x800000, 0x4)
                self.set_hwcode(self.hwcode)
        return self.hwcode

    def get_cid(self):
        if self.cid is None:
            self.cid = self.hwparam.loadsetting("cid")
        return self.cid

    def set_cid(self, cid):
        self.hwparam.writesetting("cid", cid.hex())
        self.cid = cid.hex()

    def set_hwcode(self, hwcode):
        self.hwparam.writesetting("hwcode", hex(hwcode))

    def set_meid(self, meid):
        self.meid = meid
        self.hwparam.writesetting("meid", meid.hex())

    def get_otp(self):
        if self.otp is None:
            self.otp = self.hwparam.loadsetting("otp")
        if self.preloader is not None:
            idx = self.preloader.find(b"\x4D\x4D\x4D\x01\x30")
            if idx != -1:
                self.otp = self.preloader[idx + 0xC:idx + 0xC + 32]
                self.hwparam.writesetting("otp", self.otp.hex())
        if self.otp is None:
            self.otp = 32 * b"\x00"
        return self.otp

    def set_otp(self, otp):
        self.otp = otp
        self.hwparam.writesetting("otp", otp.hex())

    def get_meid(self):
        if self.meid is None:
            if self.peek is not None:
                if self.chipconfig.meid_addr is not None:
                    self.meid = self.peek(self.chipconfig.meid_addr, 0x10)
                self.meid = self.peek(0x1008ec, 0x10)
                # self.set_meid(self.meid)
        return self.meid

    def set_socid(self, socid):
        self.socid = socid
        self.hwparam.writesetting("socid", socid.hex())

    def get_socid(self):
        if self.socid is None:
            if self.chipconfig.socid_addr is not None:
                if self.peek is not None:
                    self.socid = self.peek(0x1008ec, 0x20)
                    self.set_socid(self.socid)
        return self.socid

    def set_hwparam_path(self, path):
        if path is not None:
            self.hwparam_path = path

    def default_values(self, hwcode):
        if self.chipconfig.var1 is None:
            self.chipconfig.var1 = 0xA
        if self.chipconfig.watchdog is None:
            self.chipconfig.watchdog = 0x10007000
        if self.chipconfig.uart is None:
            self.chipconfig.uart = 0x11002000
        if self.chipconfig.brom_payload_addr is None:
            self.chipconfig.brom_payload_addr = 0x100A00
        if self.chipconfig.da_payload_addr is None:
            self.chipconfig.da_payload_addr = 0x200000
        if self.chipconfig.cqdma_base is None:
            self.chipconfig.cqdma_base = None
        if self.chipconfig.gcpu_base is None:
            self.chipconfig.gcpu_base = None
        if self.chipconfig.sej_base is None:
            self.chipconfig.sej_base = None
        if self.chipconfig.dacode is None:
            self.chipconfig.dacode = hwcode
        if self.chipconfig.ap_dma_mem is None:
            self.chipconfig.ap_dma_mem = 0x11000000 + 0x1A0
        if self.chipconfig.damode is None:
            self.chipconfig.damode = DAmodes.LEGACY
        if self.chipconfig.dxcc_base is None:
            self.chipconfig.dxcc_base = None
        if self.chipconfig.meid_addr is None:
            self.chipconfig.meid_addr = None
        if self.chipconfig.socid_addr is None:
            self.chipconfig.socid_addr = None
        if self.chipconfig.prov_addr is None:
            self.chipconfig.prov_addr = None

    def init_hwcode(self, hwcode):
        self.hwcode = hwcode
        if hwcode in hwconfig:
            self.chipconfig = hwconfig[hwcode]
        else:
            self.chipconfig = Chipconfig()
        self.default_values(hwcode)

    def get_watchdog_addr(self):
        wdt = self.chipconfig.watchdog
        if wdt != 0:
            if wdt == 0x10007000:
                return [wdt, 0x22000064]
            elif wdt == 0x10212000:
                return [wdt, 0x22000000]
            elif wdt == 0x10211000:
                return [wdt, 0x22000064]
            elif wdt == 0x10007400:
                return [wdt, 0x22000000]
            elif wdt == 0xC0000000:
                return [wdt, 0x2264]
            elif wdt == 0xA0030000:
                return [wdt, 0x2200]
            elif wdt == 0x2200:
                if self.hwcode == 0x6276 or self.hwcode == 0x8163:
                    return [wdt, 0x610C0000]
                elif self.hwcode == 0x6251 or self.hwcode == 0x6516:
                    return [wdt, 0x80030000]
                elif self.hwcode == 0x6255:
                    return [wdt, 0x701E0000]
                else:
                    return [wdt, 0x70025000]
            else:
                return [wdt, 0x22000064]

    def bmtsettings(self, hwcode):
        bmtflag = 1
        bmtblockcount = 0
        bmtpartsize = 0
        if hwcode in [0x6592, 0x8127, 0x6571]:
            if self.daconfig.storage.flashtype == "emmc":
                bmtflag = 1
                bmtblockcount = 0xA8
                bmtpartsize = 0x1500000
        elif hwcode in [0x6570, 0x8167, 0x6580, 0x6735, 0x6753, 0x6755, 0x6752, 0x6595, 0x6795, 0x6767, 0x6797, 0x8163,
                        0x8127]:
            bmtflag = 1
            bmtpartsize = 0
        elif hwcode in [0x6571]:
            if self.daconfig.storage.flashtype == "nand":
                bmtflag = 0
                bmtblockcount = 0x38
                bmtpartsize = 0xE00000
            elif self.daconfig.storage.flashtype == "emmc":
                bmtflag = 1
                bmtblockcount = 0xA8
                bmtpartsize = 0x1500000
        elif hwcode in [0x6575]:
            if self.daconfig.storage.flashtype == "nand":
                bmtflag = 0
                bmtblockcount = 0x50
            elif self.daconfig.storage.flashtype == "emmc":
                bmtflag = 1
                bmtblockcount = 0xA8
                bmtpartsize = 0x1500000
        elif hwcode in [0x6582]:
            if self.daconfig.storage.flashtype == "emmc":
                bmtflag = 2
                bmtblockcount = 0xA8
                bmtpartsize = 0x1500000
        elif hwcode in [0x6572]:
            if self.daconfig.storage.flashtype == "nand":
                bmtflag = 0
                bmtpartsize = 0x1500000
                bmtblockcount = 0xA8
            elif self.daconfig.storage.flashtype == "emmc":
                bmtflag = 0
                bmtpartsize = 0xA8
                bmtblockcount = 0x50
        elif hwcode in [0x6577, 0x6583, 0x6589]:
            if self.daconfig.storage.flashtype == "nand":
                bmtflag = 0
                bmtpartsize = 0xA00000
                bmtblockcount = 0xA8
        self.bmtflag = bmtflag
        self.bmtblockcount = bmtblockcount
        self.bmtpartsize = bmtpartsize
        return bmtflag, bmtblockcount, bmtpartsize
