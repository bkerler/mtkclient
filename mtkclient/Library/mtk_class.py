#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2025.
# Licensed under GPLv3 License
import os
import logging
from struct import unpack
from mtkclient.config.usb_ids import default_ids
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.pltools import PLTools
from mtkclient.Library.mtk_preloader import Preloader
from mtkclient.Library.DA.mtk_daloader import DAloader
from mtkclient.Library.Port import Port
from mtkclient.Library.gui_utils import LogBase, logsetup
from mtkclient.Library.utils import find_binary
from mtkclient.Library.error import ErrorHandler


def split_by_n(seq, unit_count):
    """A generator to divide a sequence into chunks of n units."""
    while seq:
        yield seq[:unit_count]
        seq = seq[unit_count:]


class Mtk(metaclass=LogBase):
    def __init__(self, config, loglevel=logging.INFO, serialportname: str = None, preinit=True):
        self.config = config
        self.loader = config.loader
        self.vid = config.vid
        self.pid = config.pid
        self.interface = config.interface
        self.pathconfig = PathConfig()
        self.reinited = False
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, loglevel,
                                                                                  config.gui)
        self.eh = ErrorHandler()
        self.serialportname = serialportname
        if preinit:
            self.setup(self.vid, self.pid, self.interface, serialportname)

    def patch_preloader_security_da1(self, data):
        patched = False
        data = bytearray(data)
        patches = [
            ("A3687BB12846", "0123A3602846", "oppo security"),
            ("B3F5807F01D1", "B3F5807F01D14FF000004FF000007047", "mt6739 c30"),
            ("B3F5807F04BF4FF4807305F011B84FF0FF307047", "B3F5807F04BF4FF480734FF000004FF000007047", "regular"),
            ("10B50C680268", "10B5012010BD", "ram blacklist"),
            ("08B5104B7B441B681B68", "00207047000000000000", "seclib_sec_usbdl_enabled"),
            ("5072656C6F61646572205374617274", "50617463686564204C205374617274", "Patched loader msg"),
            ("F0B58BB002AE20250C460746", "002070470000000000205374617274", "sec_img_auth"),
            ("FFC0F3400008BD", "FF4FF0000008BD", "get_vfy_policy"),
            ("040007C0", "00000000", "hash_check"),
            ("CCF20709", "4FF00009", "hash_check2"),
            (b"\x14\x2C\xF6.\xFE\xE7", b"\x00\x00\x00\x00\x00\x00", "hash_check3")
        ]
        i = 0
        for patchval in patches:
            if type(patchval[0]) is bytes:
                idx = find_binary(data, patchval[0])
                if idx is None:
                    idx = -1
                else:
                    data[idx:idx + len(patchval)] = patchval
                    self.info(f'Patched "{patchval[2]}" in preloader')
                    patched = True
            else:
                pattern = bytes.fromhex(patchval[0])
                idx = data.find(pattern)
                if idx != -1:
                    patch = bytes.fromhex(patchval[1])
                    data[idx:idx + len(patch)] = patch
                    self.info(f'Patched "{patchval[2]}" in preloader')
                    patched = True
                    # break
            i += 1
        if not patched:
            self.warning("Failed to patch preloader security")
        else:
            # with open("preloader.patched", "wb") as wf:
            #    wf.write(data)
            #    print("Patched !")
            # self.info(f"Patched preloader security: {hex(i)}")
            data = data
        return data

    def patch_preloader_security_da2(self, data):
        patched = False
        data = bytearray(data)
        patches = [
            ("A3687BB12846", "0123A3602846", "oppo security"),
            ("B3F5807F01D1", "B3F5807F01D14FF000004FF000007047", "mt6739 c30"),
            ("B3F5807F04BF4FF4807305F011B84FF0FF307047", "B3F5807F04BF4FF480734FF000004FF000007047", "regular"),
            ("10B50C680268", "10B5012010BD", "ram blacklist"),
            ("08B5104B7B441B681B68", "00207047000000000000", "seclib_sec_usbdl_enabled"),
            ("5072656C6F61646572205374617274", "50617463686564204C205374617274", "Patched loader msg"),
            ("F0B58BB002AE20250C460746", "002070470000000000205374617274", "sec_img_auth"),
            ("FFC0F3400008BD", "FF4FF0000008BD", "get_vfy_policy")
        ]
        i = 0
        for patchval in patches:
            pattern = bytes.fromhex(patchval[0])
            idx = data.find(pattern)
            if idx != -1:
                patch = bytes.fromhex(patchval[1])
                data[idx:idx + len(patch)] = patch
                self.info(f'Patched "{patchval[2]}" in preloader')
                patched = True
                # break
            i += 1
        if not patched:
            self.warning("Failed to patch preloader security")
        else:
            # with open("preloader.patched", "wb") as wf:
            #    wf.write(data)
            #    print("Patched !")
            # self.info(f"Patched preloader security: {hex(i)}")
            data = data
        return data

    def parse_preloader(self, preloader):
        if isinstance(preloader, str):
            if os.path.exists(preloader):
                with open(preloader, "rb") as rf:
                    data = rf.read()
        else:
            data = preloader
        data = bytearray(data)
        magic = unpack("<I", data[:4])[0]
        if magic == 0x014D4D4D:
            self.info("Valid preloader detected.")
            daaddr = unpack("<I", data[0x1C:0x20])[0]
            # dasize = unpack("<I", data[0x20:0x24])[0]
            # maxsize = unpack("<I", data[0x24:0x28])[0]
            # content_offset = unpack("<I", data[0x28:0x2C])[0]
            # sig_length = unpack("<I", data[0x2C:0x30])[0]
            jump_offset = unpack("<I", data[0x30:0x34])[0]
            daaddr = jump_offset + daaddr
            dadata = data[jump_offset:]
        else:
            self.warning("Preloader detected as shellcode, might fail to run.")
            daaddr = self.config.chipconfig.da_payload_addr
            dadata = data
        return daaddr, dadata

    def setup(self, vid=None, pid=None, interface=None, serialportname: str = None):
        if vid is None:
            vid = self.vid
        if pid is None:
            pid = self.pid
        if interface is None:
            interface = self.interface
        if vid != -1 and pid != -1:
            if interface == -1:
                for dev in default_ids:
                    if dev[0] == vid and dev[1] == pid:
                        interface = dev[2]
                        break
            portconfig = [[vid, pid, interface]]
        else:
            portconfig = default_ids
        self.port = Port(mtk=self, portconfig=portconfig, serialportname=serialportname, loglevel=self.__logger.level)
        self.preloader = Preloader(self, self.__logger.level)
        self.daloader = DAloader(self, self.__logger.level)

    def crasher(self, display=True, mode=None):
        rmtk = self
        plt = PLTools(self, self.__logger.level)
        if self.config.enforcecrash or self.config.meid is None or not self.config.is_brom:
            self.info("We're not in bootrom, trying to crash da...")
            if mode is None:
                for crashmode in range(0, 3):
                    try:
                        plt.crash(crashmode)
                    except Exception:
                        pass
                    rmtk = Mtk(config=self.config, loglevel=self.__logger.level,
                               serialportname=rmtk.port.serialportname)
                    rmtk.preloader.display = display
                    if rmtk.preloader.init():
                        if rmtk.config.is_brom:
                            break
            else:
                try:
                    plt.crash(mode)
                except Exception as err:
                    self.__logger.debug(str(err))
                    pass
                rmtk = Mtk(config=self.config, loglevel=self.__logger.level, serialportname=rmtk.port.serialportname)
                rmtk.preloader.display = display
                if rmtk.preloader.init():
                    return rmtk
        return rmtk

    def bypass_security(self):
        if self.config.chipconfig.damode == 6:
            return self
        mtk = self.crasher()
        plt = PLTools(mtk, self.__logger.level)
        if self.config.payloadfile is None:
            if self.config.chipconfig.loader is None:
                self.config.payloadfile = os.path.join(self.pathconfig.get_payloads_path(),
                                                       "generic_patcher_payload.bin")
            else:
                self.config.payloadfile = os.path.join(self.pathconfig.get_payloads_path(),
                                                       self.config.chipconfig.loader)
        if plt.runpayload(filename=self.config.payloadfile):
            if mtk.serialportname:
                mtk.port.serial_handshake()
            else:
                mtk.port.run_handshake()
            return mtk
        else:
            self.error("Error on running kamakiri payload")
        return self
