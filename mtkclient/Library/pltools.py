#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import os
import logging
import sys
from binascii import hexlify
from mtkclient.Library.Exploit.amonet import Amonet
from mtkclient.Library.Exploit.hashimoto import Hashimoto
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.gui_utils import LogBase, logsetup, progress
from mtkclient.Library.Hardware.hwcrypto import CryptoSetup, HwCrypto
from mtkclient.Library.Exploit.kamakiri import Kamakiri
from mtkclient.Library.Exploit.kamakiri2 import Kamakiri2
from mtkclient.Library.Port import Port


class PLTools(metaclass=LogBase):
    def __init__(self, mtk, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.mtk = mtk
        self.chipconfig = self.mtk.config.chipconfig
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.read32 = self.mtk.preloader.read32
        self.write32 = self.mtk.preloader.write32
        self.hwcode = mtk.config.hwcode

        # crypto types
        setup = CryptoSetup()
        setup.hwcode = self.mtk.config.hwcode
        setup.dxcc_base = self.mtk.config.chipconfig.dxcc_base
        setup.read32 = self.mtk.preloader.read32
        setup.write32 = self.mtk.preloader.write32
        setup.writemem = self.mtk.preloader.writemem
        setup.da_payload_addr = self.mtk.config.chipconfig.da_payload_addr
        setup.gcpu_base = self.mtk.config.chipconfig.gcpu_base
        setup.blacklist = self.mtk.config.chipconfig.blacklist
        setup.sej_base = self.mtk.config.chipconfig.sej_base
        setup.cqdma_base = self.mtk.config.chipconfig.cqdma_base
        setup.ap_dma_mem = self.mtk.config.chipconfig.ap_dma_mem
        setup.meid_addr = self.mtk.config.chipconfig.meid_addr
        setup.prov_addr = self.mtk.config.chipconfig.prov_addr
        self.hwcrypto = HwCrypto(setup, loglevel, self.mtk.config.gui)

        # exploit types
        if self.config.ptype == "kamakiri":
            self.exploit = Kamakiri(mtk=self.mtk, loglevel=self.__logger.level)
        elif self.config.ptype == "kamakiri2":
            self.exploit = Kamakiri2(mtk=self.mtk, loglevel=self.__logger.level)
        elif self.config.ptype == "amonet":
            self.exploit = Amonet(mtk=self.mtk, loglevel=self.__logger.level)
        elif self.config.ptype == "hashimoto":
            self.exploit = Hashimoto(mtk=self.mtk, loglevel=self.__logger.level)
        elif self.config.ptype == "carbonara":
            assert "Carbonara is best served in your local restaurant :P"

        self.pathconfig = PathConfig()
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

    def runpayload(self, filename, offset=0, ack=0xA1A2A3A4, addr=None, dontack=False):
        try:
            with open(filename, "rb") as rf:
                rf.seek(offset)
                payload = rf.read()
                self.info(f"Loading payload from {os.path.basename(filename)}, {hex(len(payload))} bytes")
        except FileNotFoundError:
            self.info(f"Couldn't open {filename} for reading.")
            return False

        response_ack = self.exploit.runpayload(payload, ack, addr, dontack)
        if response_ack == ack:
            self.info(f"Successfully sent payload: {filename}")
            self.mtk.daloader.patch = True
            return True
        elif response_ack == b"\xc1\xc2\xc3\xc4":
            if "preloader" in rf.name:
                rack = self.mtk.port.usbread(4)
                if rack == b"\xC0\xC0\xC0\xC0":
                    with open("preloader.bin", 'wb') as wf:
                        pg = progress(total=0x40000, pagesize=64, prefix='Dump preloader:')
                        for pos in range(0, 0x40000, 64):
                            wf.write(self.mtk.port.usbread(64))
                            pg.update(64)
                        pg.done()
                        self.info("Preloader dumped as: preloader.bin")
                        return True
            else:
                with open("out.bin", 'wb') as wf:
                    pg = progress(total=0x40000, pagesize=64, prefix='Dump brom:')
                    for pos in range(0, 0x20000, 64):
                        wf.write(self.mtk.port.usbread(64))
                        pg.update(64)
                    pg.done()
                    self.info("Bootrom dumped as: out.bin")
                    return True
            self.error(f"Error on sending payload: {filename}")
            sys.exit(1)
        else:
            self.error(f"Error on sending payload: {filename}")
            if response_ack is not None:
                self.error(f"Error, payload answered instead: {hexlify(response_ack).decode('utf-8')}")
            sys.exit(1)


    def runbrute(self, args):
        if self.exploit.bruteforce(args, 0x9900):
            return True
        else:
            self.error("Error on bruteforcing.")
        return False

    def crash(self, mode=0):
        return self.exploit.crash(mode)

    def crasher(self, mtk, enforcecrash: bool = False):
        if enforcecrash or self.config.meid is None:
            self.info("We're not in bootrom, trying to crash da...")
            for crashmode in range(0, 4):
                try:
                    self.exploit.crash(crashmode)
                except Exception as e:
                    self.__logger.debug(str(e))
                    pass
                portconfig = [[0xE8D, 0x0003, 1]]
                mtk.port = Port(mtk=mtk, portconfig=portconfig, serialportname=mtk.port.serialportname,
                                loglevel=self.__logger.level)
                if mtk.preloader.init(maxtries=20):
                    break
        return mtk

    def run_dump_brom(self, filename, btype, loader="generic_dump_payload.bin"):
        length = 0x20000
        if loader == "generic_sram_payload.bin":
            length = 0x200000
        pfilename = os.path.join(self.pathconfig.get_payloads_path(), loader)
        if type(self.exploit) is Kamakiri or type(self.exploit) is Kamakiri2:
            self.info("Kamakiri / DA Run")
            if self.runpayload(filename=pfilename, ack=0xC1C2C3C4, offset=0):
                if self.exploit.dump_brom(filename):
                    self.info(f"Dumped as:{filename} ")
                    return True
            else:
                self.error(f"Error on sending payload: {filename}")
        else:
            if self.exploit.dump_brom(filename, length=length):
                self.info(f"Dumped as: {filename}")
                return True
            else:
                self.error(f"Error on sending payload: {pfilename}")
        return False

    def run_dump_preloader(self, filename):
        pfilename = os.path.join(self.pathconfig.get_payloads_path(), "generic_preloader_dump_payload.bin")
        if type(self.exploit) is Kamakiri or type(self.exploit) is Kamakiri2:
            self.info("Kamakiri / DA Run")
            if self.runpayload(filename=pfilename, ack=0xC1C2C3C4, offset=0):
                data, filename = self.exploit.dump_preloader()
                return data, filename
            else:
                self.error(f"Error on sending payload: {pfilename}")
                return None, None
        else:
            if self.exploit.dump_brom(filename):
                self.info(f"Preloader dumped as: {filename}")
                return True
            else:
                self.error("Error on dumping preloader")
        return False

    def run_crypto(self, data, iv, btype="sej", encrypt=True, otp=None):
        if data is None:
            data = bytearray()
        for i in range(32):
            data.append(self.config.meid[i % len(self.config.meid)])
        if not btype:
            encrypted = self.hwcrypto.aes_hwcrypt(data=data, iv=iv, encrypt=encrypt, btype=btype, otp=otp)
            return encrypted
        return False
