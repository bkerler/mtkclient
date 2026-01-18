#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import logging
import os
from struct import pack, unpack
from mtkclient.Library.gui_utils import LogBase

regval = {
    "CQDMA_INT_FLAG": 0x0,
    "CQDMA_INT_EN": 0x4,
    "CQDMA_EN": 0x8,
    "CQDMA_RESET": 0xc,
    "CQDMA_FLUSH": 0x14,
    "CQDMA_SRC": 0x1c,
    "CQDMA_DST": 0x20,
    "CQDMA_LEN1": 0x24,
    "CQDMA_LEN2": 0x28,
    "CQDMA_SRC2": 0x60,
    "CQDMA_DST2": 0x64
}


class CqdmaReg:
    def __init__(self, setup):
        self.cqdma_base = setup.cqdma_base
        self.read32 = setup.read32
        self.write32 = setup.write32

    def __setattr__(self, key, value):
        if key in ("cqdma_base", "read32", "write32", "regval"):
            return super(CqdmaReg, self).__setattr__(key, value)
        if key in regval:
            addr = regval[key] + self.cqdma_base
            return self.write32(addr, value)
        else:
            return super(CqdmaReg, self).__setattr__(key, value)

    def __getattribute__(self, item):
        if item in ("cqdma_base", "read32", "write32", "regval"):
            return super(CqdmaReg, self).__getattribute__(item)
        if item in regval:
            addr = regval[item] + self.cqdma_base
            return self.read32(addr)
        else:
            return super(CqdmaReg, self).__getattribute__(item)


class Cqdma(metaclass=LogBase):
    def __init__(self, setup, loglevel=logging.INFO):
        self.chipconfig = None
        self.setup = setup
        self.hwcode = setup.hwcode
        self.__logger = self.__logger
        self.read32 = setup.read32
        self.write32 = setup.write32
        self.info = self.__logger.info
        self.cqdma_base = setup.cqdma_base
        self.ap_dma_mem = setup.ap_dma_mem
        self.reg = CqdmaReg(setup)
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

    def cqread32(self, addr, dwords):
        res = bytearray()
        dst_addr = self.chipconfig.ap_dma_mem  # AP_DMA_IrDA_o_MEM_ADDR (any DMA mem addr reg)
        if self.cqdma_base is not None:
            for i in range(dwords):
                self.reg.CQDMA_SRC = [addr + (i * 4)]
                self.reg.CQDMA_DST = [dst_addr]
                self.reg.CQDMA_LEN1 = [4]
                self.reg.CQDMA_EN = [1]
                while True:
                    if self.reg.CQDMA_EN & 1 == 0:
                        break
                res.extend(pack("<I", self.read32(dst_addr)))
        return res

    def cqwrite32(self, addr, dwords):
        dst_addr = self.setup.ap_dma_mem  # AP_DMA_IrDA_o_MEM_ADDR (any DMA mem addr reg)
        if self.cqdma_base is not None:
            for i in range(len(dwords)):
                self.write32(dst_addr, [dwords[i]])
                self.reg.CQDMA_SRC = [dst_addr]
                self.reg.CQDMA_DST = [addr + (i * 4)]
                self.reg.CQDMA_LEN1 = [4]
                self.reg.CQDMA_EN = [1]
                while True:
                    if self.reg.CQDMA_EN & 1 == 0:
                        break
                self.write32(dst_addr, [0xcafebabe])

    def mem_read(self, addr: int, length: int, ucqdma=False):
        dwords = length // 4
        if length % 4 != 0:
            dwords += 1
        res = b""
        if ucqdma:
            res = self.cqread32(addr, dwords)
        else:
            data = self.read32(addr, dwords)
            for value in data:
                res += pack("<I", value)
        res = res[:length]
        return res

    def mem_write(self, addr: int, data: bytes, ucqdma=False):
        cnt = len(data) % 4
        if cnt:
            data += b'\x00' * (4 - cnt)
        dwords = []
        for i in range(0, len(data), 4):
            dwords.append(unpack("<I", data[i * 4:(i * 4) + 4])[0])
        if ucqdma:
            self.cqwrite32(addr, dwords)
        else:
            self.write32(addr, dwords)

    def disable_range_blacklist(self):
        self.info("Disabling bootrom range checks..")
        for field in self.setup.blacklist:
            addr = field[0]
            values = field[1]
            if isinstance(values, int):
                values = [values]
            self.cqwrite32(addr, values)
